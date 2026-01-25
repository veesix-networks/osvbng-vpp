/*
 * Copyright (c) 2025 Veesix Networks
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vlib/unix/unix.h>

#include <osvbng_punt/osvbng_punt.h>

osvbng_punt_main_t osvbng_punt_main;

static int
osvbng_punt_socket_init_internal (osvbng_punt_main_t * pm, u8 * socket_path)
{
  int fd;

  if (pm->socket_fd != -1)
    return 0;			/* Already initialized */

  /* Create unbound socket for sendto() */
  fd = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;

  /* Prepare destination address */
  clib_memset (&pm->dest_addr, 0, sizeof (pm->dest_addr));
  pm->dest_addr.sun_family = AF_UNIX;
  strncpy (pm->dest_addr.sun_path, (char *) socket_path,
	   sizeof (pm->dest_addr.sun_path) - 1);

  pm->socket_fd = fd;
  pm->socket_path = format (0, "%s%c", socket_path, 0);

  return 0;
}

int
osvbng_punt_socket_init (u8 * socket_path)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  return osvbng_punt_socket_init_internal (pm, socket_path);
}

int
osvbng_punt_send_packet (vlib_buffer_t * b, u32 sw_if_index,
			 osvbng_punt_protocol_t protocol)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  osvbng_punt_packet_header_t hdr;
  struct iovec iov[2];
  struct msghdr msg;
  ssize_t n_sent;

  /* Check if socket is initialized */
  if (pm->socket_fd == -1)
    {
      pm->packets_dropped[protocol]++;
      return -1;
    }

  /* Build packet header with metadata only (MAC/VLAN in packet itself) */
  hdr.sw_if_index = clib_host_to_net_u32 (sw_if_index);
  hdr.protocol = protocol;
  hdr.direction = 0;		/* RX */
  hdr.data_len = clib_host_to_net_u16 (b->current_length);
  hdr.timestamp_ns = clib_host_to_net_u64 (vlib_time_now (pm->vlib_main) * 1e9);

  /* Send header + packet data using sendmsg() */
  iov[0].iov_base = &hdr;
  iov[0].iov_len = sizeof (hdr);
  iov[1].iov_base = vlib_buffer_get_current (b);
  iov[1].iov_len = b->current_length;

  clib_memset (&msg, 0, sizeof (msg));
  msg.msg_name = &pm->dest_addr;
  msg.msg_namelen = sizeof (pm->dest_addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;

  n_sent = sendmsg (pm->socket_fd, &msg, 0);
  if (n_sent < 0)
    {
      /* Socket may not exist yet, silently drop */
      pm->packets_dropped[protocol]++;
      return -1;
    }

  pm->packets_punted[protocol]++;
  return 0;
}

int
osvbng_punt_enable_disable (u32 sw_if_index,
			    osvbng_punt_protocol_t protocol,
			    u8 * socket_path, int enable_disable)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vnet_main_t *vnm = pm->vnet_main;
  osvbng_punt_proto_config_t *config;

  if (protocol >= OSVBNG_PUNT_N_PROTO)
    return VNET_API_ERROR_INVALID_VALUE;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  config = &pm->proto_configs[protocol];

  if (enable_disable)
    {
      /* Store socket path and initialize if first enable */
      if (!pm->socket_path && socket_path)
	{
	  osvbng_punt_socket_init_internal (pm, socket_path);
	}

      /* Enable punt on this interface for this protocol */
      hash_set (pm->enabled_interfaces[protocol], sw_if_index, 1);

      /* Call protocol-specific enable function */
      switch (protocol)
	{
	case OSVBNG_PUNT_PROTO_DHCPV4:
	  osvbng_punt_enable_dhcpv4 (sw_if_index, socket_path);
	  break;
	case OSVBNG_PUNT_PROTO_L2TP:
	  osvbng_punt_enable_l2tp (sw_if_index, socket_path);
	  break;
	case OSVBNG_PUNT_PROTO_IPV6_ND:
	  osvbng_punt_enable_ipv6_nd (sw_if_index, socket_path);
	  break;
	case OSVBNG_PUNT_PROTO_ARP:
	  /* Feature arc based */
	  if (config->use_feature_arc)
	    {
	      vnet_feature_enable_disable (config->arc_name,
					   config->node_name,
					   sw_if_index, 1, 0, 0);
	    }
	  break;
	default:
	  /* Other protocols use feature arcs */
	  if (config->use_feature_arc)
	    {
	      vnet_feature_enable_disable (config->arc_name,
					   config->node_name,
					   sw_if_index, 1, 0, 0);
	    }
	  break;
	}
    }
  else
    {
      /* Disable punt on this interface */
      hash_unset (pm->enabled_interfaces[protocol], sw_if_index);

      /* Call protocol-specific disable function */
      switch (protocol)
	{
	case OSVBNG_PUNT_PROTO_DHCPV4:
	  osvbng_punt_disable_dhcpv4 (sw_if_index);
	  break;
	case OSVBNG_PUNT_PROTO_L2TP:
	  osvbng_punt_disable_l2tp (sw_if_index);
	  break;
	case OSVBNG_PUNT_PROTO_IPV6_ND:
	  osvbng_punt_disable_ipv6_nd (sw_if_index);
	  break;
	case OSVBNG_PUNT_PROTO_ARP:
	  /* Feature arc based */
	  if (config->use_feature_arc)
	    {
	      vnet_feature_enable_disable (config->arc_name,
					   config->node_name,
					   sw_if_index, 0, 0, 0);
	    }
	  break;
	default:
	  /* Other protocols use feature arcs */
	  if (config->use_feature_arc)
	    {
	      vnet_feature_enable_disable (config->arc_name,
					   config->node_name,
					   sw_if_index, 0, 0, 0);
	    }
	  break;
	}

      /* Close socket if no more punts enabled */
      int still_enabled = 0;
      for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
	{
	  if (hash_elts (pm->enabled_interfaces[i]) > 0)
	    {
	      still_enabled = 1;
	      break;
	    }
	}

      if (!still_enabled && pm->socket_fd != -1)
	{
	  close (pm->socket_fd);
	  pm->socket_fd = -1;
	}
    }

  return 0;
}

static void
osvbng_punt_init_proto_configs (osvbng_punt_main_t * pm)
{
  /* DHCPv4 */
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV4].ethertype = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV4].ip_protocol = IP_PROTOCOL_UDP;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV4].l4_port = 67;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV4].use_feature_arc = 1;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV4].arc_name = "ip4-unicast";
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV4].node_name = "osvbng-punt-dhcp";

  /* DHCPv6 */
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV6].ethertype = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV6].ip_protocol = IP_PROTOCOL_UDP;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV6].l4_port = 547;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV6].use_feature_arc = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV6].arc_name = NULL;
  pm->proto_configs[OSVBNG_PUNT_PROTO_DHCPV6].node_name = "osvbng-punt-dhcp6";

  /* ARP */
  pm->proto_configs[OSVBNG_PUNT_PROTO_ARP].ethertype = 0x0806;
  pm->proto_configs[OSVBNG_PUNT_PROTO_ARP].ip_protocol = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_ARP].l4_port = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_ARP].use_feature_arc = 1;
  pm->proto_configs[OSVBNG_PUNT_PROTO_ARP].arc_name = "arp";
  pm->proto_configs[OSVBNG_PUNT_PROTO_ARP].node_name = "osvbng-punt-arp";

  /* PPPoE Discovery */
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY].ethertype = 0x8863;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY].ip_protocol = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY].l4_port = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY].use_feature_arc = 1;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY].arc_name =
    "ethernet-input";
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY].node_name =
    "osvbng-punt-pppoe-disc";

  /* PPPoE Session */
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_SESSION].ethertype = 0x8864;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_SESSION].ip_protocol = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_SESSION].l4_port = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_SESSION].use_feature_arc = 1;
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_SESSION].arc_name =
    "ethernet-input";
  pm->proto_configs[OSVBNG_PUNT_PROTO_PPPOE_SESSION].node_name =
    "osvbng-punt-pppoe-sess";

  /* IPv6 ND */
  pm->proto_configs[OSVBNG_PUNT_PROTO_IPV6_ND].ethertype = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_IPV6_ND].ip_protocol =
    IP_PROTOCOL_ICMP6;
  pm->proto_configs[OSVBNG_PUNT_PROTO_IPV6_ND].l4_port = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_IPV6_ND].use_feature_arc = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_IPV6_ND].arc_name = NULL;
  pm->proto_configs[OSVBNG_PUNT_PROTO_IPV6_ND].node_name =
    "osvbng-punt-ipv6-nd";

  /* L2TP */
  pm->proto_configs[OSVBNG_PUNT_PROTO_L2TP].ethertype = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_L2TP].ip_protocol = IP_PROTOCOL_UDP;
  pm->proto_configs[OSVBNG_PUNT_PROTO_L2TP].l4_port = 1701;
  pm->proto_configs[OSVBNG_PUNT_PROTO_L2TP].use_feature_arc = 0;
  pm->proto_configs[OSVBNG_PUNT_PROTO_L2TP].arc_name = NULL;
  pm->proto_configs[OSVBNG_PUNT_PROTO_L2TP].node_name = "osvbng-punt-l2tp";
}

static clib_error_t *
osvbng_punt_init (vlib_main_t * vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();
  pm->socket_path = NULL;
  pm->socket_fd = -1;

  /* Initialize per-protocol enable bitmaps */
  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      pm->enabled_interfaces[i] = hash_create (0, sizeof (uword));
      pm->packets_punted[i] = 0;
      pm->packets_dropped[i] = 0;
    }

  /* Initialize protocol configurations */
  osvbng_punt_init_proto_configs (pm);

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_punt_init);

/* CLI command to enable/disable punt */
static clib_error_t *
osvbng_punt_enable_disable_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 sw_if_index = ~0;
  u8 *socket_path = NULL;
  int enable = 1;
  int rv;
  osvbng_punt_protocol_t protocol = OSVBNG_PUNT_N_PROTO;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "socket %s", &socket_path))
	;
      else if (unformat (input, "protocol dhcpv4"))
	protocol = OSVBNG_PUNT_PROTO_DHCPV4;
      else if (unformat (input, "protocol dhcpv6"))
	protocol = OSVBNG_PUNT_PROTO_DHCPV6;
      else if (unformat (input, "protocol arp"))
	protocol = OSVBNG_PUNT_PROTO_ARP;
      else if (unformat (input, "protocol pppoe-disc"))
	protocol = OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY;
      else if (unformat (input, "protocol pppoe-sess"))
	protocol = OSVBNG_PUNT_PROTO_PPPOE_SESSION;
      else if (unformat (input, "protocol ipv6-nd"))
	protocol = OSVBNG_PUNT_PROTO_IPV6_ND;
      else if (unformat (input, "protocol l2tp"))
	protocol = OSVBNG_PUNT_PROTO_L2TP;
      else
	if (sw_if_index == ~0
	    && unformat (input, "%U", unformat_vnet_sw_interface,
			 pm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      vec_free (socket_path);
      return clib_error_return (0, "Please specify an interface");
    }

  if (protocol == OSVBNG_PUNT_N_PROTO)
    {
      vec_free (socket_path);
      return clib_error_return (0, "Please specify a protocol");
    }

  if (enable && !socket_path && !pm->socket_path)
    {
      return clib_error_return (0,
				"Please specify socket path when enabling");
    }

  rv = osvbng_punt_enable_disable (sw_if_index, protocol, socket_path,
				   enable);

  vec_free (socket_path);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface");

    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "Invalid protocol");

    default:
      return clib_error_return (0,
				"osvbng_punt_enable_disable returned %d", rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_enable_disable_command, static) = {
  .path = "osvbng punt",
  .short_help =
    "osvbng punt [enable|disable] <interface> protocol <dhcpv4|dhcpv6|arp|pppoe-disc|pppoe-sess|ipv6-nd|l2tp> [socket <path>]",
  .function = osvbng_punt_enable_disable_command_fn,
};

/* CLI command to show punt statistics */
static clib_error_t *
osvbng_punt_show_stats_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  char *proto_names[] = {
    "DHCPv4", "DHCPv6", "ARP", "PPPoE-Disc", "PPPoE-Sess", "IPv6-ND", "L2TP"
  };

  vlib_cli_output (vm, "OSVBNG Punt Statistics:\n");
  vlib_cli_output (vm, "Socket: %s\n",
		   pm->socket_path ? (char *) pm->socket_path : "(not set)");

  vlib_cli_output (vm, "%-15s %15s %15s", "Protocol", "Punted", "Dropped");
  vlib_cli_output (vm, "%-15s %15s %15s", "--------", "------", "-------");

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      vlib_cli_output (vm, "%-15s %15llu %15llu",
		       proto_names[i],
		       pm->packets_punted[i], pm->packets_dropped[i]);
    }

  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_show_stats_command, static) = {
  .path = "show osvbng punt stats",
  .short_help = "show osvbng punt stats",
  .function = osvbng_punt_show_stats_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OSVBNG Unified Control Plane Punt Plugin",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
