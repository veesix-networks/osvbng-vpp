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
#include <vnet/ethernet/ethernet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vlib/log.h>

#include <osvbng_punt/osvbng_punt.h>

osvbng_punt_main_t osvbng_punt_main;

void
osvbng_punt_policer_init (void)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  /* Default rates: packets per second, burst size */
  f64 default_rates[] = { 1000, 1000, 500, 1000, 1000, 500, 500 };
  u32 default_bursts[] = { 100, 100, 50, 100, 100, 50, 50 };

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      pm->policers[i].rate = default_rates[i];
      pm->policers[i].burst = default_bursts[i];
      pm->policers[i].tokens = (f64) default_bursts[i];
      pm->policers[i].last_update = vlib_time_now (pm->vlib_main);
      pm->policers[i].policed = 0;
    }
}

int
osvbng_punt_policer_configure (osvbng_punt_protocol_t protocol, f64 rate,
			       u32 burst)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (protocol >= OSVBNG_PUNT_N_PROTO)
    return -1;

  pm->policers[protocol].rate = rate;
  pm->policers[protocol].burst = burst;
  pm->policers[protocol].tokens = (f64) burst;
  pm->policers[protocol].last_update = vlib_time_now (pm->vlib_main);

  return 0;
}

int
osvbng_punt_policer_allow (osvbng_punt_protocol_t protocol)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  osvbng_punt_policer_t *p = &pm->policers[protocol];

  if (p->rate == 0)
    return 1;

  f64 now = vlib_time_now (pm->vlib_main);
  f64 elapsed = now - p->last_update;
  p->last_update = now;

  p->tokens += elapsed * p->rate;
  if (p->tokens > (f64) p->burst)
    p->tokens = (f64) p->burst;

  if (p->tokens >= 1.0)
    {
      p->tokens -= 1.0;
      return 1;
    }

  p->policed++;
  return 0;
}

int
osvbng_punt_enable_disable (u32 sw_if_index,
			    osvbng_punt_protocol_t protocol,
			    int enable_disable)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vnet_main_t *vnm = pm->vnet_main;

  if (protocol >= OSVBNG_PUNT_N_PROTO)
    return VNET_API_ERROR_INVALID_VALUE;

  if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (!pm->shm_initialized)
    {
      vlib_log_err (pm->log_class,
		    "shared memory not initialized, cannot enable punt");
      return VNET_API_ERROR_INIT_FAILED;
    }

  if (enable_disable)
    {
      hash_set (pm->enabled_interfaces[protocol], sw_if_index, 1);

      vlib_log_info (pm->log_class,
		     "punt enabled: protocol %d on sw_if_index %d",
		     protocol, sw_if_index);
    }
  else
    {
      hash_unset (pm->enabled_interfaces[protocol], sw_if_index);

      vlib_log_info (pm->log_class,
		     "punt disabled: protocol %d on sw_if_index %d",
		     protocol, sw_if_index);
    }

  return 0;
}

static void
osvbng_punt_register_ethertypes (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  vlib_log_info (pm->log_class, "registering ethertypes...");

  ethernet_register_input_type (vm, ETHERNET_TYPE_ARP,
				osvbng_punt_arp_node.index);
  pm->original_arp_node = 0;
  vlib_log_debug (pm->log_class, "registered ARP (0x0806) -> node %d",
		  osvbng_punt_arp_node.index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
				osvbng_punt_pppoe_disc_node.index);
  pm->original_pppoe_disc_node = 0;
  vlib_log_debug (pm->log_class,
		  "registered PPPoE Discovery (0x8863) -> node %d",
		  osvbng_punt_pppoe_disc_node.index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
				osvbng_punt_pppoe_sess_node.index);
  pm->original_pppoe_sess_node = 0;
  vlib_log_debug (pm->log_class,
		  "registered PPPoE Session (0x8864) -> node %d",
		  osvbng_punt_pppoe_sess_node.index);

  vlib_log_notice (pm->log_class,
		   "ethertypes registered: ARP, PPPoE-Discovery, PPPoE-Session");
}

static clib_error_t *
osvbng_punt_init (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  pm->log_class = vlib_log_register_class ("osvbng_punt", 0);

  vlib_log_info (pm->log_class, "initializing...");

  pm->vlib_main = vm;
  pm->vnet_main = vnet_get_main ();

  /* Initialize shared memory fields */
  pm->shm = NULL;
  pm->shm_fd = -1;
  pm->shm_initialized = 0;
  pm->client_connected = 0;
  pm->punt_eventfd = -1;
  pm->egress_eventfd = -1;
  pm->eventfd_listen_fd = -1;
  pm->eventfd_listen_file_index = ~0;
  pm->egress_file_index = ~0;

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      pm->enabled_interfaces[i] = hash_create (0, sizeof (uword));
      pm->packets_punted[i] = 0;
      pm->packets_dropped[i] = 0;
    }

  pm->l2tpv2_input_next_arc = ~0;

  osvbng_punt_policer_init ();

  osvbng_punt_register_ethertypes (vm);

  /* Initialize shared memory dataplane */
  if (osvbng_punt_shm_init (vm) < 0)
    {
      vlib_log_err (pm->log_class, "shared memory init failed");
      return clib_error_return (0, "shared memory init failed");
    }

  /* Initialize eventfd socket for osvbng connection */
  if (osvbng_punt_eventfd_socket_init (vm) < 0)
    {
      vlib_log_err (pm->log_class, "eventfd socket init failed");
      return clib_error_return (0, "eventfd socket init failed");
    }

  /* Initialize egress node */
  if (osvbng_punt_egress_init (vm) < 0)
    {
      vlib_log_err (pm->log_class, "egress init failed");
      return clib_error_return (0, "egress init failed");
    }

  vlib_log_notice (pm->log_class, "initialized successfully");

  return 0;
}

/* Run after native pppoe plugin to override its ethertype registration */
VLIB_INIT_FUNCTION (osvbng_punt_init) = {
  .runs_after = VLIB_INITS ("pppoe_init"),
};

static clib_error_t *
osvbng_punt_enable_disable_command_fn (vlib_main_t *vm,
				       unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 sw_if_index = ~0;
  int enable = 1;
  int rv;
  osvbng_punt_protocol_t protocol = OSVBNG_PUNT_N_PROTO;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "enable"))
	enable = 1;
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
      else if (sw_if_index == ~0 &&
	       unformat (input, "%U", unformat_vnet_sw_interface,
			 pm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface");

  if (protocol == OSVBNG_PUNT_N_PROTO)
    return clib_error_return (0, "Please specify a protocol");

  rv = osvbng_punt_enable_disable (sw_if_index, protocol, enable);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return (0, "Invalid interface");
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "Invalid protocol");
    case VNET_API_ERROR_INIT_FAILED:
      return clib_error_return (0, "Shared memory not initialized");
    default:
      return clib_error_return (0, "osvbng_punt_enable_disable returned %d",
				rv);
    }
  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_enable_disable_command, static) = {
  .path = "osvbng punt",
  .short_help =
    "osvbng punt [enable|disable] <interface> protocol <arp|pppoe-disc|pppoe-sess|dhcpv4|dhcpv6|ipv6-nd|l2tp>",
  .function = osvbng_punt_enable_disable_command_fn,
};

static clib_error_t *
osvbng_punt_show_stats_command_fn (vlib_main_t *vm,
				   unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  char *proto_names[] = {
    "DHCPv4", "DHCPv6", "ARP", "PPPoE-Disc", "PPPoE-Sess", "IPv6-ND", "L2TP"
  };

  vlib_cli_output (vm, "OSVBNG Punt Statistics:\n");
  vlib_cli_output (vm, "Shared Memory: %s\n",
		   pm->shm_initialized ? "initialized" : "NOT INITIALIZED");
  vlib_cli_output (vm, "Client Connected: %s\n",
		   pm->client_connected ? "yes" : "no");

  vlib_cli_output (vm, "%-15s %15s %15s %15s %10s %10s", "Protocol", "Punted",
		   "Dropped", "Policed", "Rate", "Burst");
  vlib_cli_output (vm, "%-15s %15s %15s %15s %10s %10s", "--------", "------",
		   "-------", "-------", "----", "-----");

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      vlib_cli_output (vm, "%-15s %15llu %15llu %15llu %10.0f %10u",
		       proto_names[i], pm->packets_punted[i],
		       pm->packets_dropped[i], pm->policers[i].policed,
		       pm->policers[i].rate, pm->policers[i].burst);
    }

  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_show_stats_command, static) = {
  .path = "show osvbng punt stats",
  .short_help = "show osvbng punt stats",
  .function = osvbng_punt_show_stats_command_fn,
};

static clib_error_t *
osvbng_punt_policer_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  osvbng_punt_protocol_t protocol = OSVBNG_PUNT_N_PROTO;
  f64 rate = 0;
  u32 burst = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "protocol dhcpv4"))
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
      else if (unformat (input, "rate %f", &rate))
	;
      else if (unformat (input, "burst %u", &burst))
	;
      else
	break;
    }

  if (protocol == OSVBNG_PUNT_N_PROTO)
    return clib_error_return (0, "Please specify a protocol");

  if (rate == 0 && burst == 0)
    return clib_error_return (0, "Please specify rate and/or burst");

  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (rate > 0)
    pm->policers[protocol].rate = rate;
  if (burst > 0)
    pm->policers[protocol].burst = burst;

  pm->policers[protocol].tokens = (f64) pm->policers[protocol].burst;

  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_policer_command, static) = {
  .path = "osvbng punt policer",
  .short_help =
    "osvbng punt policer protocol <proto> rate <pps> burst <packets>",
  .function = osvbng_punt_policer_command_fn,
};

static clib_error_t *
osvbng_punt_show_interfaces_command_fn (vlib_main_t *vm,
					unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  char *proto_names[] = {
    "DHCPv4", "DHCPv6", "ARP", "PPPoE-Disc", "PPPoE-Sess", "IPv6-ND", "L2TP"
  };

  vlib_cli_output (vm, "OSVBNG Punt Enabled Interfaces:\n");

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      uword *p;
      u32 sw_if_index;
      int count = 0;

      vlib_cli_output (vm, "\n%s:", proto_names[i]);

      hash_foreach (sw_if_index, p, pm->enabled_interfaces[i],
      ({
        vnet_sw_interface_t *si = vnet_get_sw_interface (pm->vnet_main, sw_if_index);
        vlib_cli_output (vm, "  sw_if_index %d (%U)",
                         sw_if_index,
                         format_vnet_sw_interface_name, pm->vnet_main, si);
        count++;
      }));

      if (count == 0)
	vlib_cli_output (vm, "  (none)");
    }

  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_show_interfaces_command, static) = {
  .path = "show osvbng punt interfaces",
  .short_help = "show osvbng punt interfaces",
  .function = osvbng_punt_show_interfaces_command_fn,
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
