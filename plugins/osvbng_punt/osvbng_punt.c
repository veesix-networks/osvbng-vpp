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
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_source.h>
#include <vnet/fib/ip4_fib.h>

#include <osvbng_punt/osvbng_punt.h>

osvbng_punt_main_t osvbng_punt_main;

/* Our own FIB source for the DHCP broadcast receive route, allocated
 * at init (26.06 has no static plugin source), at DHCP priority so it
 * composes with VPP's own dhcp machinery rather than fighting it. */
static fib_source_t osvbng_punt_fib_source;

void
osvbng_punt_dhcp_bcast_route (u32 sw_if_index, int enable)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
  const fib_prefix_t all_ones = {
    .fp_len = 32,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4.as_u32 = 0xffffffff,
  };
  uword *count = hash_get (pm->dhcp_bcast_refs, fib_index);

  if (enable)
    {
      if (!count)
	{
	  fib_table_entry_special_add (fib_index, &all_ones,
				       osvbng_punt_fib_source,
				       FIB_ENTRY_FLAG_LOCAL);
	  hash_set (pm->dhcp_bcast_refs, fib_index, 1);
	}
      else
	hash_set (pm->dhcp_bcast_refs, fib_index, count[0] + 1);
    }
  else if (count)
    {
      if (count[0] <= 1)
	{
	  fib_table_entry_special_remove (fib_index, &all_ones,
					  osvbng_punt_fib_source);
	  hash_unset (pm->dhcp_bcast_refs, fib_index);
	}
      else
	hash_set (pm->dhcp_bcast_refs, fib_index, count[0] - 1);
    }
}

void
osvbng_punt_policer_init (void)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  /* Default aggregate rates: packets per second, burst size. These
   * size the management link, not the subscriber load. */
  f64 default_rates[] = { 1000, 1000, 500, 1000, 1000, 500, 500, 1000 };
  u32 default_bursts[] = { 100, 100, 50, 100, 100, 50, 50, 100 };

  for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
    {
      pm->policer_rate[i] = default_rates[i];
      pm->policer_burst[i] = default_bursts[i];
    }
}

/* Push the configured rates into the per-thread buckets. The rate is
 * divided so the aggregate sustained rate holds however traffic
 * spreads across workers. The burst is NOT divided: subscriber flows
 * hash whole onto one worker, so a synchronized handshake burst lands
 * on one or two threads, and a burst/n share polices legitimate
 * bring-up at trivial scale (six PPPoE sessions on a 21-worker box
 * lost 6 of 10 discovery packets to a 100/21 share). The worst-case
 * transient this admits is burst on every worker at once, bounded and
 * small next to the sustained rate the divide protects. Runs after
 * shm init (per_thread must exist) and under a worker barrier when
 * called on a config change. */
void
osvbng_punt_policer_apply (void)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  u32 n = vec_len (pm->per_thread);

  for (u32 t = 0; t < n; t++)
    {
      osvbng_punt_per_thread_t *pt = vec_elt_at_index (pm->per_thread, t);
      for (int i = 0; i < OSVBNG_PUNT_N_PROTO; i++)
	{
	  pt->rate[i] = pm->policer_rate[i] / (f64) n;
	  pt->burst[i] = (f64) pm->policer_burst[i];
	  if (pt->burst[i] < 1.0)
	    pt->burst[i] = 1.0;
	  pt->tokens[i] = pt->burst[i];
	  pt->last_update[i] = vlib_time_now (pm->vlib_main);
	}
    }
}

int
osvbng_punt_policer_configure (osvbng_punt_protocol_t protocol, f64 rate,
			       u32 burst)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (protocol >= OSVBNG_PUNT_N_PROTO)
    return -1;

  pm->policer_rate[protocol] = rate;
  if (burst > 0)
    pm->policer_burst[protocol] = burst;

  /* Rewriting another thread's bucket needs the workers stopped: a
   * one-shot config change, never a per-packet path. */
  vlib_worker_thread_barrier_sync (pm->vlib_main);
  osvbng_punt_policer_apply ();
  vlib_worker_thread_barrier_release (pm->vlib_main);

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

  /* The datapath reads this hash per packet and hash_set can realloc
   * it. The binapi path already holds the API barrier; the CLI path
   * does not, so take it here (nested from binapi is a refcount). */
  vlib_worker_thread_barrier_sync (pm->vlib_main);
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
  vlib_worker_thread_barrier_release (pm->vlib_main);

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
    pm->enabled_interfaces[i] = hash_create (0, sizeof (uword));

  pm->l2tpv2_input_next_arc = ~0;
  pm->dhcp_bcast_refs = hash_create (0, sizeof (uword));
  osvbng_punt_fib_source =
    fib_source_allocate ("osvbng-punt", FIB_SOURCE_PRIORITY_HI,
			 FIB_SOURCE_BH_SIMPLE);

  osvbng_punt_policer_init ();

  osvbng_punt_register_ethertypes (vm);

  /* The shared memory region has one punt ring per thread, and the
   * worker count is only known once the threads exist, so the region
   * is built at main-loop entry, not here (VLIB_INIT_FUNCTION runs
   * before workers exist). See osvbng_punt_main_loop_enter. */
  vlib_log_notice (pm->log_class, "initialized successfully");

  return 0;
}

/* Run after native pppoe plugin to override its ethertype registration */
VLIB_INIT_FUNCTION (osvbng_punt_init) = {
  .runs_after = VLIB_INITS ("pppoe_init"),
};

static clib_error_t *
osvbng_punt_main_loop_enter (vlib_main_t *vm)
{
  if (osvbng_punt_shm_init (vm) < 0)
    return clib_error_return (0, "shared memory init failed");
  if (osvbng_punt_eventfd_socket_init (vm) < 0)
    return clib_error_return (0, "eventfd socket init failed");
  if (osvbng_punt_egress_init (vm) < 0)
    return clib_error_return (0, "egress init failed");

  /* per_thread exists now; push the configured rates into the buckets. */
  osvbng_punt_policer_apply ();
  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (osvbng_punt_main_loop_enter);

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
      else if (unformat (input, "protocol l2gw-trigger"))
	protocol = OSVBNG_PUNT_PROTO_L2GW_TRIGGER;
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
    "osvbng punt [enable|disable] <interface> protocol <arp|pppoe-disc|pppoe-sess|dhcpv4|dhcpv6|ipv6-nd|l2tp|l2gw-trigger>",
  .function = osvbng_punt_enable_disable_command_fn,
};

static clib_error_t *
osvbng_punt_show_stats_command_fn (vlib_main_t *vm,
				   unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  char *proto_names[] = {
    "DHCPv4", "DHCPv6", "ARP", "PPPoE-Disc", "PPPoE-Sess", "IPv6-ND", "L2TP",
    "L2GW-Trigger"
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
      u64 punted = 0, dropped = 0, policed = 0;
      osvbng_punt_per_thread_t *pt;

      /* Sum the per-thread counters here, off the punt path, which is
       * what pays for keeping them per-thread on the path. */
      vec_foreach (pt, pm->per_thread)
	{
	  punted += pt->punted[i];
	  dropped += pt->dropped[i];
	  policed += pt->policed[i];
	}

      vlib_cli_output (vm, "%-15s %15llu %15llu %15llu %10.0f %10u",
		       proto_names[i], punted, dropped, policed,
		       pm->policer_rate[i], pm->policer_burst[i]);
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
      else if (unformat (input, "protocol l2gw-trigger"))
	protocol = OSVBNG_PUNT_PROTO_L2GW_TRIGGER;
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

  /* Config plus barrier plus per-thread re-apply, all in one place. */
  if (rate == 0)
    rate = pm->policer_rate[protocol];
  osvbng_punt_policer_configure (protocol, rate, burst);

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
    "DHCPv4", "DHCPv6", "ARP", "PPPoE-Disc", "PPPoE-Sess", "IPv6-ND", "L2TP",
    "L2GW-Trigger"
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
