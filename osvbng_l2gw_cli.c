/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng L2GW Plugin - CLI
 */

#include <vnet/vnet.h>

#include <osvbng_l2gw/osvbng_l2gw.h>

static clib_error_t *
l2gw_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  l2gw_main_t *lm = &l2gw_main;
  u32 sw_if_index = ~0;
  u8 enable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 lm->vnet_main, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface required");

  rv = vnet_l2gw_enable_disable (sw_if_index, enable);
  if (rv)
    return clib_error_return (0, "l2gw enable/disable failed (rv %d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (l2gw_enable_disable_command, static) = {
  .path = "osvbng l2gw",
  .short_help = "osvbng l2gw <interface> [disable]",
  .function = l2gw_enable_disable_command_fn,
};

static clib_error_t *
l2gw_trigger_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  l2gw_main_t *lm = &l2gw_main;
  u32 sw_if_index = ~0;
  u32 lo = 0, hi = 0;
  u8 is_add = 1;
  u8 any_protocol = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "any"))
	any_protocol = 1;
      else if (unformat (input, "svlan %d-%d", &lo, &hi))
	;
      else if (unformat (input, "svlan %d", &lo))
	hi = lo;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 lm->vnet_main, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface required");
  if (lo == 0)
    return clib_error_return (0, "svlan required");

  rv = vnet_l2gw_trigger_svlan_range (sw_if_index, lo, hi, any_protocol,
				      is_add);
  if (rv)
    return clib_error_return (0, "l2gw trigger failed (rv %d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (l2gw_trigger_command, static) = {
  .path = "osvbng l2gw trigger",
  .short_help =
    "osvbng l2gw trigger <interface> svlan <lo>[-<hi>] [any] [del]",
  .function = l2gw_trigger_command_fn,
};

static clib_error_t *
l2gw_circuit_add_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  l2gw_main_t *lm = &l2gw_main;
  vnet_l2gw_add_del_circuit_args_t a = { .is_add = 1, .enabled = 1 };
  u32 circuit_id = ~0;
  u32 val;
  int rv;

  a.access_sw_if_index = ~0;
  a.handoff_sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	a.is_add = 0;
      else if (unformat (input, "access %U svlan %d cvlan any",
			 unformat_vnet_sw_interface, lm->vnet_main,
			 &a.access_sw_if_index, &val))
	{
	  a.access_svlan = val;
	  a.access_cvlan = L2GW_CVLAN_ANY;
	}
      else if (unformat (input, "access %U svlan %d cvlan %d",
			 unformat_vnet_sw_interface, lm->vnet_main,
			 &a.access_sw_if_index, &val, &circuit_id))
	{
	  a.access_svlan = val;
	  a.access_cvlan = circuit_id;
	  circuit_id = ~0;
	}
      else if (unformat (input, "access %U svlan %d",
			 unformat_vnet_sw_interface, lm->vnet_main,
			 &a.access_sw_if_index, &val))
	a.access_svlan = val;
      else if (unformat (input, "handoff %U svlan %d cvlan any",
			 unformat_vnet_sw_interface, lm->vnet_main,
			 &a.handoff_sw_if_index, &val))
	{
	  a.handoff_svlan = val;
	  a.handoff_cvlan = L2GW_CVLAN_ANY;
	}
      else if (unformat (input, "handoff %U svlan %d cvlan %d",
			 unformat_vnet_sw_interface, lm->vnet_main,
			 &a.handoff_sw_if_index, &val, &circuit_id))
	{
	  a.handoff_svlan = val;
	  a.handoff_cvlan = circuit_id;
	  circuit_id = ~0;
	}
      else if (unformat (input, "handoff %U svlan %d",
			 unformat_vnet_sw_interface, lm->vnet_main,
			 &a.handoff_sw_if_index, &val))
	a.handoff_svlan = val;
      else if (unformat (input, "access-tpid dot1q"))
	a.access_tpid = ETHERNET_TYPE_VLAN;
      else if (unformat (input, "access-tpid dot1ad"))
	a.access_tpid = ETHERNET_TYPE_DOT1AD;
      else if (unformat (input, "handoff-tpid dot1q"))
	a.handoff_tpid = ETHERNET_TYPE_VLAN;
      else if (unformat (input, "handoff-tpid dot1ad"))
	a.handoff_tpid = ETHERNET_TYPE_DOT1AD;
      else if (unformat (input, "transparent"))
	a.transparent = 1;
      else if (unformat (input, "disabled"))
	a.enabled = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (a.access_sw_if_index == ~0 || a.handoff_sw_if_index == ~0)
    return clib_error_return (0, "access and handoff interfaces required");

  rv = vnet_l2gw_add_del_circuit (&a, &circuit_id);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "circuit %u", circuit_id);
      break;
    case VNET_API_ERROR_ENTRY_NEEDS_REFRESH:
      return clib_error_return (
	0, "circuit %u exists with different parameters", circuit_id);
    default:
      return clib_error_return (0, "l2gw circuit add/del failed (rv %d)", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (l2gw_circuit_add_del_command, static) = {
  .path = "osvbng l2gw circuit",
  .short_help =
    "osvbng l2gw circuit [del] access <interface> svlan <id> [cvlan <id>|cvlan any] "
    "handoff <interface> svlan <id> [cvlan <id>|cvlan any] "
    "[access-tpid dot1q|dot1ad] [handoff-tpid dot1q|dot1ad] "
    "[transparent] [disabled]",
  .function = l2gw_circuit_add_del_command_fn,
};

static clib_error_t *
l2gw_circuit_state_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  u32 circuit_id = ~0;
  u8 enabled = 1;
  u8 have_state = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "all"))
	circuit_id = ~0;
      else if (unformat (input, "%d", &circuit_id))
	;
      else if (unformat (input, "enable"))
	{
	  enabled = 1;
	  have_state = 1;
	}
      else if (unformat (input, "disable"))
	{
	  enabled = 0;
	  have_state = 1;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!have_state)
    return clib_error_return (0, "enable or disable required");

  rv = vnet_l2gw_circuit_set_state (circuit_id, enabled);
  if (rv)
    return clib_error_return (0, "l2gw circuit state failed (rv %d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (l2gw_circuit_state_command, static) = {
  .path = "osvbng l2gw state",
  .short_help = "osvbng l2gw state <circuit-id>|all enable|disable",
  .function = l2gw_circuit_state_command_fn,
};

static u8 *
format_l2gw_side (u8 *s, va_list *args)
{
  vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
  u32 sw_if_index = va_arg (*args, u32);
  u32 svlan = va_arg (*args, u32);
  u32 cvlan = va_arg (*args, u32);

  s = format (s, "%U svlan %d", format_vnet_sw_if_index_name, vnm,
	      sw_if_index, svlan);
  if (cvlan == L2GW_CVLAN_ANY)
    s = format (s, " cvlan any");
  else if (cvlan)
    s = format (s, " cvlan %d", cvlan);
  return s;
}

static clib_error_t *
l2gw_show_circuits_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  l2gw_main_t *lm = &l2gw_main;
  l2gw_entry_t *e;

  pool_foreach (e, lm->entries)
    {
      if (!(e->flags & L2GW_ENTRY_F_ACCESS_SIDE))
	continue;

      l2gw_entry_t *peer = pool_elt_at_index (lm->entries,
					      e->peer_entry_index);
      vlib_counter_t up, down;
      vlib_get_combined_counter (&lm->counters, e->circuit_id, &up);
      vlib_get_combined_counter (&lm->counters, e->peer_entry_index, &down);

      vlib_cli_output (
	vm, "[%u]%s%s access %U <-> handoff %U%s", e->circuit_id,
	(e->flags & L2GW_ENTRY_F_ENABLED) ? "" : " (disabled)",
	(e->flags & L2GW_ENTRY_F_TRANSPARENT) ? " (transparent)" : "",
	format_l2gw_side, lm->vnet_main, e->rx_sw_if_index, (u32) e->rx_svlan,
	(u32) e->rx_cvlan, format_l2gw_side, lm->vnet_main,
	peer->rx_sw_if_index, (u32) peer->rx_svlan, (u32) peer->rx_cvlan,
	(e->flags & L2GW_ENTRY_F_WILDCARD) ? " (wildcard)" : "");
      vlib_cli_output (
	vm, "     up %llu pkts %llu bytes / down %llu pkts %llu bytes",
	up.packets, up.bytes, down.packets, down.bytes);
    }

  return 0;
}

VLIB_CLI_COMMAND (l2gw_show_circuits_command, static) = {
  .path = "show osvbng l2gw circuits",
  .short_help = "show osvbng l2gw circuits",
  .function = l2gw_show_circuits_command_fn,
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
