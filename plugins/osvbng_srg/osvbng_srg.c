/* Copyright 2025 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng SRG Plugin - Core implementation
 * SRG add/del, state transitions, virtual MAC management, CLI.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/interface_funcs.h>

#include <osvbng_srg/osvbng_srg.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

osvbng_srg_main_t osvbng_srg_main;

char *srg_error_strings[] = {
#define srg_error(n, s) s,
#include <osvbng_srg/osvbng_srg_error.def>
#undef srg_error
};

static inline void
srg_vec_validate_if_to_srg (u32 sw_if_index)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vec_validate_init_empty (sm->if_to_srg, sw_if_index, ~0);
}

/*
 * Null-terminate a VPP API string type (length-prefixed).
 * The caller must provide a buffer of at least 64 bytes.
 */
static inline void
srg_name_terminate (u8 *dst, const u8 *src, u32 max_len)
{
  u32 len = clib_min (max_len - 1, strlen ((const char *) src));
  clib_memcpy (dst, src, len);
  dst[len] = 0;
}

int
osvbng_srg_add_del (u8 *name, mac_address_t *mac, u32 *sw_if_indices,
		    u32 count, u8 is_add)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vnet_main_t *vnm = sm->vnet_main;
  uword *p;

  p = hash_get_mem (sm->srg_by_name, name);

  if (is_add)
    {
      if (p)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      /* Validate all sw_if_indices exist and are not already assigned */
      for (u32 i = 0; i < count; i++)
	{
	  if (pool_is_free_index (vnm->interface_main.sw_interfaces,
				  sw_if_indices[i]))
	    {
	      vlib_log_err (sm->log_class,
			    "add: sw_if_index %u does not exist",
			    sw_if_indices[i]);
	      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
	    }

	  srg_vec_validate_if_to_srg (sw_if_indices[i]);
	  if (sm->if_to_srg[sw_if_indices[i]] != ~0)
	    {
	      vlib_log_err (sm->log_class,
			    "add: sw_if_index %u already belongs to SRG %s",
			    sw_if_indices[i],
			    sm->srgs[sm->if_to_srg[sw_if_indices[i]]].srg_name);
	      return VNET_API_ERROR_VALUE_EXIST;
	    }
	}

      osvbng_srg_t *srg;
      pool_get_zero (sm->srgs, srg);
      u32 srg_index = srg - sm->srgs;

      srg_name_terminate (srg->srg_name, name, sizeof (srg->srg_name));
      clib_memcpy (&srg->virtual_mac, mac, sizeof (mac_address_t));
      srg->is_active = false;

      for (u32 i = 0; i < count; i++)
	{
	  vec_add1 (srg->sw_if_indices, sw_if_indices[i]);
	  sm->if_to_srg[sw_if_indices[i]] = srg_index;
	}

      hash_set_mem (sm->srg_by_name, srg->srg_name, srg_index);

      /* Extend counter vecs */
      vec_validate (sm->garp_sent, srg_index);
      vec_validate (sm->na_sent, srg_index);
      vec_validate (sm->mac_adds, srg_index);
      vec_validate (sm->mac_removes, srg_index);
      vec_validate (sm->garp_skipped, srg_index);
      sm->garp_sent[srg_index] = 0;
      sm->na_sent[srg_index] = 0;
      sm->mac_adds[srg_index] = 0;
      sm->mac_removes[srg_index] = 0;
      sm->garp_skipped[srg_index] = 0;

      vlib_log_notice (sm->log_class,
		       "SRG '%s' added with %u interfaces, vMAC %U",
		       srg->srg_name, count, format_mac_address_t,
		       &srg->virtual_mac);
    }
  else
    {
      /* Delete */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      u32 srg_index = p[0];
      osvbng_srg_t *srg = pool_elt_at_index (sm->srgs, srg_index);

      /* If active, transition to standby first */
      if (srg->is_active)
	osvbng_srg_set_state (name, 0);

      /* Clear if_to_srg entries */
      for (u32 i = 0; i < vec_len (srg->sw_if_indices); i++)
	{
	  u32 sw = srg->sw_if_indices[i];
	  if (sw < vec_len (sm->if_to_srg))
	    sm->if_to_srg[sw] = ~0;
	}

      vlib_log_notice (sm->log_class, "SRG '%s' deleted", srg->srg_name);

      hash_unset_mem (sm->srg_by_name, srg->srg_name);
      vec_free (srg->sw_if_indices);
      pool_put (sm->srgs, srg);
    }

  return 0;
}

int
osvbng_srg_set_state (u8 *name, u8 is_active)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vnet_main_t *vnm = sm->vnet_main;
  uword *p;

  p = hash_get_mem (sm->srg_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  u32 srg_index = p[0];
  osvbng_srg_t *srg = pool_elt_at_index (sm->srgs, srg_index);

  /* Idempotent */
  if ((is_active && srg->is_active) || (!is_active && !srg->is_active))
    return 0;

  for (u32 i = 0; i < vec_len (srg->sw_if_indices); i++)
    {
      u32 sw_if_index = srg->sw_if_indices[i];

      /* Validate interface still exists */
      if (pool_is_free_index (vnm->interface_main.sw_interfaces, sw_if_index))
	{
	  vlib_log_warn (sm->log_class,
			 "set_state: sw_if_index %u no longer valid, skipping",
			 sw_if_index);
	  continue;
	}

      vnet_hw_interface_t *hw =
	vnet_get_sup_hw_interface (vnm, sw_if_index);

      osvbng_srg_hw_mac_key_t key;
      clib_memset (&key, 0, sizeof (key));
      key.hw_if_index = hw->hw_if_index;
      clib_memcpy (key.mac, srg->virtual_mac.bytes, 6);

      uword *refp = mhash_get (&sm->hw_mac_refcount, &key);

      if (is_active)
	{
	  if (refp)
	    {
	      /* Already added on this HW interface, bump refcount */
	      (*refp)++;
	    }
	  else
	    {
	      /* First ref — add vMAC to HW interface */
	      clib_error_t *err =
		vnet_hw_interface_add_del_mac_address (vnm, hw->hw_if_index,
						       srg->virtual_mac.bytes,
						       1 /* is_add */);
	      if (err)
		{
		  vlib_log_err (sm->log_class,
				"failed to add vMAC %U on hw_if %u: %U",
				format_mac_address_t, &srg->virtual_mac,
				hw->hw_if_index, format_clib_error, err);
		  clib_error_free (err);
		  continue;
		}

	      uword one = 1;
	      mhash_set (&sm->hw_mac_refcount, &key, one, NULL);
	      sm->mac_adds[srg_index]++;

	      vlib_log_notice (sm->log_class,
			       "added vMAC %U on hw_if %u (SRG '%s')",
			       format_mac_address_t, &srg->virtual_mac,
			       hw->hw_if_index, srg->srg_name);
	    }
	}
      else
	{
	  if (!refp)
	    continue;

	  if (*refp > 1)
	    {
	      (*refp)--;
	    }
	  else
	    {
	      /* Last ref — remove vMAC from HW interface */
	      clib_error_t *err =
		vnet_hw_interface_add_del_mac_address (vnm, hw->hw_if_index,
						       srg->virtual_mac.bytes,
						       0 /* is_add */);
	      if (err)
		{
		  vlib_log_err (sm->log_class,
				"failed to remove vMAC %U on hw_if %u: %U",
				format_mac_address_t, &srg->virtual_mac,
				hw->hw_if_index, format_clib_error, err);
		  clib_error_free (err);
		  continue;
		}

	      mhash_unset (&sm->hw_mac_refcount, &key, NULL);
	      sm->mac_removes[srg_index]++;

	      vlib_log_notice (sm->log_class,
			       "removed vMAC %U on hw_if %u (SRG '%s')",
			       format_mac_address_t, &srg->virtual_mac,
			       hw->hw_if_index, srg->srg_name);
	    }
	}
    }

  srg->is_active = is_active;

  vlib_log_notice (sm->log_class, "SRG '%s' → %s", srg->srg_name,
		   is_active ? "ACTIVE" : "STANDBY");

  return 0;
}

/*
 * CLI: show osvbng srg [name <name>]
 */
static clib_error_t *
show_osvbng_srg_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  u8 *name = 0;
  osvbng_srg_t *srg;
  u32 srg_index;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (name)
    {
      uword *p = hash_get_mem (sm->srg_by_name, name);
      if (!p)
	{
	  vec_free (name);
	  return clib_error_return (0, "SRG '%s' not found", name);
	}

      srg_index = p[0];
      srg = pool_elt_at_index (sm->srgs, srg_index);

      vlib_cli_output (vm, "%-20s %-20s %-8s %-6s %-10s %-10s %-10s %-10s %-10s",
		       "Name", "Virtual MAC", "State", "IFs", "GARP Sent",
		       "NA Sent", "MAC Adds", "MAC Dels", "GARP Skip");
      vlib_cli_output (vm,
		       "%-20s %-20U %-8s %-6u %-10llu %-10llu %-10llu %-10llu %-10llu",
		       srg->srg_name, format_mac_address_t,
		       &srg->virtual_mac,
		       srg->is_active ? "active" : "standby",
		       vec_len (srg->sw_if_indices),
		       sm->garp_sent[srg_index], sm->na_sent[srg_index],
		       sm->mac_adds[srg_index], sm->mac_removes[srg_index],
		       sm->garp_skipped[srg_index]);

      vec_free (name);
    }
  else
    {
      vlib_cli_output (vm, "%-20s %-20s %-8s %-6s %-10s %-10s %-10s %-10s %-10s",
		       "Name", "Virtual MAC", "State", "IFs", "GARP Sent",
		       "NA Sent", "MAC Adds", "MAC Dels", "GARP Skip");

      pool_foreach (srg, sm->srgs)
	{
	  srg_index = srg - sm->srgs;
	  vlib_cli_output (
	    vm, "%-20s %-20U %-8s %-6u %-10llu %-10llu %-10llu %-10llu %-10llu",
	    srg->srg_name, format_mac_address_t, &srg->virtual_mac,
	    srg->is_active ? "active" : "standby",
	    vec_len (srg->sw_if_indices), sm->garp_sent[srg_index],
	    sm->na_sent[srg_index], sm->mac_adds[srg_index],
	    sm->mac_removes[srg_index], sm->garp_skipped[srg_index]);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (show_osvbng_srg_command, static) = {
  .path = "show osvbng srg",
  .short_help = "show osvbng srg [name <name>]",
  .function = show_osvbng_srg_command_fn,
};

/*
 * Plugin init
 */
static clib_error_t *
osvbng_srg_init (vlib_main_t *vm)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vlib_node_t *intf_output_node;

  sm->vlib_main = vm;
  sm->vnet_main = vnet_get_main ();

  sm->log_class = vlib_log_register_class ("osvbng_srg", 0);

  sm->srg_by_name = hash_create_string (0, sizeof (uword));
  mhash_init (&sm->hw_mac_refcount, sizeof (uword),
	       sizeof (osvbng_srg_hw_mac_key_t));

  intf_output_node =
    vlib_get_node_by_name (vm, (u8 *) "interface-output");
  sm->intf_output_node_idx = intf_output_node->index;

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_srg_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0.0",
  .description = "osvbng SRG Plugin",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
