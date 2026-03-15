/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - Core implementation
 * Pool management, subscriber mapping, bypass table, feature enablement.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <osvbng_cgnat/osvbng_cgnat.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

cgnat_main_t cgnat_main;

char *cgnat_error_strings[] = {
#define cgnat_error(n, s) s,
#include <osvbng_cgnat/osvbng_cgnat_error.def>
#undef cgnat_error
};

int
cgnat_pool_add_del (cgnat_pool_t *cfg, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p;

  p = hash_get (cm->pool_by_id, cfg->pool_id);

  if (is_add)
    {
      if (p)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      cgnat_pool_t *pool;
      pool_get_zero (cm->pools, pool);
      u32 pool_index = pool - cm->pools;

      pool->pool_id = cfg->pool_id;
      pool->mode = cfg->mode;
      pool->address_pooling = cfg->address_pooling;
      pool->filtering = cfg->filtering;
      pool->block_size = cfg->block_size;
      pool->max_blocks_per_sub = cfg->max_blocks_per_sub;
      pool->max_sessions_per_sub = cfg->max_sessions_per_sub;
      pool->port_range_start = cfg->port_range_start;
      pool->port_range_end = cfg->port_range_end;
      pool->port_reuse_timeout = cfg->port_reuse_timeout;
      pool->alg_bitmask = cfg->alg_bitmask;
      clib_memcpy (pool->timeouts, cfg->timeouts, sizeof (pool->timeouts));
      pool->outside_fib_index = ~0;
      pool->outside_fib_valid = 0;

      if (cfg->det_params && cfg->n_det_params > 0)
	{
	  vec_validate (pool->det_params, cfg->n_det_params - 1);
	  clib_memcpy (pool->det_params, cfg->det_params,
		       cfg->n_det_params * sizeof (cgnat_det_params_t));
	  pool->n_det_params = cfg->n_det_params;
	}

      hash_set (cm->pool_by_id, cfg->pool_id, pool_index);

      vlib_log_notice (cm->log_class,
		       "pool %u added (mode %s, block_size %u)",
		       cfg->pool_id,
		       cfg->mode == CGNAT_POOL_MODE_PBA ? "pba" :
							  "deterministic",
		       cfg->block_size);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      u32 pool_index = p[0];
      cgnat_pool_t *pool = pool_elt_at_index (cm->pools, pool_index);

      for (u32 i = 0; i < vec_len (pool->outside_prefixes); i++)
	{
	  if (pool->outside_fib_valid &&
	      pool->outside_fib_entries[i] != FIB_NODE_INDEX_INVALID)
	    fib_table_entry_special_remove (pool->outside_fib_index,
					   &pool->outside_prefixes[i],
					   cm->outside_fib_src);
	}
      vec_free (pool->outside_prefixes);
      vec_free (pool->outside_fib_entries);
      dpo_reset (&pool->dpo);

      vec_free (pool->det_params);
      hash_unset (cm->pool_by_id, pool->pool_id);
      pool_put (cm->pools, pool);

      vlib_log_notice (cm->log_class, "pool %u deleted", cfg->pool_id);
    }

  return 0;
}

int
cgnat_set_outside_fib (u32 pool_id, u32 vrf_id)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_by_id, pool_id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  if (fib_index == ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  u32 pool_index = p[0];
  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, pool_index);

  if (pool->outside_fib_valid)
    {
      for (u32 i = 0; i < vec_len (pool->outside_prefixes); i++)
	{
	  if (pool->outside_fib_entries[i] != FIB_NODE_INDEX_INVALID)
	    fib_table_entry_special_remove (pool->outside_fib_index,
					   &pool->outside_prefixes[i],
					   cm->outside_fib_src);
	  pool->outside_fib_entries[i] = FIB_NODE_INDEX_INVALID;
	}
    }

  pool->outside_fib_index = fib_index;
  pool->outside_fib_valid = 1;

  if (!dpo_id_is_valid (&pool->dpo))
    {
      dpo_set (&pool->dpo, cm->dpo_type, DPO_PROTO_IP4, pool_index);
    }

  for (u32 i = 0; i < vec_len (pool->outside_prefixes); i++)
    {
      pool->outside_fib_entries[i] = fib_table_entry_special_dpo_add (
	fib_index, &pool->outside_prefixes[i], cm->outside_fib_src,
	FIB_ENTRY_FLAG_EXCLUSIVE, &pool->dpo);
    }

  vlib_log_notice (cm->log_class,
		   "pool %u outside FIB: vrf_id %u -> fib_index %u (%u prefixes installed)",
		   pool_id, vrf_id, fib_index, vec_len (pool->outside_prefixes));
  return 0;
}

int
cgnat_add_del_subscriber_mapping (u32 pool_id, u32 sw_if_index,
				  ip4_address_t *inside_ip, u32 inside_vrf_id,
				  ip4_address_t *outside_ip, u16 port_start,
				  u16 port_end, u8 enable_feature, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_by_id, pool_id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  u32 pool_index = p[0];

  u32 fib_index =
    fib_table_find (FIB_PROTOCOL_IP4, inside_vrf_id);
  if (fib_index == ~0)
    fib_index = 0;

  if (is_add)
    {
      clib_bihash_kv_8_8_t kv;
      cgnat_inside_key_t key;
      key.ip.as_u32 = inside_ip->as_u32;
      key.fib_index = fib_index;
      kv.key = key.as_u64;

      if (clib_bihash_search_inline_8_8 (&cm->inside_lookup, &kv) == 0)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      cgnat_mapping_t *m;
      pool_get_zero (cm->mappings, m);
      u32 mapping_index = m - cm->mappings;

      m->inside_ip.as_u32 = inside_ip->as_u32;
      m->outside_ip.as_u32 = outside_ip->as_u32;
      m->inside_vrf_id = inside_vrf_id;
      m->inside_fib_index = fib_index;
      m->port_block_start = port_start;
      m->port_block_end = port_end;
      m->pool_index = pool_index;
      m->sw_if_index = sw_if_index;
      m->next_port = port_start;
      m->session_count = 0;

      u32 block_size = port_end - port_start + 1;
      vec_validate_init_empty (m->port_reuse_timestamps, block_size - 1,
			       0.0);

      kv.value = mapping_index;
      clib_bihash_add_del_8_8 (&cm->inside_lookup, &kv, 1);

      if (enable_feature)
	vnet_feature_enable_disable ("ip4-unicast", "cgnat-in2out",
				     sw_if_index, 1, 0, 0);

      vlib_log_notice (
	cm->log_class,
	"mapping added: %U → %U:%u-%u (pool %u, sw_if %u)",
	format_ip4_address, inside_ip, format_ip4_address, outside_ip,
	port_start, port_end, pool_id, sw_if_index);
    }
  else
    {
      clib_bihash_kv_8_8_t kv;
      cgnat_inside_key_t key;
      key.ip.as_u32 = inside_ip->as_u32;
      key.fib_index = fib_index;
      kv.key = key.as_u64;

      if (clib_bihash_search_inline_8_8 (&cm->inside_lookup, &kv) != 0)
	return 0;

      u32 mapping_index = (u32) kv.value;
      cgnat_mapping_t *m = pool_elt_at_index (cm->mappings, mapping_index);

      if (enable_feature || m->sw_if_index != ~0)
	vnet_feature_enable_disable ("ip4-unicast", "cgnat-in2out",
				     m->sw_if_index, 0, 0, 0);

      /* TODO: walk and delete all sessions for this mapping */

      vec_free (m->port_reuse_timestamps);
      clib_bihash_add_del_8_8 (&cm->inside_lookup, &kv, 0);
      pool_put (cm->mappings, m);

      vlib_log_notice (cm->log_class,
		       "mapping removed: %U (pool %u)", format_ip4_address,
		       inside_ip, pool_id);
    }

  return 0;
}

int
cgnat_enable_on_session (u32 pool_id, u32 sw_if_index, u8 is_enable)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_by_id, pool_id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vnet_feature_enable_disable ("ip4-unicast", "cgnat-in2out", sw_if_index,
			       is_enable, 0, 0);

  vlib_log_notice (cm->log_class, "cgnat-in2out %s on sw_if %u (pool %u)",
		   is_enable ? "enabled" : "disabled", sw_if_index, pool_id);
  return 0;
}

int
cgnat_pool_add_outside_prefix (u32 pool_id, fib_prefix_t *prefix)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_by_id, pool_id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  u32 pool_index = p[0];
  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, pool_index);

  vec_add1 (pool->outside_prefixes, *prefix);
  fib_node_index_t fei = FIB_NODE_INDEX_INVALID;

  if (pool->outside_fib_valid)
    {
      if (!dpo_id_is_valid (&pool->dpo))
	dpo_set (&pool->dpo, cm->dpo_type, DPO_PROTO_IP4, pool_index);

      fei = fib_table_entry_special_dpo_add (
	pool->outside_fib_index, prefix, cm->outside_fib_src,
	FIB_ENTRY_FLAG_EXCLUSIVE, &pool->dpo);
    }

  vec_add1 (pool->outside_fib_entries, fei);

  vlib_log_notice (cm->log_class,
		   "pool %u outside prefix %U/%u added (fib_entry %s)",
		   pool_id, format_ip4_address, &prefix->fp_addr.ip4,
		   prefix->fp_len,
		   fei != FIB_NODE_INDEX_INVALID ? "installed" : "deferred");
  return 0;
}

int
cgnat_pool_del_outside_prefix (u32 pool_id, fib_prefix_t *prefix)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_by_id, pool_id);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, p[0]);

  for (u32 i = 0; i < vec_len (pool->outside_prefixes); i++)
    {
      if (pool->outside_prefixes[i].fp_len == prefix->fp_len &&
	  pool->outside_prefixes[i].fp_addr.ip4.as_u32 ==
	    prefix->fp_addr.ip4.as_u32)
	{
	  if (pool->outside_fib_valid &&
	      pool->outside_fib_entries[i] != FIB_NODE_INDEX_INVALID)
	    fib_table_entry_special_remove (pool->outside_fib_index, prefix,
					   cm->outside_fib_src);

	  vec_del1 (pool->outside_prefixes, i);
	  vec_del1 (pool->outside_fib_entries, i);

	  vlib_log_notice (cm->log_class,
			   "pool %u outside prefix %U/%u removed", pool_id,
			   format_ip4_address, &prefix->fp_addr.ip4,
			   prefix->fp_len);
	  return 0;
	}
    }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
cgnat_add_del_bypass (fib_prefix_t *prefix, u32 vrf_id, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf_id);
  if (fib_index == ~0)
    fib_index = 0;

  if (is_add)
    {
      cgnat_bypass_entry_t *be;
      pool_get_zero (cm->bypass_entries, be);
      be->prefix = *prefix;
      be->fib_index = fib_index;

      be->fib_entry_index = fib_table_entry_special_add (
	fib_index, prefix, cm->bypass_fib_src, FIB_ENTRY_FLAG_DROP);
      cm->bypass_entry_count++;

      vlib_log_notice (cm->log_class, "bypass added: %U/%u vrf %u",
		       format_ip4_address, &prefix->fp_addr.ip4, prefix->fp_len,
		       vrf_id);
    }
  else
    {
      cgnat_bypass_entry_t *be;
      pool_foreach (be, cm->bypass_entries)
	{
	  if (be->fib_index == fib_index &&
	      be->prefix.fp_len == prefix->fp_len &&
	      be->prefix.fp_addr.ip4.as_u32 == prefix->fp_addr.ip4.as_u32)
	    {
	      fib_table_entry_special_remove (fib_index, prefix,
					      cm->bypass_fib_src);
	      pool_put (cm->bypass_entries, be);
	      cm->bypass_entry_count--;

	      vlib_log_notice (cm->log_class, "bypass removed: %U/%u vrf %u",
			       format_ip4_address, &prefix->fp_addr.ip4,
			       prefix->fp_len, vrf_id);
	      break;
	    }
	}
    }

  return 0;
}

int
cgnat_pool_update (u32 pool_id, u32 max_sessions, u8 alg_bitmask,
		   u32 *timeouts)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_by_id, pool_id);

  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, p[0]);
  pool->max_sessions_per_sub = max_sessions;
  pool->alg_bitmask = alg_bitmask;
  if (timeouts)
    clib_memcpy (pool->timeouts, timeouts, sizeof (pool->timeouts));

  vlib_log_notice (cm->log_class, "pool %u updated", pool_id);
  return 0;
}

static clib_error_t *
show_osvbng_cgnat_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;

  vlib_cli_output (vm, "%-8s %-12s %-10s %-10s %-8s %-10s %-8s", "Pool ID",
		   "Mode", "BlockSize", "MaxSess", "ALG", "OutFIB", "Maps");

  pool_foreach (pool, cm->pools)
    {
      vlib_cli_output (vm, "%-8u %-12s %-10u %-10u 0x%02x    %-10u %-8u",
		       pool->pool_id,
		       pool->mode == CGNAT_POOL_MODE_PBA ? "pba" :
							   "deterministic",
		       pool->block_size, pool->max_sessions_per_sub,
		       pool->alg_bitmask,
		       pool->outside_fib_valid ? pool->outside_fib_index : ~0,
		       pool_elts (cm->mappings));
    }

  vlib_cli_output (vm, "\nMappings: %u  Sessions: %u  Bypasses: %u",
		   pool_elts (cm->mappings), pool_elts (cm->sessions),
		   cm->bypass_entry_count);

  return 0;
}

VLIB_CLI_COMMAND (show_osvbng_cgnat_command, static) = {
  .path = "show osvbng cgnat",
  .short_help = "show osvbng cgnat",
  .function = show_osvbng_cgnat_command_fn,
};

static clib_error_t *
show_osvbng_cgnat_mappings_command_fn (vlib_main_t *vm,
				       unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_mapping_t *m;

  vlib_cli_output (vm, "%-18s %-18s %-12s %-12s %-8s", "Inside IP",
		   "Outside IP", "Ports", "Sessions", "SwIf");

  pool_foreach (m, cm->mappings)
    {
      vlib_cli_output (vm, "%-18U %-18U %u-%u     %-12u %-8u",
		       format_ip4_address, &m->inside_ip, format_ip4_address,
		       &m->outside_ip, m->port_block_start, m->port_block_end,
		       m->session_count, m->sw_if_index);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_osvbng_cgnat_mappings_command, static) = {
  .path = "show osvbng cgnat mappings",
  .short_help = "show osvbng cgnat mappings",
  .function = show_osvbng_cgnat_mappings_command_fn,
};

static void
cgnat_dpo_lock (dpo_id_t *dpo)
{
}

static void
cgnat_dpo_unlock (dpo_id_t *dpo)
{
}

static u8 *
format_cgnat_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);

  s = format (s, "cgnat-out2in pool:%d", index);
  return s;
}

const static dpo_vft_t cgnat_dpo_vft = {
  .dv_lock = cgnat_dpo_lock,
  .dv_unlock = cgnat_dpo_unlock,
  .dv_format = format_cgnat_dpo,
};

const static char *const cgnat_dpo_ip4_nodes[] = {
  "cgnat-out2in",
  NULL,
};

const static char *const *const cgnat_dpo_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = cgnat_dpo_ip4_nodes,
};

void
cgnat_dpo_module_init (void)
{
  cgnat_main_t *cm = &cgnat_main;
  cm->dpo_type =
    dpo_register_new_type (&cgnat_dpo_vft, cgnat_dpo_nodes);
}

static clib_error_t *
osvbng_cgnat_init (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();

  cm->log_class = vlib_log_register_class ("osvbng_cgnat", 0);

  cm->pool_by_id = hash_create (0, sizeof (uword));

  cgnat_session_table_init ();

  clib_bihash_init_8_8 (&cm->inside_lookup, "cgnat inside lookup", 1024,
			 16 << 20);

  cm->bypass_fib_src = fib_source_allocate ("cgnat-bypass",
					    FIB_SOURCE_PRIORITY_HI,
					    FIB_SOURCE_BH_DROP);

  cm->outside_fib_src = fib_source_allocate ("cgnat-outside",
					     FIB_SOURCE_PRIORITY_HI,
					     FIB_SOURCE_BH_API);

  cgnat_dpo_module_init ();

  vlib_log_notice (cm->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_cgnat_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0.0",
  .description = "osvbng CGNAT Plugin",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
