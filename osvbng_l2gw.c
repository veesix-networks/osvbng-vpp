/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng L2GW Plugin - circuit management
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <osvbng_l2gw/osvbng_l2gw.h>

l2gw_main_t l2gw_main;

char *l2gw_error_strings[] = {
#define l2gw_error(n, s) s,
#include <osvbng_l2gw/osvbng_l2gw_error.def>
#undef l2gw_error
};

static void
l2gw_table_add_del (l2gw_key_t *key, u32 entry_index, int is_add)
{
  l2gw_main_t *lm = &l2gw_main;
  clib_bihash_kv_16_8_t kv;
  l2gw_result_t result;

  result.raw = 0;
  result.fields.entry_index = entry_index;

  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];
  kv.value = result.raw;

  clib_bihash_add_del_16_8 (&lm->circuit_table, &kv, is_add);
}

static int
l2gw_table_lookup (l2gw_key_t *key, u32 *entry_indexp)
{
  l2gw_main_t *lm = &l2gw_main;
  clib_bihash_kv_16_8_t kv;

  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];
  kv.value = ~0ULL;

  if (clib_bihash_search_inline_16_8 (&lm->circuit_table, &kv) < 0)
    return -1;

  *entry_indexp = ((l2gw_result_t) { .raw = kv.value }).fields.entry_index;
  return 0;
}

static u16
l2gw_normalize_tpid (u16 tpid)
{
  if (tpid == 0)
    return ETHERNET_TYPE_DOT1AD;
  return tpid;
}

static int
l2gw_validate_args (vnet_l2gw_add_del_circuit_args_t *a)
{
  l2gw_main_t *lm = &l2gw_main;
  int access_wild = a->access_cvlan == L2GW_CVLAN_ANY;
  int handoff_wild = a->handoff_cvlan == L2GW_CVLAN_ANY;

  if (!vnet_sw_interface_is_api_valid (lm->vnet_main, a->access_sw_if_index) ||
      !vnet_sw_interface_is_api_valid (lm->vnet_main, a->handoff_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (a->access_svlan > 4095 || a->handoff_svlan > 4095)
    return VNET_API_ERROR_INVALID_VALUE;
  if (!access_wild && a->access_cvlan > 4095)
    return VNET_API_ERROR_INVALID_VALUE;
  if (!handoff_wild && a->handoff_cvlan > 4095)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Wildcard circuits are symmetric and need a real outer tag on both
   * sides: the C-tags pass through untouched and the S-tag is the only
   * thing that can translate. */
  if (access_wild != handoff_wild)
    return VNET_API_ERROR_INVALID_VALUE_2;
  if (access_wild && (a->access_svlan == 0 || a->handoff_svlan == 0))
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* An inner tag without an outer tag is not a valid emission target. */
  if (!handoff_wild && a->handoff_cvlan != 0 && a->handoff_svlan == 0)
    return VNET_API_ERROR_INVALID_VALUE_2;
  if (!access_wild && a->access_cvlan != 0 && a->access_svlan == 0)
    return VNET_API_ERROR_INVALID_VALUE_2;

  u16 atpid = l2gw_normalize_tpid (a->access_tpid);
  u16 htpid = l2gw_normalize_tpid (a->handoff_tpid);
  if ((atpid != ETHERNET_TYPE_DOT1AD && atpid != ETHERNET_TYPE_VLAN) ||
      (htpid != ETHERNET_TYPE_DOT1AD && htpid != ETHERNET_TYPE_VLAN))
    return VNET_API_ERROR_INVALID_VALUE;

  return 0;
}

static void
l2gw_fill_entry (l2gw_entry_t *e, u32 rx_sw_if_index, u16 rx_svlan,
		 u16 rx_cvlan, u32 tx_sw_if_index, u16 tx_svlan, u16 tx_cvlan,
		 u16 tx_tpid, u8 flags)
{
  clib_memset (e, 0, sizeof (*e));
  e->rx_sw_if_index = rx_sw_if_index;
  e->rx_svlan = rx_svlan;
  e->rx_cvlan = rx_cvlan;
  e->tx_sw_if_index = tx_sw_if_index;
  e->tx_svlan = tx_svlan;
  e->tx_cvlan = tx_cvlan;
  e->tx_outer_tpid = tx_tpid;
  e->flags = flags;
  e->qos_index = ~0;
  e->acl_index = ~0;
}

static int
l2gw_entry_matches_args (l2gw_entry_t *access_e, l2gw_entry_t *handoff_e,
			 vnet_l2gw_add_del_circuit_args_t *a, u8 flags_common)
{
  u16 atpid = l2gw_normalize_tpid (a->access_tpid);
  u16 htpid = l2gw_normalize_tpid (a->handoff_tpid);

  return access_e->tx_sw_if_index == a->handoff_sw_if_index &&
	 access_e->tx_svlan == (a->transparent ? 0 : a->handoff_svlan) &&
	 access_e->tx_cvlan ==
	   ((a->transparent || a->handoff_cvlan == L2GW_CVLAN_ANY) ?
	      0 :
	      a->handoff_cvlan) &&
	 access_e->tx_outer_tpid == htpid &&
	 handoff_e->tx_svlan == (a->transparent ? 0 : a->access_svlan) &&
	 handoff_e->tx_cvlan ==
	   ((a->transparent || a->access_cvlan == L2GW_CVLAN_ANY) ?
	      0 :
	      a->access_cvlan) &&
	 handoff_e->tx_outer_tpid == atpid &&
	 ((access_e->flags & (L2GW_ENTRY_F_WILDCARD | L2GW_ENTRY_F_TRANSPARENT)) ==
	  (flags_common & (L2GW_ENTRY_F_WILDCARD | L2GW_ENTRY_F_TRANSPARENT)));
}

int
vnet_l2gw_add_del_circuit (vnet_l2gw_add_del_circuit_args_t *a,
			   u32 *circuit_idp)
{
  l2gw_main_t *lm = &l2gw_main;
  l2gw_key_t access_key, handoff_key;
  u32 existing_access;
  int rv;

  *circuit_idp = ~0;

  if ((rv = l2gw_validate_args (a)))
    return rv;

  l2gw_make_key (&access_key, a->access_sw_if_index, a->access_svlan,
		 a->access_cvlan);
  l2gw_make_key (&handoff_key, a->handoff_sw_if_index, a->handoff_svlan,
		 a->handoff_cvlan);

  int access_exists = l2gw_table_lookup (&access_key, &existing_access) == 0;

  if (!a->is_add)
    {
      if (!access_exists)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      l2gw_entry_t *e = pool_elt_at_index (lm->entries, existing_access);
      l2gw_entry_t *peer = pool_elt_at_index (lm->entries, e->peer_entry_index);

      l2gw_key_t ekey, pkey;
      l2gw_make_key (&ekey, e->rx_sw_if_index, e->rx_svlan, e->rx_cvlan);
      l2gw_make_key (&pkey, peer->rx_sw_if_index, peer->rx_svlan,
		     peer->rx_cvlan);
      l2gw_table_add_del (&ekey, existing_access, 0);
      l2gw_table_add_del (&pkey, e->peer_entry_index, 0);

      *circuit_idp = e->circuit_id;
      pool_put (lm->entries, peer);
      pool_put (lm->entries, e);
      return 0;
    }

  u8 flags_common = a->enabled ? L2GW_ENTRY_F_ENABLED : 0;
  if (a->access_cvlan == L2GW_CVLAN_ANY)
    flags_common |= L2GW_ENTRY_F_WILDCARD;
  if (a->transparent)
    flags_common |= L2GW_ENTRY_F_TRANSPARENT;

  if (access_exists)
    {
      l2gw_entry_t *e = pool_elt_at_index (lm->entries, existing_access);
      l2gw_entry_t *peer = pool_elt_at_index (lm->entries, e->peer_entry_index);

      *circuit_idp = e->circuit_id;

      if (l2gw_entry_matches_args (e, peer, a, flags_common) &&
	  peer->rx_sw_if_index == a->handoff_sw_if_index &&
	  peer->rx_svlan == a->handoff_svlan &&
	  peer->rx_cvlan == a->handoff_cvlan)
	return 0;

      return VNET_API_ERROR_ENTRY_NEEDS_REFRESH;
    }

  u32 dummy;
  if (l2gw_table_lookup (&handoff_key, &dummy) == 0)
    return VNET_API_ERROR_VALUE_EXIST;

  l2gw_entry_t *access_e, *handoff_e;
  u32 access_index, handoff_index;

  pool_get_aligned (lm->entries, access_e, CLIB_CACHE_LINE_BYTES);
  access_index = access_e - lm->entries;
  pool_get_aligned (lm->entries, handoff_e, CLIB_CACHE_LINE_BYTES);
  handoff_index = handoff_e - lm->entries;
  access_e = pool_elt_at_index (lm->entries, access_index);

  u16 atpid = l2gw_normalize_tpid (a->access_tpid);
  u16 htpid = l2gw_normalize_tpid (a->handoff_tpid);
  u16 wild_or_transparent =
    a->transparent || a->access_cvlan == L2GW_CVLAN_ANY;

  l2gw_fill_entry (access_e, a->access_sw_if_index, a->access_svlan,
		   a->access_cvlan, a->handoff_sw_if_index,
		   a->transparent ? 0 : a->handoff_svlan,
		   wild_or_transparent ? 0 : a->handoff_cvlan, htpid,
		   flags_common | L2GW_ENTRY_F_ACCESS_SIDE);
  l2gw_fill_entry (handoff_e, a->handoff_sw_if_index, a->handoff_svlan,
		   a->handoff_cvlan, a->access_sw_if_index,
		   a->transparent ? 0 : a->access_svlan,
		   wild_or_transparent ? 0 : a->access_cvlan, atpid,
		   flags_common);

  access_e->peer_entry_index = handoff_index;
  handoff_e->peer_entry_index = access_index;
  access_e->circuit_id = access_index;
  handoff_e->circuit_id = access_index;

  u32 max_index = clib_max (access_index, handoff_index);
  vlib_validate_combined_counter (&lm->counters, max_index);
  vlib_zero_combined_counter (&lm->counters, access_index);
  vlib_zero_combined_counter (&lm->counters, handoff_index);

  l2gw_table_add_del (&access_key, access_index, 1);
  l2gw_table_add_del (&handoff_key, handoff_index, 1);

  *circuit_idp = access_index;
  return 0;
}

int
vnet_l2gw_circuit_set_state (u32 circuit_id, u8 enabled)
{
  l2gw_main_t *lm = &l2gw_main;
  l2gw_entry_t *e;

  if (circuit_id == ~0)
    {
      pool_foreach (e, lm->entries)
	{
	  if (enabled)
	    e->flags |= L2GW_ENTRY_F_ENABLED;
	  else
	    e->flags &= ~L2GW_ENTRY_F_ENABLED;
	}
      return 0;
    }

  if (pool_is_free_index (lm->entries, circuit_id))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  e = pool_elt_at_index (lm->entries, circuit_id);
  if (!(e->flags & L2GW_ENTRY_F_ACCESS_SIDE))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  l2gw_entry_t *peer = pool_elt_at_index (lm->entries, e->peer_entry_index);
  if (enabled)
    {
      e->flags |= L2GW_ENTRY_F_ENABLED;
      peer->flags |= L2GW_ENTRY_F_ENABLED;
    }
  else
    {
      e->flags &= ~L2GW_ENTRY_F_ENABLED;
      peer->flags &= ~L2GW_ENTRY_F_ENABLED;
    }

  return 0;
}

int
vnet_l2gw_enable_disable (u32 sw_if_index, u8 enable)
{
  l2gw_main_t *lm = &l2gw_main;

  if (!vnet_sw_interface_is_api_valid (lm->vnet_main, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (clib_bitmap_get (lm->enabled_by_sw_if_index, sw_if_index) ==
      (enable != 0))
    return 0;

  int rv = vnet_feature_enable_disable ("device-input", "l2gw-input",
					sw_if_index, enable, 0, 0);
  if (rv)
    return rv;

  lm->enabled_by_sw_if_index =
    clib_bitmap_set (lm->enabled_by_sw_if_index, sw_if_index, enable);

  return 0;
}

int
vnet_l2gw_trigger_svlan_range (u32 sw_if_index, u16 svlan_lo, u16 svlan_hi,
			       u8 is_add)
{
  l2gw_main_t *lm = &l2gw_main;

  if (!vnet_sw_interface_is_api_valid (lm->vnet_main, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (svlan_lo == 0 || svlan_hi > 4094 || svlan_lo > svlan_hi)
    return VNET_API_ERROR_INVALID_VALUE;

  vec_validate_init_empty (lm->trigger_svlans, sw_if_index, 0);

  for (u32 v = svlan_lo; v <= svlan_hi; v++)
    lm->trigger_svlans[sw_if_index] =
      clib_bitmap_set (lm->trigger_svlans[sw_if_index], v, is_add != 0);

  return 0;
}

static clib_error_t *
l2gw_init (vlib_main_t *vm)
{
  l2gw_main_t *lm = &l2gw_main;

  lm->vlib_main = vm;
  lm->vnet_main = vnet_get_main ();

  clib_bihash_init_16_8 (&lm->circuit_table, "l2gw circuit table",
			 L2GW_NUM_BUCKETS, L2GW_MEMORY_SIZE);

  lm->counters.name = "l2gw";
  lm->counters.stat_segment_name = "/osvbng/l2gw";

  /* Resolve the punt SHM service next-arc now: vlib_node_add_next must
   * run on the main thread, and the target node (if the punt plugin is
   * loaded) is registered before any VLIB_INIT_FUNCTION. ~0 leaves the
   * trigger snoop disarmed. */
  lm->punt_shm_tx_next_arc = ~0;
  {
    vlib_node_t *target =
      vlib_get_node_by_name (vm, (u8 *) "osvbng-punt-shm-tx");
    if (target)
      lm->punt_shm_tx_next_arc =
	vlib_node_add_next (vm, l2gw_input_node.index, target->index);
  }

  return 0;
}

VLIB_INIT_FUNCTION (l2gw_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0.0",
  .description = "osvbng Layer 2 Wholesale Gateway Plugin",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
