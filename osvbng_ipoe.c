/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 veesix ::networks
 *
 * osvbng IPoE Plugin - Main implementation
 * Per-subscriber virtual interfaces for IPoE subscribers.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_source.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj.h>

#include <osvbng_ipoe/osvbng_ipoe.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

ipoe_main_t ipoe_main;

/* FIB source for IPoE subscriber routes */
static fib_source_t ipoe_fib_src;

char *ipoe_error_strings[] = {
#define ipoe_error(n,s) s,
#include <osvbng_ipoe/osvbng_ipoe_error.def>
#undef ipoe_error
};

/*
 * Device class for ipoe_session interfaces
 */
static u8 *
format_ipoe_session_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ipoe_session%d", dev_instance);
}

static clib_error_t *
ipoe_interface_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

VNET_DEVICE_CLASS (ipoe_device_class) = {
  .name = "IPoE",
  .format_device_name = format_ipoe_session_name,
  .admin_up_down_function = ipoe_interface_admin_up_down,
};

/*
 * Build L2 rewrite header for TX path
 *
 * Creates: [Dst MAC][Src MAC][S-VLAN?][C-VLAN?][Ethertype]
 */
static u8 *
ipoe_build_rewrite (vnet_main_t *vnm, u32 sw_if_index, vnet_link_t link_type,
                    const void *dst_address)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *s;
  u8 *rw = 0;
  int len;
  u32 session_index;

  /* Safety check: verify sw_if_index is valid */
  if (sw_if_index >= vec_len (im->session_index_by_sw_if_index))
    return NULL;

  session_index = im->session_index_by_sw_if_index[sw_if_index];
  if (session_index == ~0)
    return NULL;

  s = pool_elt_at_index (im->sessions, session_index);

  /* Calculate rewrite length */
  len = sizeof (ethernet_header_t);
  if (s->outer_vlan && s->inner_vlan)
    len += 2 * sizeof (ethernet_vlan_header_t); /* Q-in-Q */
  else if (s->outer_vlan || s->inner_vlan)
    len += sizeof (ethernet_vlan_header_t);     /* Single tag */

  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ethernet_header_t *eth = (ethernet_header_t *) rw;
  clib_memcpy_fast (eth->dst_address, s->client_mac, 6);
  clib_memcpy_fast (eth->src_address, s->local_mac, 6);

  u8 *p = rw + sizeof (ethernet_header_t);

  if (s->outer_vlan && s->inner_vlan)
    {
      /* Q-in-Q: 802.1ad S-VLAN + 802.1Q C-VLAN */
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD);

      ethernet_vlan_header_t *svlan = (ethernet_vlan_header_t *) p;
      svlan->priority_cfi_and_id =
        clib_host_to_net_u16 (s->outer_vlan & 0xFFF);
      svlan->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      p += sizeof (ethernet_vlan_header_t);

      ethernet_vlan_header_t *cvlan = (ethernet_vlan_header_t *) p;
      cvlan->priority_cfi_and_id =
        clib_host_to_net_u16 (s->inner_vlan & 0xFFF);
      cvlan->type = clib_host_to_net_u16 (
        link_type == VNET_LINK_IP4 ? ETHERNET_TYPE_IP4 : ETHERNET_TYPE_IP6);
    }
  else if (s->outer_vlan)
    {
      /* Single S-VLAN */
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD);

      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) p;
      vlan->priority_cfi_and_id =
        clib_host_to_net_u16 (s->outer_vlan & 0xFFF);
      vlan->type = clib_host_to_net_u16 (
        link_type == VNET_LINK_IP4 ? ETHERNET_TYPE_IP4 : ETHERNET_TYPE_IP6);
    }
  else if (s->inner_vlan)
    {
      /* Single C-VLAN (unusual but supported) */
      eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);

      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) p;
      vlan->priority_cfi_and_id =
        clib_host_to_net_u16 (s->inner_vlan & 0xFFF);
      vlan->type = clib_host_to_net_u16 (
        link_type == VNET_LINK_IP4 ? ETHERNET_TYPE_IP4 : ETHERNET_TYPE_IP6);
    }
  else
    {
      /* Untagged */
      eth->type = clib_host_to_net_u16 (
        link_type == VNET_LINK_IP4 ? ETHERNET_TYPE_IP4 : ETHERNET_TYPE_IP6);
    }

  return rw;
}

/*
 * Update adjacency - create midchain that stacks to encap interface
 */
static void
ipoe_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *s;
  u32 session_index;
  dpo_id_t dpo = DPO_INVALID;
  ip_adjacency_t *adj;

  /* Safety check: verify sw_if_index is valid */
  if (sw_if_index >= vec_len (im->session_index_by_sw_if_index))
    return;

  session_index = im->session_index_by_sw_if_index[sw_if_index];
  if (session_index == ~0)
    return;

  adj = adj_get (ai);
  s = pool_elt_at_index (im->sessions, session_index);

  /* Update midchain rewrite - no fixup needed for IPoE (unlike PPPoE) */
  adj_nbr_midchain_update_rewrite (
    ai, NULL, NULL, /* No fixup function needed */
    ADJ_FLAG_NONE,
    ipoe_build_rewrite (vnm, sw_if_index, adj->ia_link, NULL));

  /* Stack to encap interface */
  interface_tx_dpo_add_or_lock (vnet_link_to_dpo_proto (adj->ia_link),
                                s->encap_if_index, &dpo);

  adj_nbr_midchain_stack (ai, &dpo);
  dpo_reset (&dpo);
}

VNET_HW_INTERFACE_CLASS (ipoe_hw_class) = {
  .name = "IPoE",
  .build_rewrite = ipoe_build_rewrite,
  .update_adjacency = ipoe_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

/*
 * Create or delete an IPoE session
 */
int
vnet_ipoe_add_del_session (vnet_ipoe_add_del_session_args_t *a,
                           u32 *sw_if_indexp)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *s;
  vnet_main_t *vnm = im->vnet_main;
  u32 hw_if_index, sw_if_index;
  vnet_hw_interface_t *hi;
  ipoe_entry_key_t key;
  ipoe_entry_result_t result;
  clib_bihash_kv_16_8_t kv;

  /* Check if session already exists */
  ipoe_make_key (&key, a->encap_if_index, a->inner_vlan, a->client_mac);
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];

  if (clib_bihash_search_inline_16_8 (&im->session_table, &kv) == 0)
    {
      /* Session exists */
      result.raw = kv.value;
      s = pool_elt_at_index (im->sessions, result.fields.session_index);

      if (a->is_add)
        {
          /* Already exists */
          *sw_if_indexp = s->sw_if_index;
          return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
        }

      /* Delete session */
      *sw_if_indexp = s->sw_if_index;

      vnet_reset_interface_l3_output_node (vnm->vlib_main, s->sw_if_index);

      /* Remove any FIB entries */
      if (s->ipv4_bound)
        vnet_ipoe_set_session_ipv4 (s->sw_if_index, &s->client_ipv4, 0);
      if (s->ipv6_bound)
        vnet_ipoe_set_session_ipv6 (s->sw_if_index, &s->client_ipv6, 0);
      if (s->delegated_prefix_len)
        vnet_ipoe_set_delegated_prefix (s->sw_if_index, &s->delegated_prefix,
                                        s->delegated_prefix_len,
                                        &s->pd_next_hop, 0);

      /* Remove from lookup table */
      ipoe_session_table_del (&im->session_table, a->encap_if_index,
                              a->inner_vlan, a->client_mac);

      /* Clear reverse lookup before deleting the hw interface so any
       * adjacency callback that fires during teardown bails at the
       * early ~0 check. */
      im->session_index_by_sw_if_index[s->sw_if_index] = ~0;

      vnet_sw_interface_set_flags (vnm, s->sw_if_index, 0 /* down */);
      vnet_delete_hw_interface (vnm, s->hw_if_index);

      pool_put (im->sessions, s);

      return 0;
    }

  /* Session doesn't exist */
  if (!a->is_add)
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  /* Create new session */
  pool_get_aligned (im->sessions, s, CLIB_CACHE_LINE_BYTES);
  clib_memset (s, 0, sizeof (*s));

  s->encap_if_index = a->encap_if_index;
  clib_memcpy_fast (s->client_mac, a->client_mac, 6);
  clib_memcpy_fast (s->local_mac, a->local_mac, 6);
  s->outer_vlan = a->outer_vlan;
  s->inner_vlan = a->inner_vlan;
  s->decap_fib_index = a->decap_fib_index;

  hw_if_index = vnet_register_interface (
    vnm, ipoe_device_class.index, s - im->sessions,
    ipoe_hw_class.index, s - im->sessions);

  hi = vnet_get_hw_interface (vnm, hw_if_index);

  s->hw_if_index = hw_if_index;
  s->sw_if_index = sw_if_index = hi->sw_if_index;

  vnet_hw_interface_set_flags (vnm, hw_if_index,
                               VNET_HW_INTERFACE_FLAG_LINK_UP);
  vnet_sw_interface_set_flags (vnm, sw_if_index,
                               VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  vnet_set_interface_l3_output_node (vnm->vlib_main, sw_if_index,
                                     (u8 *) "tunnel-output");

  vec_validate_init_empty (im->session_index_by_sw_if_index, sw_if_index, ~0);
  im->session_index_by_sw_if_index[sw_if_index] = s - im->sessions;

  {
    u32 table_id = 0;
    if (s->decap_fib_index != 0)
      table_id =
        fib_table_get_table_id (s->decap_fib_index, FIB_PROTOCOL_IP4);

    ip_table_bind (FIB_PROTOCOL_IP4, sw_if_index, table_id);
    ip_table_bind (FIB_PROTOCOL_IP6, sw_if_index, table_id);
    s->decap_fib_index_ip6 = fib_table_find (FIB_PROTOCOL_IP6, table_id);
  }

  /* Add to lookup table */
  result.fields.sw_if_index = sw_if_index;
  result.fields.session_index = s - im->sessions;
  ipoe_session_table_add (&im->session_table, a->encap_if_index, a->inner_vlan,
                          a->client_mac, &result);

  *sw_if_indexp = sw_if_index;

  return 0;
}

/*
 * Set/clear IPv4 binding
 */
int
vnet_ipoe_set_session_ipv4 (u32 sw_if_index, ip4_address_t *addr, u8 is_add)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *s;
  u32 session_index;
  fib_prefix_t pfx;

  if (sw_if_index >= vec_len (im->session_index_by_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  session_index = im->session_index_by_sw_if_index[sw_if_index];
  if (session_index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  s = pool_elt_at_index (im->sessions, session_index);

  clib_memset (&pfx, 0, sizeof (pfx));
  pfx.fp_proto = FIB_PROTOCOL_IP4;
  pfx.fp_len = 32;
  pfx.fp_addr.ip4 = *addr;

  if (is_add)
    {
      if (s->ipv4_bound &&
          !clib_memcmp (&s->client_ipv4, addr, sizeof (ip4_address_t)))
        return 0;

      if (s->ipv4_bound)
        vnet_ipoe_set_session_ipv4 (sw_if_index, &s->client_ipv4, 0);

      fib_table_entry_path_add (
        s->decap_fib_index, &pfx, ipoe_fib_src, FIB_ENTRY_FLAG_NONE,
        DPO_PROTO_IP4, NULL, sw_if_index, ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

      s->client_ipv4 = *addr;
      s->ipv4_bound = 1;
    }
  else
    {
      if (!s->ipv4_bound)
        return 0;

      fib_table_entry_path_remove (
        s->decap_fib_index, &pfx, ipoe_fib_src, DPO_PROTO_IP4, NULL,
        sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

      clib_memset (&s->client_ipv4, 0, sizeof (s->client_ipv4));
      s->ipv4_bound = 0;
    }

  return 0;
}

/*
 * Set/clear IPv6 binding
 */
int
vnet_ipoe_set_session_ipv6 (u32 sw_if_index, ip6_address_t *addr, u8 is_add)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *s;
  u32 session_index;
  fib_prefix_t pfx;

  if (sw_if_index >= vec_len (im->session_index_by_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  session_index = im->session_index_by_sw_if_index[sw_if_index];
  if (session_index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  s = pool_elt_at_index (im->sessions, session_index);

  clib_memset (&pfx, 0, sizeof (pfx));
  pfx.fp_proto = FIB_PROTOCOL_IP6;
  pfx.fp_len = 128;
  pfx.fp_addr.ip6 = *addr;

  if (is_add)
    {
      if (s->ipv6_bound &&
          !clib_memcmp (&s->client_ipv6, addr, sizeof (ip6_address_t)))
        return 0;

      if (s->ipv6_bound)
        vnet_ipoe_set_session_ipv6 (sw_if_index, &s->client_ipv6, 0);

      fib_table_entry_path_add (
        s->decap_fib_index_ip6, &pfx, ipoe_fib_src, FIB_ENTRY_FLAG_NONE,
        DPO_PROTO_IP6, NULL, sw_if_index, ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

      s->client_ipv6 = *addr;
      s->ipv6_bound = 1;
    }
  else
    {
      if (!s->ipv6_bound)
        return 0;

      fib_table_entry_path_remove (
        s->decap_fib_index_ip6, &pfx, ipoe_fib_src, DPO_PROTO_IP6, NULL,
        sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

      clib_memset (&s->client_ipv6, 0, sizeof (s->client_ipv6));
      s->ipv6_bound = 0;
    }

  return 0;
}

/*
 * Set/clear delegated prefix
 */
int
vnet_ipoe_set_delegated_prefix (u32 sw_if_index, ip6_address_t *prefix,
                                u8 prefix_len, ip6_address_t *next_hop,
                                u8 is_add)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *s;
  u32 session_index;
  fib_prefix_t pfx;

  if (sw_if_index >= vec_len (im->session_index_by_sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  session_index = im->session_index_by_sw_if_index[sw_if_index];
  if (session_index == ~0)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  s = pool_elt_at_index (im->sessions, session_index);

  clib_memset (&pfx, 0, sizeof (pfx));
  pfx.fp_proto = FIB_PROTOCOL_IP6;
  pfx.fp_len = prefix_len;
  pfx.fp_addr.ip6 = *prefix;

  if (is_add)
    {
      if (s->delegated_prefix_len == prefix_len &&
          !clib_memcmp (&s->delegated_prefix, prefix, sizeof (ip6_address_t)))
        return 0;

      if (s->delegated_prefix_len)
        vnet_ipoe_set_delegated_prefix (sw_if_index, &s->delegated_prefix,
                                        s->delegated_prefix_len,
                                        &s->pd_next_hop, 0);

      fib_table_entry_path_add (
        s->decap_fib_index_ip6, &pfx, ipoe_fib_src, FIB_ENTRY_FLAG_NONE,
        DPO_PROTO_IP6, NULL, sw_if_index, ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

      s->delegated_prefix = *prefix;
      s->delegated_prefix_len = prefix_len;
      s->pd_next_hop = *next_hop;
    }
  else
    {
      if (!s->delegated_prefix_len)
        return 0;

      fib_table_entry_path_remove (
        s->decap_fib_index_ip6, &pfx, ipoe_fib_src, DPO_PROTO_IP6, NULL,
        sw_if_index, ~0, 1, FIB_ROUTE_PATH_FLAG_NONE);

      clib_memset (&s->delegated_prefix, 0, sizeof (s->delegated_prefix));
      s->delegated_prefix_len = 0;
      clib_memset (&s->pd_next_hop, 0, sizeof (s->pd_next_hop));
    }

  return 0;
}

int
vnet_ipoe_enable_disable (u32 sw_if_index, u8 enable)
{
  ipoe_main_t *im = &ipoe_main;

  if (!vnet_sw_interface_is_api_valid (im->vnet_main, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (enable && !im->ethertypes_registered)
    {
      ethernet_register_input_type (im->vlib_main, ETHERNET_TYPE_IP4,
				    ipoe_input_node.index);
      ethernet_register_input_type (im->vlib_main, ETHERNET_TYPE_IP6,
				    ipoe_input_node.index);

      im->ethertypes_registered = 1;
    }

  im->enabled_by_sw_if_index =
    clib_bitmap_set (im->enabled_by_sw_if_index, sw_if_index, enable);

  return 0;
}

/*
 * Plugin initialization
 */
static clib_error_t *
ipoe_init (vlib_main_t *vm)
{
  ipoe_main_t *im = &ipoe_main;

  im->vlib_main = vm;
  im->vnet_main = vnet_get_main ();

  /* Initialize session table */
  clib_bihash_init_16_8 (&im->session_table, "ipoe session table",
                         IPOE_NUM_BUCKETS, IPOE_MEMORY_SIZE);

  /* Register FIB source for IPoE subscriber routes */
  ipoe_fib_src = fib_source_allocate ("osvbng-ipoe",
                                      FIB_SOURCE_PRIORITY_HI,
                                      FIB_SOURCE_BH_API);

  return 0;
}

VLIB_INIT_FUNCTION (ipoe_init);

/*
 * Plugin registration
 */
VLIB_PLUGIN_REGISTER () = {
  .version = "1.0.0",
  .description = "osvbng IPoE Plugin",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
