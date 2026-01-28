/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 veesix ::networks
 *
 * osvbng IPoE Plugin - API handlers
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <osvbng_ipoe/osvbng_ipoe.h>

#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <osvbng_ipoe/osvbng_ipoe.api_enum.h>
#include <osvbng_ipoe/osvbng_ipoe.api_types.h>

#define REPLY_MSG_ID_BASE im->msg_id_base
#include <vlibapi/api_helper_macros.h>

/*
 * Add/Delete session handler
 */
static void
vl_api_osvbng_ipoe_add_del_session_t_handler (
  vl_api_osvbng_ipoe_add_del_session_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_osvbng_ipoe_add_del_session_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ~0;

  vnet_ipoe_add_del_session_args_t a = {
    .is_add = mp->is_add,
    .encap_if_index = ntohl (mp->encap_if_index),
    .outer_vlan = ntohs (mp->outer_vlan),
    .inner_vlan = ntohs (mp->inner_vlan),
    .decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4,
                                       ntohl (mp->decap_vrf_id)),
  };

  mac_address_decode (mp->client_mac, (mac_address_t *) a.client_mac);
  mac_address_decode (mp->local_mac, (mac_address_t *) a.local_mac);

  rv = vnet_ipoe_add_del_session (&a, &sw_if_index);

  REPLY_MACRO2 (VL_API_OSVBNG_IPOE_ADD_DEL_SESSION_REPLY,
                ({ rmp->sw_if_index = htonl (sw_if_index); }));
}

/*
 * Set IPv4 binding handler
 */
static void
vl_api_osvbng_ipoe_set_session_ipv4_t_handler (
  vl_api_osvbng_ipoe_set_session_ipv4_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_osvbng_ipoe_set_session_ipv4_reply_t *rmp;
  int rv = 0;

  ip4_address_t addr;
  clib_memcpy (&addr, mp->client_ip, sizeof (addr));

  rv = vnet_ipoe_set_session_ipv4 (ntohl (mp->sw_if_index), &addr, mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_IPOE_SET_SESSION_IPV4_REPLY);
}

/*
 * Set IPv6 binding handler
 */
static void
vl_api_osvbng_ipoe_set_session_ipv6_t_handler (
  vl_api_osvbng_ipoe_set_session_ipv6_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_osvbng_ipoe_set_session_ipv6_reply_t *rmp;
  int rv = 0;

  ip6_address_t addr;
  clib_memcpy (&addr, mp->client_ip, sizeof (addr));

  rv = vnet_ipoe_set_session_ipv6 (ntohl (mp->sw_if_index), &addr, mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_IPOE_SET_SESSION_IPV6_REPLY);
}

/*
 * Set delegated prefix handler
 */
static void
vl_api_osvbng_ipoe_set_delegated_prefix_t_handler (
  vl_api_osvbng_ipoe_set_delegated_prefix_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_osvbng_ipoe_set_delegated_prefix_reply_t *rmp;
  int rv = 0;

  ip6_address_t prefix, next_hop;
  ip_prefix_decode (&mp->prefix, (fib_prefix_t *) &prefix);

  /* Extract prefix address and length */
  fib_prefix_t fib_pfx;
  ip_prefix_decode (&mp->prefix, &fib_pfx);

  clib_memcpy (&next_hop, mp->next_hop, sizeof (next_hop));

  rv = vnet_ipoe_set_delegated_prefix (ntohl (mp->sw_if_index), &fib_pfx.fp_addr.ip6,
                                       fib_pfx.fp_len, &next_hop, mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_IPOE_SET_DELEGATED_PREFIX_REPLY);
}

/*
 * Enable/Disable handler
 */
static void
vl_api_osvbng_ipoe_enable_disable_t_handler (
  vl_api_osvbng_ipoe_enable_disable_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_osvbng_ipoe_enable_disable_reply_t *rmp;
  int rv = 0;

  rv = vnet_ipoe_enable_disable (ntohl (mp->sw_if_index), mp->enable);

  REPLY_MACRO (VL_API_OSVBNG_IPOE_ENABLE_DISABLE_REPLY);
}

/*
 * Session dump - send function
 */
static void
send_ipoe_session_details (ipoe_session_t *s, vl_api_registration_t *reg,
                           u32 context)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_osvbng_ipoe_session_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    htons (VL_API_OSVBNG_IPOE_SESSION_DETAILS + im->msg_id_base);
  rmp->context = context;

  rmp->sw_if_index = htonl (s->sw_if_index);
  rmp->encap_if_index = htonl (s->encap_if_index);
  mac_address_encode ((mac_address_t *) s->client_mac, rmp->client_mac);
  mac_address_encode ((mac_address_t *) s->local_mac, rmp->local_mac);
  rmp->outer_vlan = htons (s->outer_vlan);
  rmp->inner_vlan = htons (s->inner_vlan);

  /* IPv4 binding */
  clib_memcpy (rmp->client_ipv4, &s->client_ipv4, sizeof (s->client_ipv4));
  rmp->ipv4_bound = s->ipv4_bound;

  /* IPv6 binding */
  clib_memcpy (rmp->client_ipv6, &s->client_ipv6, sizeof (s->client_ipv6));
  rmp->ipv6_bound = s->ipv6_bound;

  /* Delegated prefix */
  fib_prefix_t pfx = {
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_len = s->delegated_prefix_len,
    .fp_addr.ip6 = s->delegated_prefix,
  };
  ip_prefix_encode (&pfx, &rmp->delegated_prefix);
  clib_memcpy (rmp->pd_next_hop, &s->pd_next_hop, sizeof (s->pd_next_hop));

  rmp->decap_vrf_id = htonl (
    fib_table_get_table_id (s->decap_fib_index, FIB_PROTOCOL_IP4));

  vl_api_send_msg (reg, (u8 *) rmp);
}

/*
 * Session dump handler
 */
static void
vl_api_osvbng_ipoe_session_dump_t_handler (
  vl_api_osvbng_ipoe_session_dump_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_registration_t *reg;
  ipoe_session_t *s;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (sw_if_index == ~0)
    {
      /* Dump all sessions */
      pool_foreach (s, im->sessions)
        {
          send_ipoe_session_details (s, reg, mp->context);
        }
    }
  else
    {
      /* Dump specific session */
      if (sw_if_index < vec_len (im->session_index_by_sw_if_index))
        {
          u32 session_index = im->session_index_by_sw_if_index[sw_if_index];
          if (session_index != ~0)
            {
              s = pool_elt_at_index (im->sessions, session_index);
              send_ipoe_session_details (s, reg, mp->context);
            }
        }
    }
}

#include <osvbng_ipoe/osvbng_ipoe.api.c>

/*
 * API initialization
 */
static clib_error_t *
ipoe_api_init (vlib_main_t *vm)
{
  ipoe_main_t *im = &ipoe_main;

  im->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (ipoe_api_init) = {
  .runs_after = VLIB_INITS ("ipoe_init"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
