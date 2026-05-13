/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Copyright (c) 2025 veesix ::networks
 *
 * Based on VPP pppoe plugin, modified for explicit control plane programming
 * and Q-in-Q VLAN support.
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <osvbng_pppoe/osvbng_pppoe.h>

#include <vnet/format_fns.h>
#include <osvbng_pppoe/osvbng_pppoe.api_enum.h>
#include <osvbng_pppoe/osvbng_pppoe.api_types.h>

#define REPLY_MSG_ID_BASE pem->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void vl_api_osvbng_pppoe_add_del_session_t_handler
  (vl_api_osvbng_pppoe_add_del_session_t * mp)
{
  vl_api_osvbng_pppoe_add_del_session_reply_t *rmp;
  int rv = 0;
  u32 decap_fib_index;
  ip4_main_t *im = &ip4_main;
  osvbng_pppoe_main_t *pem = &osvbng_pppoe_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->decap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_INNER_FIB;
      goto out;
    }
  decap_fib_index = p[0];

  vnet_osvbng_pppoe_add_del_session_args_t a = {
    .is_add = mp->is_add,
    .decap_fib_index = decap_fib_index,
    .session_id = ntohs (mp->session_id),
    .encap_if_index = ntohl (mp->encap_if_index),
    .outer_vlan = ntohs (mp->outer_vlan),
    .inner_vlan = ntohs (mp->inner_vlan),
  };
  ip_address_decode (&mp->client_ip, &a.client_ip);
  clib_memcpy (a.client_mac, mp->client_mac, 6);
  clib_memcpy (a.local_mac, mp->local_mac, 6);

  u32 sw_if_index = ~0;
  rv = vnet_osvbng_pppoe_add_del_session (&a, &sw_if_index);

out:
  REPLY_MACRO2(VL_API_OSVBNG_PPPOE_ADD_DEL_SESSION_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void vl_api_osvbng_pppoe_set_lac_tunnel_t_handler
  (vl_api_osvbng_pppoe_set_lac_tunnel_t * mp)
{
  vl_api_osvbng_pppoe_set_lac_tunnel_reply_t *rmp;
  osvbng_pppoe_main_t *pem = &osvbng_pppoe_main;
  int rv;

  rv = osvbng_pppoe_set_lac_tunnel (ntohl (mp->sw_if_index),
                                    mp->is_lac_tunneled ? 1 : 0,
                                    ntohl (mp->lac_l2tp_session_index));
  if (rv != 0)
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;

  REPLY_MACRO (VL_API_OSVBNG_PPPOE_SET_LAC_TUNNEL_REPLY);
}

static void send_osvbng_pppoe_session_details
  (osvbng_pppoe_session_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_osvbng_pppoe_session_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  osvbng_pppoe_main_t *pem = &osvbng_pppoe_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->client_ip);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_OSVBNG_PPPOE_SESSION_DETAILS + pem->msg_id_base);
  ip_address_encode (&t->client_ip, is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
                     &rmp->client_ip);

  if (is_ipv6)
    {
      rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id);
    }
  else
    {
      rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id);
    }
  rmp->session_id = htons (t->session_id);
  rmp->encap_if_index = htonl (t->encap_if_index);
  clib_memcpy (rmp->local_mac, t->local_mac, 6);
  clib_memcpy (rmp->client_mac, t->client_mac, 6);
  rmp->outer_vlan = htons (t->outer_vlan);
  rmp->inner_vlan = htons (t->inner_vlan);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_osvbng_pppoe_session_dump_t_handler (vl_api_osvbng_pppoe_session_dump_t * mp)
{
  vl_api_registration_t *reg;
  osvbng_pppoe_main_t *pem = &osvbng_pppoe_main;
  osvbng_pppoe_session_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      pool_foreach (t, pem->sessions)
       {
        send_osvbng_pppoe_session_details(t, reg, mp->context);
      }
    }
  else
    {
      if ((sw_if_index >= vec_len (pem->session_index_by_sw_if_index)) ||
          (~0 == pem->session_index_by_sw_if_index[sw_if_index]))
        {
          return;
        }
      t = &pem->sessions[pem->session_index_by_sw_if_index[sw_if_index]];
      send_osvbng_pppoe_session_details (t, reg, mp->context);
    }
}

#include <osvbng_pppoe/osvbng_pppoe.api.c>
static clib_error_t *
osvbng_pppoe_api_hookup (vlib_main_t * vm)
{
  osvbng_pppoe_main_t *pem = &osvbng_pppoe_main;

  pem->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (osvbng_pppoe_api_hookup);
