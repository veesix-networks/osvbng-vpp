/* Copyright 2025 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng SRG Plugin - API message handlers
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <osvbng_srg/osvbng_srg.h>
#include <osvbng_srg/osvbng_srg_garp.h>

#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <osvbng_srg/osvbng_srg.api_enum.h>
#include <osvbng_srg/osvbng_srg.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_osvbng_srg_add_del_t_handler (vl_api_osvbng_srg_add_del_t *mp)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vl_api_osvbng_srg_add_del_reply_t *rmp;
  int rv = 0;
  u32 count = ntohl (mp->sw_if_count);
  u8 name[64];
  mac_address_t mac;

  /* Null-terminate the API string */
  clib_memset (name, 0, sizeof (name));
  u32 name_len = clib_min (mp->srg_name.length, 63);
  clib_memcpy (name, mp->srg_name.buf, name_len);

  mac_address_decode (mp->virtual_mac, &mac);

  u32 *sw_ifs = 0;
  for (u32 i = 0; i < count; i++)
    vec_add1 (sw_ifs, ntohl (mp->sw_if_indices[i]));

  rv = osvbng_srg_add_del (name, &mac, sw_ifs, count, mp->is_add);

  vec_free (sw_ifs);

  REPLY_MACRO (VL_API_OSVBNG_SRG_ADD_DEL_REPLY);
}

static void
vl_api_osvbng_srg_set_state_t_handler (vl_api_osvbng_srg_set_state_t *mp)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vl_api_osvbng_srg_set_state_reply_t *rmp;
  int rv = 0;
  u8 name[64];

  clib_memset (name, 0, sizeof (name));
  u32 name_len = clib_min (mp->srg_name.length, 63);
  clib_memcpy (name, mp->srg_name.buf, name_len);

  rv = osvbng_srg_set_state (name, mp->is_active);

  REPLY_MACRO (VL_API_OSVBNG_SRG_SET_STATE_REPLY);
}

static void
vl_api_osvbng_srg_send_garp_t_handler (vl_api_osvbng_srg_send_garp_t *mp)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vl_api_osvbng_srg_send_garp_reply_t *rmp;
  int rv = 0;
  u8 name[64];
  u32 count = ntohl (mp->count);

  clib_memset (name, 0, sizeof (name));
  u32 name_len = clib_min (mp->srg_name.length, 63);
  clib_memcpy (name, mp->srg_name.buf, name_len);

  /* Look up SRG to get virtual MAC */
  uword *p = hash_get_mem (sm->srg_by_name, name);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto reply;
    }

  u32 srg_index = p[0];
  osvbng_srg_t *srg = pool_elt_at_index (sm->srgs, srg_index);

  /* Decode entries */
  u32 *sw_ifs = 0;
  ip46_address_t *addrs = 0;
  u8 *af = 0;

  for (u32 i = 0; i < count; i++)
    {
      vl_api_osvbng_srg_garp_entry_t *e = &mp->entries[i];
      ip_address_t decoded;

      vec_add1 (sw_ifs, ntohl (e->sw_if_index));
      ip_address_decode (&e->ip_address, &decoded);

      ip46_address_t a;
      clib_memset (&a, 0, sizeof (a));
      if (ip_addr_version (&decoded) == AF_IP6)
	{
	  a.ip6 = decoded.ip.ip6;
	  vec_add1 (af, 1);
	}
      else
	{
	  a.ip4 = decoded.ip.ip4;
	  vec_add1 (af, 0);
	}
      vec_add1 (addrs, a);
    }

  rv = osvbng_srg_send_garp_batch (sm->vlib_main, name, sw_ifs, addrs, af,
				   count, &srg->virtual_mac);

  vec_free (sw_ifs);
  vec_free (addrs);
  vec_free (af);

reply:
  REPLY_MACRO (VL_API_OSVBNG_SRG_SEND_GARP_REPLY);
}

static void
send_srg_counter_details (osvbng_srg_t *srg, u32 srg_index,
			  vl_api_registration_t *reg, u32 context)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vl_api_osvbng_srg_counter_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    htons (VL_API_OSVBNG_SRG_COUNTER_DETAILS + sm->msg_id_base);
  rmp->context = context;

  /* Copy name into length-prefixed string */
  u32 slen = strlen ((char *) srg->srg_name);
  rmp->counters.srg_name.length = htonl (slen);
  clib_memcpy (rmp->counters.srg_name.buf, srg->srg_name, slen);

  rmp->counters.garp_sent = clib_host_to_net_u64 (sm->garp_sent[srg_index]);
  rmp->counters.na_sent = clib_host_to_net_u64 (sm->na_sent[srg_index]);
  rmp->counters.mac_adds = clib_host_to_net_u64 (sm->mac_adds[srg_index]);
  rmp->counters.mac_removes =
    clib_host_to_net_u64 (sm->mac_removes[srg_index]);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_osvbng_srg_counter_dump_t_handler (
  vl_api_osvbng_srg_counter_dump_t *mp)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vl_api_registration_t *reg;
  u8 name[64];

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  clib_memset (name, 0, sizeof (name));
  u32 name_len = clib_min (mp->srg_name.length, 63);
  clib_memcpy (name, mp->srg_name.buf, name_len);

  if (name[0] != 0)
    {
      uword *p = hash_get_mem (sm->srg_by_name, name);
      if (p)
	{
	  u32 idx = p[0];
	  osvbng_srg_t *srg = pool_elt_at_index (sm->srgs, idx);
	  send_srg_counter_details (srg, idx, reg, mp->context);
	}
    }
  else
    {
      osvbng_srg_t *srg;
      pool_foreach (srg, sm->srgs)
	{
	  u32 idx = srg - sm->srgs;
	  send_srg_counter_details (srg, idx, reg, mp->context);
	}
    }
}

#include <osvbng_srg/osvbng_srg.api.c>

static clib_error_t *
osvbng_srg_api_init (vlib_main_t *vm)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;

  sm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_srg_api_init) = {
  .runs_after = VLIB_INITS ("osvbng_srg_init"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
