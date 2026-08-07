/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng L2GW Plugin - API handlers
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <osvbng_l2gw/osvbng_l2gw.h>

#include <vnet/format_fns.h>

#include <osvbng_l2gw/osvbng_l2gw.api_enum.h>
#include <osvbng_l2gw/osvbng_l2gw.api_types.h>

#define REPLY_MSG_ID_BASE lm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_osvbng_l2gw_enable_disable_t_handler (
  vl_api_osvbng_l2gw_enable_disable_t *mp)
{
  l2gw_main_t *lm = &l2gw_main;
  vl_api_osvbng_l2gw_enable_disable_reply_t *rmp;
  int rv;

  rv = vnet_l2gw_enable_disable (ntohl (mp->sw_if_index), mp->enable);

  REPLY_MACRO (VL_API_OSVBNG_L2GW_ENABLE_DISABLE_REPLY);
}

static void
vl_api_osvbng_l2gw_trigger_svlan_range_t_handler (
  vl_api_osvbng_l2gw_trigger_svlan_range_t *mp)
{
  l2gw_main_t *lm = &l2gw_main;
  vl_api_osvbng_l2gw_trigger_svlan_range_reply_t *rmp;
  int rv;

  rv = vnet_l2gw_trigger_svlan_range (ntohl (mp->sw_if_index),
				      ntohs (mp->svlan_lo),
				      ntohs (mp->svlan_hi), mp->any_protocol,
				      mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_L2GW_TRIGGER_SVLAN_RANGE_REPLY);
}

static void
vl_api_osvbng_l2gw_add_del_circuit_t_handler (
  vl_api_osvbng_l2gw_add_del_circuit_t *mp)
{
  l2gw_main_t *lm = &l2gw_main;
  vl_api_osvbng_l2gw_add_del_circuit_reply_t *rmp;
  int rv;
  u32 circuit_id = ~0;

  vnet_l2gw_add_del_circuit_args_t a = {
    .is_add = mp->is_add,
    .access_sw_if_index = ntohl (mp->access_sw_if_index),
    .access_svlan = ntohs (mp->access_svlan),
    .access_cvlan =
      mp->access_cvlan_any ? L2GW_CVLAN_ANY : ntohs (mp->access_cvlan),
    .access_tpid = ntohs (mp->access_tpid),
    .handoff_sw_if_index = ntohl (mp->handoff_sw_if_index),
    .handoff_svlan = ntohs (mp->handoff_svlan),
    .handoff_cvlan =
      mp->handoff_cvlan_any ? L2GW_CVLAN_ANY : ntohs (mp->handoff_cvlan),
    .handoff_tpid = ntohs (mp->handoff_tpid),
    .transparent = mp->transparent,
    .enabled = mp->enabled,
  };

  rv = vnet_l2gw_add_del_circuit (&a, &circuit_id);

  u32 handoff_entry_index = ~0;
  if (circuit_id != ~0 && !pool_is_free_index (lm->entries, circuit_id))
    handoff_entry_index =
      pool_elt_at_index (lm->entries, circuit_id)->peer_entry_index;

  REPLY_MACRO2 (VL_API_OSVBNG_L2GW_ADD_DEL_CIRCUIT_REPLY, ({
		  rmp->circuit_id = htonl (circuit_id);
		  rmp->handoff_entry_index = htonl (handoff_entry_index);
		}));
}

static void
vl_api_osvbng_l2gw_circuit_set_state_t_handler (
  vl_api_osvbng_l2gw_circuit_set_state_t *mp)
{
  l2gw_main_t *lm = &l2gw_main;
  vl_api_osvbng_l2gw_circuit_set_state_reply_t *rmp;
  int rv;

  rv = vnet_l2gw_circuit_set_state (ntohl (mp->circuit_id), mp->enabled);

  REPLY_MACRO (VL_API_OSVBNG_L2GW_CIRCUIT_SET_STATE_REPLY);
}

static void
send_l2gw_circuit_details (l2gw_entry_t *access_e, vl_api_registration_t *reg,
			   u32 context)
{
  l2gw_main_t *lm = &l2gw_main;
  l2gw_entry_t *handoff_e =
    pool_elt_at_index (lm->entries, access_e->peer_entry_index);
  vl_api_osvbng_l2gw_circuit_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    htons (VL_API_OSVBNG_L2GW_CIRCUIT_DETAILS + lm->msg_id_base);
  rmp->context = context;

  rmp->circuit_id = htonl (access_e->circuit_id);
  rmp->access_entry_index = htonl (access_e->circuit_id);
  rmp->handoff_entry_index = htonl (access_e->peer_entry_index);

  rmp->access_sw_if_index = htonl (access_e->rx_sw_if_index);
  rmp->access_svlan = htons (access_e->rx_svlan);
  rmp->access_cvlan_any = access_e->rx_cvlan == L2GW_CVLAN_ANY;
  rmp->access_cvlan =
    rmp->access_cvlan_any ? 0 : htons (access_e->rx_cvlan);
  rmp->access_tpid = htons (handoff_e->tx_outer_tpid);

  rmp->handoff_sw_if_index = htonl (handoff_e->rx_sw_if_index);
  rmp->handoff_svlan = htons (handoff_e->rx_svlan);
  rmp->handoff_cvlan_any = handoff_e->rx_cvlan == L2GW_CVLAN_ANY;
  rmp->handoff_cvlan =
    rmp->handoff_cvlan_any ? 0 : htons (handoff_e->rx_cvlan);
  rmp->handoff_tpid = htons (access_e->tx_outer_tpid);

  rmp->transparent = !!(access_e->flags & L2GW_ENTRY_F_TRANSPARENT);
  rmp->enabled = !!(access_e->flags & L2GW_ENTRY_F_ENABLED);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_osvbng_l2gw_circuit_dump_t_handler (
  vl_api_osvbng_l2gw_circuit_dump_t *mp)
{
  l2gw_main_t *lm = &l2gw_main;
  vl_api_registration_t *reg;
  l2gw_entry_t *e;
  u32 circuit_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  circuit_id = ntohl (mp->circuit_id);

  if (circuit_id == ~0)
    {
      pool_foreach (e, lm->entries)
	{
	  if (e->flags & L2GW_ENTRY_F_ACCESS_SIDE)
	    send_l2gw_circuit_details (e, reg, mp->context);
	}
    }
  else if (!pool_is_free_index (lm->entries, circuit_id))
    {
      e = pool_elt_at_index (lm->entries, circuit_id);
      if (e->flags & L2GW_ENTRY_F_ACCESS_SIDE)
	send_l2gw_circuit_details (e, reg, mp->context);
    }
}

#include <osvbng_l2gw/osvbng_l2gw.api.c>

static clib_error_t *
l2gw_api_init (vlib_main_t *vm)
{
  l2gw_main_t *lm = &l2gw_main;

  lm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (l2gw_api_init) = {
  .runs_after = VLIB_INITS ("l2gw_init"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
