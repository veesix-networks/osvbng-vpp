/* Copyright 2026 The osvbng Authors
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng Tunnel Plugin - API handlers
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <osvbng_tunnel/osvbng_tunnel.h>

#include <vnet/format_fns.h>

#include <osvbng_tunnel/osvbng_tunnel.api_enum.h>
#include <osvbng_tunnel/osvbng_tunnel.api_types.h>

#define REPLY_MSG_ID_BASE tm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_osvbng_tunnel_decap_next_get_t_handler (
  vl_api_osvbng_tunnel_decap_next_get_t *mp)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;
  vl_api_osvbng_tunnel_decap_next_get_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_OSVBNG_TUNNEL_DECAP_NEXT_GET_REPLY, ({
		  rmp->vxlan4_next = htonl (tm->vxlan4_decap_next);
		  rmp->vxlan6_next = htonl (tm->vxlan6_decap_next);
		}));
}

#include <osvbng_tunnel/osvbng_tunnel.api.c>

static clib_error_t *
osvbng_tunnel_api_init (vlib_main_t *vm)
{
  osvbng_tunnel_main_t *tm = &osvbng_tunnel_main;

  tm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_tunnel_api_init) = {
  .runs_after = VLIB_INITS ("osvbng_tunnel_init"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
