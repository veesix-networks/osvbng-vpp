/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - API message handlers
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/fib/fib_table.h>

#include <osvbng_cgnat/osvbng_cgnat.h>

#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>

#include <osvbng_cgnat/osvbng_cgnat.api_enum.h>
#include <osvbng_cgnat/osvbng_cgnat.api_types.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_osvbng_cgnat_pool_add_del_t_handler (
  vl_api_osvbng_cgnat_pool_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_pool_add_del_reply_t *rmp;
  int rv = 0;

  cgnat_pool_t cfg;
  clib_memset (&cfg, 0, sizeof (cfg));

  cfg.pool_id = ntohl (mp->pool_id);
  cfg.mode = mp->mode;
  cfg.address_pooling = mp->address_pooling;
  cfg.filtering = mp->filtering;
  cfg.block_size = ntohs (mp->block_size);
  cfg.max_blocks_per_sub = mp->max_blocks_per_sub;
  cfg.max_sessions_per_sub = ntohl (mp->max_sessions_per_sub);
  cfg.port_range_start = ntohs (mp->port_range_start);
  cfg.port_range_end = ntohs (mp->port_range_end);
  cfg.port_reuse_timeout = ntohs (mp->port_reuse_timeout);
  cfg.alg_bitmask = mp->alg_bitmask;

  cfg.timeouts[CGNAT_PROTO_TCP] = ntohl (mp->timeouts.tcp_established);
  cfg.timeouts[CGNAT_PROTO_UDP] = ntohl (mp->timeouts.udp);
  cfg.timeouts[CGNAT_PROTO_ICMP] = ntohl (mp->timeouts.icmp);

  if (cfg.port_range_start == 0)
    cfg.port_range_start = 1024;
  if (cfg.port_range_end == 0)
    cfg.port_range_end = 65535;
  if (cfg.max_sessions_per_sub == 0)
    cfg.max_sessions_per_sub = 2000;
  if (cfg.timeouts[CGNAT_PROTO_TCP] == 0)
    cfg.timeouts[CGNAT_PROTO_TCP] = 7200;
  if (cfg.timeouts[CGNAT_PROTO_UDP] == 0)
    cfg.timeouts[CGNAT_PROTO_UDP] = 300;
  if (cfg.timeouts[CGNAT_PROTO_ICMP] == 0)
    cfg.timeouts[CGNAT_PROTO_ICMP] = 60;

  rv = cgnat_pool_add_del (&cfg, mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_POOL_ADD_DEL_REPLY);
}

static void
vl_api_osvbng_cgnat_pool_add_del_inside_prefix_t_handler (
  vl_api_osvbng_cgnat_pool_add_del_inside_prefix_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_pool_add_del_inside_prefix_reply_t *rmp;
  int rv = 0;

  u32 pool_id = ntohl (mp->pool_id);
  uword *p = hash_get (cm->pool_by_id, pool_id);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto reply;
    }

  u32 pool_index = p[0];
  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, pool_index);

  ip4_address_t base;
  ip4_address_decode (mp->prefix.address.un.ip4, &base);
  u8 len = mp->prefix.len;
  u32 vrf_id = ntohl (mp->vrf_id);

  if (mp->is_add && pool->mode == CGNAT_POOL_MODE_DETERMINISTIC)
    {
      cgnat_det_params_t dp;
      clib_memset (&dp, 0, sizeof (dp));
      dp.inside_base.as_u32 = base.as_u32;
      dp.inside_count = 1 << (32 - len);
      dp.port_range_start = pool->port_range_start;
      dp.port_range_end = pool->port_range_end;

      vec_add1 (pool->det_params, dp);
      pool->n_det_params = vec_len (pool->det_params);
    }

  vlib_log_notice (cm->log_class, "pool %u inside prefix %U/%u vrf %u %s",
		   pool_id, format_ip4_address, &base, len, vrf_id,
		   mp->is_add ? "added" : "removed");

reply:
  REPLY_MACRO (VL_API_OSVBNG_CGNAT_POOL_ADD_DEL_INSIDE_PREFIX_REPLY);
}

static void
vl_api_osvbng_cgnat_pool_add_del_outside_address_t_handler (
  vl_api_osvbng_cgnat_pool_add_del_outside_address_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_pool_add_del_outside_address_reply_t *rmp;
  int rv = 0;

  u32 pool_id = ntohl (mp->pool_id);
  uword *p = hash_get (cm->pool_by_id, pool_id);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto reply;
    }

  u32 pool_index = p[0];
  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, pool_index);

  ip4_address_t base;
  ip4_address_decode (mp->prefix.address.un.ip4, &base);
  u8 len = mp->prefix.len;

  if (mp->is_add && pool->mode == CGNAT_POOL_MODE_DETERMINISTIC &&
      pool->n_det_params > 0)
    {
      cgnat_det_params_t *dp = &pool->det_params[pool->n_det_params - 1];
      dp->outside_base.as_u32 = base.as_u32;
      dp->outside_count = 1 << (32 - len);
      dp->sharing_ratio = dp->inside_count / dp->outside_count;
      if (dp->sharing_ratio == 0)
	dp->sharing_ratio = 1;
      u32 usable_ports = dp->port_range_end - dp->port_range_start + 1;
      dp->ports_per_host = usable_ports / dp->sharing_ratio;
    }

  vlib_log_notice (cm->log_class, "pool %u outside address %U/%u %s",
		   pool_id, format_ip4_address, &base, len,
		   mp->is_add ? "added" : "removed");

reply:
  REPLY_MACRO (VL_API_OSVBNG_CGNAT_POOL_ADD_DEL_OUTSIDE_ADDRESS_REPLY);
}

static void
vl_api_osvbng_cgnat_set_outside_fib_t_handler (
  vl_api_osvbng_cgnat_set_outside_fib_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_set_outside_fib_reply_t *rmp;
  int rv = 0;

  rv = cgnat_set_outside_fib (ntohl (mp->pool_id), ntohl (mp->fib_index));

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_SET_OUTSIDE_FIB_REPLY);
}

static void
vl_api_osvbng_cgnat_add_del_subscriber_mapping_t_handler (
  vl_api_osvbng_cgnat_add_del_subscriber_mapping_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_add_del_subscriber_mapping_reply_t *rmp;
  int rv = 0;

  ip4_address_t inside_ip, outside_ip;
  ip4_address_decode (mp->inside_ip, &inside_ip);
  ip4_address_decode (mp->outside_ip, &outside_ip);

  rv = cgnat_add_del_subscriber_mapping (
    ntohl (mp->pool_id), ntohl (mp->sw_if_index), &inside_ip,
    ntohl (mp->inside_vrf_id), &outside_ip, ntohs (mp->port_block_start),
    ntohs (mp->port_block_end), mp->enable_feature, mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_ADD_DEL_SUBSCRIBER_MAPPING_REPLY);
}

static void
vl_api_osvbng_cgnat_add_subscriber_mapping_bulk_t_handler (
  vl_api_osvbng_cgnat_add_subscriber_mapping_bulk_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_add_subscriber_mapping_bulk_reply_t *rmp;
  int rv = 0;
  u32 count = ntohl (mp->count);
  u32 pool_id = ntohl (mp->pool_id);

  for (u32 i = 0; i < count; i++)
    {
      vl_api_osvbng_cgnat_bulk_mapping_entry_t *e = &mp->mappings[i];
      ip4_address_t inside_ip, outside_ip;
      ip4_address_decode (e->inside_ip, &inside_ip);
      ip4_address_decode (e->outside_ip, &outside_ip);

      int rc = cgnat_add_del_subscriber_mapping (
	pool_id, ntohl (e->sw_if_index), &inside_ip, ntohl (e->inside_vrf_id),
	&outside_ip, ntohs (e->port_block_start), ntohs (e->port_block_end),
	e->enable_feature, 1);

      if (rc != 0 && rv == 0)
	rv = rc;
    }

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_ADD_SUBSCRIBER_MAPPING_BULK_REPLY);
}

static void
vl_api_osvbng_cgnat_enable_on_session_t_handler (
  vl_api_osvbng_cgnat_enable_on_session_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_enable_on_session_reply_t *rmp;
  int rv = 0;

  rv = cgnat_enable_on_session (ntohl (mp->pool_id),
				ntohl (mp->sw_if_index), mp->is_enable);

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_ENABLE_ON_SESSION_REPLY);
}

static void
vl_api_osvbng_cgnat_set_outside_interface_t_handler (
  vl_api_osvbng_cgnat_set_outside_interface_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_set_outside_interface_reply_t *rmp;
  int rv = 0;

  rv = cgnat_set_outside_interface (ntohl (mp->sw_if_index),
				    ntohl (mp->pool_id), mp->is_enable);

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_SET_OUTSIDE_INTERFACE_REPLY);
}

static void
vl_api_osvbng_cgnat_add_del_bypass_t_handler (
  vl_api_osvbng_cgnat_add_del_bypass_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_add_del_bypass_reply_t *rmp;
  int rv = 0;

  ip4_address_t ip;
  ip4_address_decode (mp->inside_ip, &ip);

  rv = cgnat_add_del_bypass (&ip, ntohl (mp->inside_vrf_id), mp->is_add);

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_ADD_DEL_BYPASS_REPLY);
}

static void
vl_api_osvbng_cgnat_pool_update_t_handler (
  vl_api_osvbng_cgnat_pool_update_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_pool_update_reply_t *rmp;
  int rv = 0;

  u32 timeouts[CGNAT_N_PROTOS];
  timeouts[CGNAT_PROTO_TCP] = ntohl (mp->timeouts.tcp_established);
  timeouts[CGNAT_PROTO_UDP] = ntohl (mp->timeouts.udp);
  timeouts[CGNAT_PROTO_ICMP] = ntohl (mp->timeouts.icmp);
  timeouts[CGNAT_PROTO_OTHER] = ntohl (mp->timeouts.udp);

  rv = cgnat_pool_update (ntohl (mp->pool_id),
			  ntohl (mp->max_sessions_per_sub), mp->alg_bitmask,
			  timeouts);

  REPLY_MACRO (VL_API_OSVBNG_CGNAT_POOL_UPDATE_REPLY);
}

static void
send_subscriber_mapping_details (cgnat_mapping_t *m, u32 pool_id,
				 vl_api_registration_t *reg, u32 context)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_osvbng_cgnat_subscriber_mapping_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    htons (VL_API_OSVBNG_CGNAT_SUBSCRIBER_MAPPING_DETAILS + cm->msg_id_base);
  rmp->context = context;
  rmp->pool_id = htonl (pool_id);
  rmp->sw_if_index = htonl (m->sw_if_index);
  ip4_address_encode (&m->inside_ip, rmp->inside_ip);
  rmp->inside_vrf_id = htonl (m->inside_vrf_id);
  ip4_address_encode (&m->outside_ip, rmp->outside_ip);
  rmp->port_block_start = htons (m->port_block_start);
  rmp->port_block_end = htons (m->port_block_end);
  rmp->active_sessions = htonl (m->session_count);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_osvbng_cgnat_subscriber_mapping_dump_t_handler (
  vl_api_osvbng_cgnat_subscriber_mapping_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 filter_pool_id = ntohl (mp->pool_id);
  cgnat_mapping_t *m;

  pool_foreach (m, cm->mappings)
    {
      cgnat_pool_t *pool = pool_elt_at_index (cm->pools, m->pool_index);
      if (filter_pool_id == ~0 || pool->pool_id == filter_pool_id)
	send_subscriber_mapping_details (m, pool->pool_id, reg, mp->context);
    }
}

#include <osvbng_cgnat/osvbng_cgnat.api.c>

static clib_error_t *
osvbng_cgnat_api_init (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;

  cm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_cgnat_api_init) = {
  .runs_after = VLIB_INITS ("osvbng_cgnat_init"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
