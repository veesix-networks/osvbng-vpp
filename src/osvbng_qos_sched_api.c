/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - API message handlers
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

#include <vnet/format_fns.h>

#include <osvbng_qos_sched/osvbng_qos_sched.api_enum.h>
#include <osvbng_qos_sched/osvbng_qos_sched.api_types.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_osvbng_cake_sched_enable_disable_t_handler (
  vl_api_osvbng_cake_sched_enable_disable_t *mp)
{
  cake_main_t *cm = &cake_main;
  vl_api_osvbng_cake_sched_enable_disable_reply_t *rmp;
  int rv = 0;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u64 rate_bytes_per_sec = clib_net_to_host_u64 (mp->rate_bytes_per_sec);
  u8 tin_mode = (u8) mp->tin_mode;
  i16 overhead_bytes = (i16) ntohs (mp->overhead_bytes);
  u8 atm_mode = (u8) mp->atm_mode;
  u8 mpu = mp->mpu;
  u32 buffer_limit = ntohl (mp->buffer_limit);
  u32 target_us = ntohl (mp->target_us);
  u32 interval_us = ntohl (mp->interval_us);
  u32 flags = ntohl (mp->flags);

  rv = cake_sched_enable_disable (sw_if_index, mp->is_enable,
				  rate_bytes_per_sec, tin_mode,
				  overhead_bytes, atm_mode, mpu, buffer_limit,
				  target_us, interval_us, flags);

  REPLY_MACRO (VL_API_OSVBNG_CAKE_SCHED_ENABLE_DISABLE_REPLY);
}

static void
send_cake_sched_details (cake_sched_t *cs, vl_api_registration_t *reg,
			 u32 context)
{
  cake_main_t *cm = &cake_main;
  vl_api_osvbng_cake_sched_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id =
    ntohs (VL_API_OSVBNG_CAKE_SCHED_DETAILS + cm->msg_id_base);
  rmp->context = context;
  rmp->sw_if_index = ntohl (cs->sw_if_index);
  rmp->rate_bytes_per_sec = clib_host_to_net_u64 (cs->rate_bytes_per_sec);
  rmp->tin_mode = (vl_api_osvbng_cake_tin_mode_t) cs->tin_mode;
  rmp->tin_cnt = cs->tin_cnt;
  rmp->buffer_usage = ntohl (cs->buffer_usage);
  rmp->buffer_limit = ntohl (cs->buffer_limit);

  for (u8 t = 0; t < cs->tin_cnt && t < 8; t++)
    {
      cake_tin_t *tin = &cs->tins[t];
      rmp->tin_packets[t] = clib_host_to_net_u64 (tin->packets);
      rmp->tin_bytes[t] = clib_host_to_net_u64 (tin->bytes);
      rmp->tin_drops[t] = clib_host_to_net_u64 (tin->drops);
      rmp->tin_ecn_marks[t] = clib_host_to_net_u64 (tin->ecn_marks);
      rmp->tin_peak_delay_us[t] = ntohl (tin->peak_queue_delay_us);
      rmp->tin_avg_delay_us[t] = ntohl (tin->avg_queue_delay_us);
      rmp->tin_sparse_flows[t] = ntohl (tin->sparse_flow_count);
      rmp->tin_bulk_flows[t] = ntohl (tin->bulk_flow_count);
    }

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_osvbng_cake_sched_dump_t_handler (
  vl_api_osvbng_cake_sched_dump_t *mp)
{
  cake_main_t *cm = &cake_main;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  u32 filter_sw_if_index = ntohl (mp->sw_if_index);

  for (u32 i = 0; i < vec_len (cm->sched_index_by_sw_if_index); i++)
    {
      u32 packed = cm->sched_index_by_sw_if_index[i];
      if (packed == 0)
	continue;
      if (filter_sw_if_index != ~0 && i != filter_sw_if_index)
	continue;

      u32 owner_thread = packed >> 16;
      u32 pool_index = packed & 0xffff;
      cake_per_thread_t *pt = &cm->per_thread[owner_thread];
      cake_sched_t *cs = pool_elt_at_index (pt->schedulers, pool_index);

      send_cake_sched_details (cs, reg, mp->context);
    }
}

static void
vl_api_osvbng_cake_sched_reset_stats_t_handler (
  vl_api_osvbng_cake_sched_reset_stats_t *mp)
{
  cake_main_t *cm = &cake_main;
  vl_api_osvbng_cake_sched_reset_stats_reply_t *rmp;
  int rv = 0;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  cake_sched_reset_stats (sw_if_index);

  REPLY_MACRO (VL_API_OSVBNG_CAKE_SCHED_RESET_STATS_REPLY);
}

#include <osvbng_qos_sched/osvbng_qos_sched.api.c>

static clib_error_t *
osvbng_qos_sched_api_init (vlib_main_t *vm)
{
  cake_main_t *cm = &cake_main;

  cm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_qos_sched_api_init) = {
  .runs_after = VLIB_INITS ("osvbng_qos_sched_init"),
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
