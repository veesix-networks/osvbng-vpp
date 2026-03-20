/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Core implementation
 * Per-subscriber enable/disable, DSCP mapping tables, CLI commands.
 *
 * Algorithms derived from the Linux CAKE qdisc (sch_cake.c).
 * Original authors: Dave Taht, Jonathan Morton, Toke Hoiland-Jorgensen,
 * Sebastian Moeller, Kevin Darbyshire-Bryant, Ryan Mounce.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

cake_main_t cake_main;

char *cake_error_strings[] = {
#define cake_error(n, s) s,
#include <osvbng_qos_sched/osvbng_qos_sched_error.def>
#undef cake_error
};

/*
 * CoDel rec_inv_sqrt Newton-Raphson cache.
 * First 16 values precomputed; beyond that, iterate.
 * rec_inv_sqrt approximates 1/sqrt(count) scaled to u16 range.
 */
static void
cake_init_codel_cache (cake_main_t *cm)
{
  cm->codel_rec_inv_sqrt_cache[0] = 0xffff; /* 1/sqrt(1) */
  for (int i = 1; i < 16; i++)
    {
      u32 val = (u32) cm->codel_rec_inv_sqrt_cache[i - 1];
      /* Newton step: val = val * (3 - val*val*count) / 2 */
      val = (val * 3) / 2 - (val * val * val * i) / (2 * 0xffff * 0xffff);
      if (val > 0xffff)
	val = 0xffff;
      cm->codel_rec_inv_sqrt_cache[i] = (u16) val;
    }
}

/*
 * DiffServ DSCP → tin mapping tables.
 * Index = DSCP value (0-63), value = tin index.
 */
static void
cake_init_dscp_tables (cake_main_t *cm)
{
  /* besteffort: all traffic → tin 0 */
  clib_memset (cm->dscp_to_tin_besteffort, 0,
	       sizeof (cm->dscp_to_tin_besteffort));

  /* diffserv3: 3 tins — Bulk(0), Best Effort(1), Voice(2) */
  clib_memset (cm->dscp_to_tin_diffserv3, 1,
	       sizeof (cm->dscp_to_tin_diffserv3));
  /* CS1/LE → Bulk */
  cm->dscp_to_tin_diffserv3[8] = 0;  /* CS1 */
  /* EF/VA/CS5/CS6/CS7 → Voice */
  cm->dscp_to_tin_diffserv3[46] = 2; /* EF */
  cm->dscp_to_tin_diffserv3[44] = 2; /* VA */
  cm->dscp_to_tin_diffserv3[40] = 2; /* CS5 */
  cm->dscp_to_tin_diffserv3[48] = 2; /* CS6 */
  cm->dscp_to_tin_diffserv3[56] = 2; /* CS7 */

  /* diffserv4: 4 tins — Bulk(0), Best Effort(1), Video(2), Voice(3) */
  clib_memset (cm->dscp_to_tin_diffserv4, 1,
	       sizeof (cm->dscp_to_tin_diffserv4));
  /* CS1 → Bulk */
  cm->dscp_to_tin_diffserv4[8] = 0;
  /* AF1x → Best Effort (already default 1) */
  /* CS2/AF2x/CS3/AF3x → Video */
  cm->dscp_to_tin_diffserv4[16] = 2; /* CS2 */
  cm->dscp_to_tin_diffserv4[18] = 2; /* AF21 */
  cm->dscp_to_tin_diffserv4[20] = 2; /* AF22 */
  cm->dscp_to_tin_diffserv4[22] = 2; /* AF23 */
  cm->dscp_to_tin_diffserv4[24] = 2; /* CS3 */
  cm->dscp_to_tin_diffserv4[26] = 2; /* AF31 */
  cm->dscp_to_tin_diffserv4[28] = 2; /* AF32 */
  cm->dscp_to_tin_diffserv4[30] = 2; /* AF33 */
  /* CS4/AF4x → Video */
  cm->dscp_to_tin_diffserv4[32] = 2; /* CS4 */
  cm->dscp_to_tin_diffserv4[34] = 2; /* AF41 */
  cm->dscp_to_tin_diffserv4[36] = 2; /* AF42 */
  cm->dscp_to_tin_diffserv4[38] = 2; /* AF43 */
  /* EF/VA/CS5/CS6/CS7 → Voice */
  cm->dscp_to_tin_diffserv4[46] = 3; /* EF */
  cm->dscp_to_tin_diffserv4[44] = 3; /* VA */
  cm->dscp_to_tin_diffserv4[40] = 3; /* CS5 */
  cm->dscp_to_tin_diffserv4[48] = 3; /* CS6 */
  cm->dscp_to_tin_diffserv4[56] = 3; /* CS7 */

  /* diffserv8: 8 tins — one per IP precedence (DSCP >> 3) */
  for (int i = 0; i < 64; i++)
    cm->dscp_to_tin_diffserv8[i] = i >> 3;
}

/*
 * Initialize a scheduler instance with default tin configuration.
 */
static void
cake_sched_init_tins (cake_sched_t *cs)
{
  u8 tin_cnt;

  switch (cs->tin_mode)
    {
    case 1:
      tin_cnt = 3;
      break; /* diffserv3 */
    case 2:
      tin_cnt = 4;
      break; /* diffserv4 */
    case 3:
      tin_cnt = 8;
      break; /* diffserv8 */
    default:
      tin_cnt = 1;
      break; /* besteffort */
    }

  cs->tin_cnt = tin_cnt;
  vec_validate (cs->tins, tin_cnt - 1);
  clib_memset (cs->tins, 0, sizeof (cake_tin_t) * tin_cnt);

  for (u8 i = 0; i < tin_cnt; i++)
    {
      cake_tin_t *tin = &cs->tins[i];
      tin->tin_index = i;
      tin->priority = i;
      tin->new_flow_head = ~0;
      tin->old_flow_head = ~0;
      tin->decaying_flow_head = ~0;

      /* Per-tin rate: divide global rate among tins.
       * In besteffort mode, the single tin gets full rate.
       * In diffserv modes, shares are configured per design. */
      tin->tin_rate_ns_per_byte = cs->rate_ns_per_byte; /* placeholder: equal
							   share */
      tin->tin_shaper_time_ns = 0;

      /* Default quantum: 1514 (Ethernet MTU + header) */
      tin->quantum = 1514;
      tin->flow_quantum = 1514;

      /* Initialize all flow DRR pointers */
      for (u32 f = 0; f < CAKE_QUEUES; f++)
	{
	  tin->flows[f].next = ~0;
	  tin->flows[f].prev = ~0;
	  tin->flows[f].flow_state = CAKE_FLOW_NONE;
	  tin->flows[f].queue = NULL;
	  tin->flows[f].head = 0;
	  tin->flows[f].tail = 0;
	}
    }
}

/*
 * Enable or disable a per-subscriber scheduler instance.
 */
int
cake_sched_enable_disable (u32 sw_if_index, u8 is_enable,
			   u64 rate_bytes_per_sec, u8 tin_mode,
			   i16 overhead_bytes, u8 atm_mode, u8 mpu,
			   u32 buffer_limit, u32 target_us, u32 interval_us,
			   u32 flags)
{
  cake_main_t *cm = &cake_main;
  u32 thread_index = vlib_get_thread_index ();

  vec_validate (cm->sched_index_by_sw_if_index, sw_if_index);
  vec_validate (cm->per_thread, vlib_num_workers ());

  cake_per_thread_t *pt = &cm->per_thread[thread_index];

  if (is_enable)
    {
      /* Check for existing scheduler on this interface */
      if (cm->sched_index_by_sw_if_index[sw_if_index] != 0)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      cake_sched_t *cs;
      pool_get_zero (pt->schedulers, cs);
      u32 pool_index = cs - pt->schedulers;

      cs->sw_if_index = sw_if_index;
      cs->sched_index = pool_index;
      cs->rate_bytes_per_sec = rate_bytes_per_sec;
      cs->rate_ns_per_byte =
	rate_bytes_per_sec > 0 ? (u64) 1e9 / rate_bytes_per_sec : 0;
      cs->tin_mode = tin_mode;
      cs->overhead_bytes = overhead_bytes;
      cs->atm_mode = atm_mode;
      cs->mpu = mpu;
      cs->target_us = target_us > 0 ? target_us : CAKE_TARGET_US;
      cs->interval_us = interval_us > 0 ? interval_us : CAKE_INTERVAL_US;
      cs->flags = flags;
      cs->global_shaper_time_ns = 0;
      cs->last_dequeue_time_ns = 0;

      /* Auto-calculate buffer limit: rate * interval * 1.5 */
      if (buffer_limit == 0)
	cs->buffer_limit =
	  (u32) ((rate_bytes_per_sec * cs->interval_us * 3) / (1000000 * 2));
      else
	cs->buffer_limit = buffer_limit;

      cs->buffer_usage = 0;

      cake_sched_init_tins (cs);

      /* Store mapping: sw_if_index → (thread << 16 | pool_index) */
      cm->sched_index_by_sw_if_index[sw_if_index] =
	(thread_index << 16) | (pool_index & 0xffff);

      /* Enable feature arc on this interface */
      vnet_feature_enable_disable ("interface-output", "cake-enqueue",
				   sw_if_index, 1, 0, 0);

      vlib_log_notice (cm->log_class,
		       "scheduler enabled on sw_if_index %u "
		       "(rate %llu B/s, %u tins, overhead %d)",
		       sw_if_index, rate_bytes_per_sec,
		       (u32) cs->tin_cnt, (int) overhead_bytes);
    }
  else
    {
      u32 packed = cm->sched_index_by_sw_if_index[sw_if_index];
      if (packed == 0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      u32 owner_thread = packed >> 16;
      u32 pool_index = packed & 0xffff;

      if (owner_thread != thread_index)
	{
	  vlib_log_err (cm->log_class,
			"scheduler disable from wrong thread "
			"(owner=%u, caller=%u)",
			owner_thread, thread_index);
	  return VNET_API_ERROR_INVALID_WORKER;
	}

      cake_sched_t *cs = pool_elt_at_index (pt->schedulers, pool_index);

      /* Disable feature arc */
      vnet_feature_enable_disable ("interface-output", "cake-enqueue",
				   sw_if_index, 0, 0, 0);

      /* Free all flow queues */
      for (u8 t = 0; t < cs->tin_cnt; t++)
	{
	  cake_tin_t *tin = &cs->tins[t];
	  for (u32 f = 0; f < CAKE_QUEUES; f++)
	    {
	      if (tin->flows[f].queue)
		{
		  /* TODO: free queued buffer indices back to VPP */
		  vec_free (tin->flows[f].queue);
		}
	    }
	}
      vec_free (cs->tins);

      /* Clear bitmap and mapping */
      clib_bitmap_set (pt->active_bitmap, pool_index, 0);
      cm->sched_index_by_sw_if_index[sw_if_index] = 0;

      pool_put (pt->schedulers, cs);

      vlib_log_notice (cm->log_class,
		       "scheduler disabled on sw_if_index %u", sw_if_index);
    }

  return 0;
}

/*
 * Reset statistics for a scheduler instance.
 */
void
cake_sched_reset_stats (u32 sw_if_index)
{
  cake_main_t *cm = &cake_main;

  if (sw_if_index >= vec_len (cm->sched_index_by_sw_if_index))
    return;

  u32 packed = cm->sched_index_by_sw_if_index[sw_if_index];
  if (packed == 0)
    return;

  u32 owner_thread = packed >> 16;
  u32 pool_index = packed & 0xffff;
  cake_per_thread_t *pt = &cm->per_thread[owner_thread];
  cake_sched_t *cs = pool_elt_at_index (pt->schedulers, pool_index);

  for (u8 t = 0; t < cs->tin_cnt; t++)
    {
      cake_tin_t *tin = &cs->tins[t];
      tin->packets = 0;
      tin->bytes = 0;
      tin->drops = 0;
      tin->ecn_marks = 0;
      tin->peak_queue_delay_us = 0;
      tin->avg_queue_delay_us = 0;
    }
}

/*
 * CLI: set cake scheduler <interface> rate <kbps> [tin-mode <mode>]
 *      [overhead <bytes>] [atm|ptm|noatm]
 */
static clib_error_t *
cake_sched_set_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  u64 rate_kbps = 0;
  u8 tin_mode = 0;
  i16 overhead_bytes = 0;
  u8 atm_mode = 0;
  u8 mpu = 64;
  u8 is_disable = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else if (unformat (input, "rate %llu", &rate_kbps))
	;
      else if (unformat (input, "tin-mode besteffort"))
	tin_mode = 0;
      else if (unformat (input, "tin-mode diffserv3"))
	tin_mode = 1;
      else if (unformat (input, "tin-mode diffserv4"))
	tin_mode = 2;
      else if (unformat (input, "tin-mode diffserv8"))
	tin_mode = 3;
      else if (unformat (input, "overhead %d", &overhead_bytes))
	;
      else if (unformat (input, "atm"))
	atm_mode = 1;
      else if (unformat (input, "ptm"))
	atm_mode = 2;
      else if (unformat (input, "noatm"))
	atm_mode = 0;
      else if (unformat (input, "mpu %d", &mpu))
	;
      else if (unformat (input, "disable"))
	is_disable = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "interface required");

  if (!is_disable && rate_kbps == 0)
    return clib_error_return (0, "rate required (kbps)");

  u64 rate_bytes = rate_kbps * 1000 / 8;

  int rv =
    cake_sched_enable_disable (sw_if_index, !is_disable, rate_bytes, tin_mode,
			       overhead_bytes, atm_mode, mpu, 0, 0, 0, 0);

  if (rv)
    return clib_error_return (0, "failed: %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (cake_sched_set_command, static) = {
  .path = "set cake scheduler",
  .short_help = "set cake scheduler <interface> rate <kbps> "
		"[tin-mode besteffort|diffserv3|diffserv4|diffserv8] "
		"[overhead <bytes>] [atm|ptm|noatm] [mpu <bytes>] [disable]",
  .function = cake_sched_set_command_fn,
};

/*
 * CLI: show cake scheduler [<interface>]
 */
static clib_error_t *
cake_sched_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  cake_main_t *cm = &cake_main;
  u32 sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnet_get_main (), &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  u32 found = 0;
  for (u32 i = 0; i < vec_len (cm->sched_index_by_sw_if_index); i++)
    {
      u32 packed = cm->sched_index_by_sw_if_index[i];
      if (packed == 0)
	continue;
      if (sw_if_index != ~0 && i != sw_if_index)
	continue;

      u32 owner_thread = packed >> 16;
      u32 pool_index = packed & 0xffff;
      cake_per_thread_t *pt = &cm->per_thread[owner_thread];
      cake_sched_t *cs = pool_elt_at_index (pt->schedulers, pool_index);

      vlib_cli_output (vm,
		       "  sw_if_index %u: rate %llu B/s (%llu kbps), "
		       "%u tins (%s), overhead %d, buffer %u/%u bytes",
		       cs->sw_if_index, cs->rate_bytes_per_sec,
		       cs->rate_bytes_per_sec * 8 / 1000, (u32) cs->tin_cnt,
		       cs->tin_mode == 0   ? "besteffort"
		       : cs->tin_mode == 1 ? "diffserv3"
		       : cs->tin_mode == 2 ? "diffserv4"
					   : "diffserv8",
		       (int) cs->overhead_bytes, cs->buffer_usage,
		       cs->buffer_limit);

      for (u8 t = 0; t < cs->tin_cnt; t++)
	{
	  cake_tin_t *tin = &cs->tins[t];
	  vlib_cli_output (vm,
			   "    tin %u: pkts %llu bytes %llu drops %llu "
			   "ecn %llu delay peak %u avg %u us "
			   "flows sparse %u bulk %u",
			   t, tin->packets, tin->bytes, tin->drops,
			   tin->ecn_marks, tin->peak_queue_delay_us,
			   tin->avg_queue_delay_us, tin->sparse_flow_count,
			   tin->bulk_flow_count);
	}
      found++;
    }

  if (found == 0)
    vlib_cli_output (vm, "  no schedulers configured");

  return 0;
}

VLIB_CLI_COMMAND (cake_sched_show_command, static) = {
  .path = "show cake scheduler",
  .short_help = "show cake scheduler [<interface>]",
  .function = cake_sched_show_command_fn,
};

/*
 * Plugin initialization.
 */
static clib_error_t *
osvbng_qos_sched_init (vlib_main_t *vm)
{
  cake_main_t *cm = &cake_main;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();

  cm->log_class = vlib_log_register_class ("osvbng_qos_sched", 0);

  cake_init_dscp_tables (cm);
  cake_init_codel_cache (cm);

  vlib_log_notice (cm->log_class, "initialized");

  return 0;
}

VLIB_INIT_FUNCTION (osvbng_qos_sched_init);

VLIB_PLUGIN_REGISTER () = {
  .version = "1.0.0",
  .description = "osvbng QoS Scheduler Plugin (CAKE)",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
