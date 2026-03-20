/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Core implementation
 * Plugin init, per-subscriber enable/disable, CLI commands.
 *
 * Phase 1: Single FIFO per subscriber, token-bucket shaping only.
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
 * Set dequeue INPUT node state on all threads.
 * Must be called under barrier (API handlers run inside barrier).
 */
static void
cake_set_dequeue_node_state (vlib_node_state_t state)
{
  cake_main_t *cm = &cake_main;

  foreach_vlib_main ()
    {
      vlib_node_set_state (this_vlib_main, cm->dequeue_node_index, state);
    }
}

/*
 * Enable or disable a per-subscriber scheduler instance.
 * Called from API handlers (inside barrier) or CLI (main thread).
 */
int
cake_sched_enable_disable (vlib_main_t *vm, u32 sw_if_index, u8 is_enable,
			   u64 rate_bytes_per_sec, u8 tin_mode,
			   i16 overhead_bytes, u8 atm_mode, u8 mpu,
			   u32 buffer_limit, u32 target_us, u32 interval_us,
			   u32 flags)
{
  cake_main_t *cm = &cake_main;

  /* Validate interface exists */
  if (!vnet_sw_interface_is_api_valid (vnet_get_main (), sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (is_enable)
    {
      /* Check for existing scheduler on this interface */
      vec_validate_init_empty (cm->sched_index_by_sw_if_index, sw_if_index,
			       ~0);
      if (cm->sched_index_by_sw_if_index[sw_if_index] != ~0)
	return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;

      /* Allocate scheduler instance in global pool */
      cake_sched_t *cs;
      pool_get_zero (cm->schedulers, cs);
      u32 pool_index = cs - cm->schedulers;

      cs->sw_if_index = sw_if_index;
      cs->sched_index = pool_index;
      cs->rate_bytes_per_sec = rate_bytes_per_sec;
      cs->rate_ns_per_byte =
	rate_bytes_per_sec > 0 ? (u64) 1e9 / rate_bytes_per_sec : 0;
      cs->overhead_bytes = overhead_bytes;
      cs->atm_mode = atm_mode;
      cs->mpu = mpu;
      cs->global_shaper_time_ns = 0;

      /* Auto-calculate buffer limit: rate × 100ms × 1.5
       * This gives ~150ms of buffering at the configured rate. */
      if (buffer_limit == 0)
	{
	  u32 interval =
	    interval_us > 0 ? interval_us : 100000; /* default 100ms */
	  cs->buffer_limit =
	    (u32) ((rate_bytes_per_sec * interval * 3) / (1000000 * 2));
	  /* Minimum 64KB to avoid tiny queues at low rates */
	  if (cs->buffer_limit < 65536)
	    cs->buffer_limit = 65536;
	}
      else
	cs->buffer_limit = buffer_limit;

      cs->buffer_usage = 0;
      cs->queued_buffers = 0;
      cs->queue = NULL;
      cs->queue_head = 0;

      /* Store mapping */
      cm->sched_index_by_sw_if_index[sw_if_index] = pool_index;

      /* Enable feature arc on this interface */
      vnet_feature_enable_disable ("interface-output", "cake-enqueue",
				   sw_if_index, 1, 0, 0);

      /* If first scheduler, enable dequeue INPUT node on all threads */
      cm->n_schedulers++;
      if (cm->n_schedulers == 1)
	cake_set_dequeue_node_state (VLIB_NODE_STATE_POLLING);

      /* Ensure per-thread state is allocated for all threads */
      u32 n_threads = vlib_get_n_threads ();
      vec_validate (cm->per_thread, n_threads - 1);

      vlib_log_notice (cm->log_class,
		       "scheduler enabled on sw_if_index %u "
		       "(rate %llu B/s, overhead %d, buffer_limit %u)",
		       sw_if_index, rate_bytes_per_sec, (int) overhead_bytes,
		       cs->buffer_limit);
    }
  else
    {
      /* Disable */
      vec_validate_init_empty (cm->sched_index_by_sw_if_index, sw_if_index,
			       ~0);
      u32 pool_index = cm->sched_index_by_sw_if_index[sw_if_index];
      if (pool_index == ~0)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      cake_sched_t *cs = pool_elt_at_index (cm->schedulers, pool_index);

      /* Disable feature arc on this interface */
      vnet_feature_enable_disable ("interface-output", "cake-enqueue",
				   sw_if_index, 0, 0, 0);

      /*
       * Drain FIFO: free all queued buffers back to VPP.
       * This is one of the five explicit buffer free paths
       * (Decision #2: subscriber teardown).
       */
      if (cs->queue)
	{
	  u32 n_queued = vec_len (cs->queue) - cs->queue_head;
	  if (n_queued > 0)
	    {
	      vlib_buffer_free (vm, cs->queue + cs->queue_head, n_queued);
	      vlib_log_notice (cm->log_class,
			       "drained %u queued buffers on sw_if_index %u",
			       n_queued, sw_if_index);
	    }
	  vec_free (cs->queue);
	}

      /* Clear per-thread active bitmaps for this scheduler */
      for (u32 ti = 0; ti < vec_len (cm->per_thread); ti++)
	{
	  cake_per_thread_t *pt = vec_elt_at_index (cm->per_thread, ti);
	  pt->active_bitmap =
	    clib_bitmap_set (pt->active_bitmap, pool_index, 0);
	}

      /* Clear mapping and release pool entry */
      cm->sched_index_by_sw_if_index[sw_if_index] = ~0;
      pool_put (cm->schedulers, cs);

      /* If last scheduler, disable dequeue INPUT node on all threads */
      cm->n_schedulers--;
      if (cm->n_schedulers == 0)
	cake_set_dequeue_node_state (VLIB_NODE_STATE_DISABLED);

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

  u32 pool_index = cm->sched_index_by_sw_if_index[sw_if_index];
  if (pool_index == ~0)
    return;

  cake_sched_t *cs = pool_elt_at_index (cm->schedulers, pool_index);

  cs->enqueued_pkts = 0;
  cs->enqueued_bytes = 0;
  cs->dequeued_pkts = 0;
  cs->dequeued_bytes = 0;
  cs->dropped_pkts = 0;
}

/*
 * CLI: set cake scheduler <interface> rate <kbps> [overhead <bytes>]
 *      [atm|ptm|noatm] [mpu <bytes>] [disable]
 */
static clib_error_t *
cake_sched_set_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  u32 sw_if_index = ~0;
  u64 rate_kbps = 0;
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

  int rv = cake_sched_enable_disable (
    vm, sw_if_index, !is_disable, rate_bytes,
    0 /* tin_mode: besteffort */, overhead_bytes, atm_mode, mpu,
    0 /* auto buffer_limit */, 0 /* default target */, 0 /* default interval */,
    0 /* no flags */);

  if (rv)
    return clib_error_return (0, "cake_sched_enable_disable returned %d", rv);

  return 0;
}

VLIB_CLI_COMMAND (cake_sched_set_command, static) = {
  .path = "set cake scheduler",
  .short_help = "set cake scheduler <interface> rate <kbps> "
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
  cake_sched_t *cs;
  pool_foreach (cs, cm->schedulers)
    {
      if (sw_if_index != ~0 && cs->sw_if_index != sw_if_index)
	continue;

      u32 queue_depth = 0;
      if (cs->queue)
	queue_depth = vec_len (cs->queue) - cs->queue_head;

      vlib_cli_output (
	vm,
	"  %U: rate %llu B/s (%llu kbps), overhead %d, "
	"queue %u pkts %u/%u bytes",
	format_vnet_sw_if_index_name, vnet_get_main (), cs->sw_if_index,
	cs->rate_bytes_per_sec, cs->rate_bytes_per_sec * 8 / 1000,
	(int) cs->overhead_bytes, queue_depth, cs->buffer_usage,
	cs->buffer_limit);

      vlib_cli_output (vm,
		       "    enqueued: %llu pkts %llu bytes, "
		       "dequeued: %llu pkts %llu bytes, "
		       "dropped: %llu pkts",
		       cs->enqueued_pkts, cs->enqueued_bytes,
		       cs->dequeued_pkts, cs->dequeued_bytes,
		       cs->dropped_pkts);
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
  cm->n_schedulers = 0;

  /* Store node indices for later reference */
  cm->enqueue_node_index = cake_enqueue_node.index;
  cm->dequeue_node_index = cake_dequeue_node.index;

  vlib_log_notice (cm->log_class, "initialized (Phase 1: shaper only)");

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
