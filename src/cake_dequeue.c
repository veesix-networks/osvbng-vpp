/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng QoS Scheduler Plugin - Dequeue node
 * VLIB_NODE_TYPE_INPUT polling node.
 *
 * Phase 3: DRR scheduling + COBALT AQM (CoDel + BLUE).
 *
 * MULTIARCH: compiled with SIMD variants (AVX2, AVX-512, NEON).
 */

#include <vnet/vnet.h>
#include <vnet/feature/feature.h>

#include <osvbng_qos_sched/osvbng_qos_sched.h>

typedef enum
{
  CAKE_DEQUEUE_NEXT_REINJECT_IP4,
  CAKE_DEQUEUE_NEXT_REINJECT_IP6,
  CAKE_DEQUEUE_N_NEXT,
} cake_dequeue_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 n_dequeued;
  u32 flow_idx;
} cake_dequeue_trace_t;

static u8 *
format_cake_dequeue_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cake_dequeue_trace_t *t = va_arg (*args, cake_dequeue_trace_t *);

  s = format (s, "CAKE-DEQUEUE: sw_if_index %u flow %u dequeued %u",
	      t->sw_if_index, t->flow_idx, t->n_dequeued);
  return s;
}

static_always_inline void
cake_agg_complete_detach (cake_main_t *cm, cake_aggregate_t *agg,
			   cake_sched_t *cs, u32 sched_idx)
{
  if (cs->agg_active)
    {
      cake_agg_child_list_remove (cm->schedulers, &agg->active_child_head,
				   &agg->active_child_tail, sched_idx);
      agg->n_active_children--;
      cs->agg_active = 0;
    }

  if (agg->drr_cursor == sched_idx)
    agg->drr_cursor = cs->agg_next != ~0 ? cs->agg_next : agg->child_head;

  cake_agg_child_list_remove (cm->schedulers, &agg->child_head,
			       &agg->child_tail, sched_idx);
  agg->n_children--;

  cake_agg_discharge (cm, cs, cs->buffer_usage);

  cs->aggregate_index = ~0;
  cs->agg_deficit = 0;
  cs->agg_draining = 0;
}

static_always_inline u8
cake_sched_has_backlog (cake_sched_t *cs)
{
  for (u8 t = 0; t < cs->n_tins; t++)
    {
      cake_tin_t *tin = &cs->tins[t];
      if (tin->sparse_flow_count + tin->bulk_flow_count > 0 ||
	  tin->decaying_flow_head != ~0)
	return 1;
    }
  return 0;
}

static_always_inline void
cake_flow_reclaim (vlib_main_t *vm, cake_tin_t *tin, cake_sched_t *cs,
		   u32 flow_idx, u32 *list_head, u32 *list_tail, u32 now_us)
{
  cake_flow_t *f = &tin->flows[flow_idx];

  cobalt_queue_empty (f, cs->target_us, cs->p_dec, cs->interval_us, now_us);

  cake_flow_list_remove (list_head, list_tail, tin->flows, flow_idx);
  cake_flow_ring_free (vm, f);

  if (f->flow_state == CAKE_FLOW_SPARSE)
    tin->sparse_flow_count--;
  else if (f->flow_state == CAKE_FLOW_BULK)
    {
      tin->bulk_flow_count--;
      if (f->dst_host_idx < CAKE_HOSTS)
	{
	  if (tin->hosts[f->dst_host_idx].bulk_flow_count > 0)
	    tin->hosts[f->dst_host_idx].bulk_flow_count--;
	}
    }

  tin->flow_tags[flow_idx] = 0;
  clib_memset (f, 0, sizeof (*f));
  f->next = ~0;
  f->prev = ~0;
  tin->flow_count--;
}

static_always_inline u32
cake_select_flow (cake_tin_t *tin)
{
  if (tin->new_flow_head != ~0)
    return tin->new_flow_head;
  if (tin->old_flow_head != ~0)
    return tin->old_flow_head;
  if (tin->decaying_flow_head != ~0)
    return tin->decaying_flow_head;
  return ~0;
}

/*
 * Dequeue one packet from a flow, apply COBALT AQM, and either
 * re-inject or drop. Returns 1 if a packet was re-injected, 0 if
 * dropped or queue empty.
 */
static_always_inline u8
cake_dequeue_one (vlib_main_t *vm, vlib_node_runtime_t *node,
		  cake_main_t *cm, cake_sched_t *cs, cake_tin_t *tin,
		  cake_flow_t *flow, u32 now_us, u64 now_ns,
		  u32 *out_bi, u16 *out_next, u32 *n_aqm_drops,
		  u32 *n_ecn_marks, u32 *random_seed)
{
  if (cake_flow_queue_len (flow) == 0)
    return 0;

  u32 bi = flow->ring[flow->head & CAKE_FLOW_RING_MASK];
  flow->head++;

  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  u32 pkt_len = vlib_buffer_length_in_chain (vm, b);

  u32 enqueue_us = cake_buffer_enqueue_time (b);
  u32 sojourn_us = now_us - enqueue_us;

  u8 ecn_capable = 0;
  u8 *ip_hdr = cake_l3_header (b);
  u8 is_v4 = (ip_hdr[0] >> 4) == 4;

  if (is_v4)
    ecn_capable =
      (((ip4_header_t *) ip_hdr)->tos & IP_PACKET_TC_FIELD_ECN_MASK) !=
      IP_ECN_NON_ECN;
  else
    {
      u32 vtcfl = clib_net_to_host_u32 (
	((ip6_header_t *) ip_hdr)->ip_version_traffic_class_and_flow_label);
      ecn_capable = ((vtcfl >> 20) & 0x03) != 0;
    }

  u8 ecn_marked = 0;
  u8 should_drop = cobalt_should_drop (
    flow, cs, sojourn_us, now_us,
    tin->bulk_flow_count > 0 ? tin->bulk_flow_count : 1, ecn_capable,
    &ecn_marked, random_seed);

  if (PREDICT_FALSE (should_drop))
    {
      flow->backlog_bytes -= pkt_len;
      cs->buffer_usage -= pkt_len;
      cs->queued_buffers--;
      cs->dropped_pkts++;
      tin->drops++;
      (*n_aqm_drops)++;
      cake_agg_discharge (cm, cs, pkt_len);
      vlib_buffer_free_one (vm, bi);
      return 0;
    }

  if (PREDICT_FALSE (ecn_marked))
    {
      cake_ecn_mark (b);
      tin->ecn_marks++;
      (*n_ecn_marks)++;
    }

  u32 adj_len = cake_overhead_adjust (cs, pkt_len);
  cs->global_shaper_time_ns += (u64) adj_len * cs->rate_ns_per_byte;
  u64 max_shaper = now_ns + (u64) 150000000;
  if (cs->global_shaper_time_ns > max_shaper)
    cs->global_shaper_time_ns = max_shaper;

  flow->backlog_bytes -= pkt_len;
  flow->deficit -= (i32) adj_len;
  cs->buffer_usage -= pkt_len;
  cs->queued_buffers--;
  cs->dequeued_pkts++;
  cs->dequeued_bytes += pkt_len;
  cake_agg_discharge (cm, cs, pkt_len);

  b->flags |= CAKE_BUFFER_F_SCHEDULED;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  u32 dummy;

  if (is_v4)
    {
      vnet_feature_arc_start (cm->ip4_output_arc_index, sw_if_index, &dummy,
			      b);
      *out_next = CAKE_DEQUEUE_NEXT_REINJECT_IP4;
    }
  else
    {
      vnet_feature_arc_start (cm->ip6_output_arc_index, sw_if_index, &dummy,
			      b);
      *out_next = CAKE_DEQUEUE_NEXT_REINJECT_IP6;
    }

  *out_bi = bi;
  return 1;
}

static_always_inline u32
cake_dequeue_scheduler (vlib_main_t *vm, vlib_node_runtime_t *node,
			 cake_main_t *cm, cake_sched_t *cs, u32 si,
			 u64 now_ns, u32 now_us, u32 budget,
			 u32 *out_bi, u16 *out_nexts, u32 *n_out_p,
			 u32 *n_aqm_drops, u32 *n_ecn_marks,
			 u32 *random_seed)
{
  u32 n_out = *n_out_p;
  u32 sched_dequeued = 0;
  u32 last_flow_idx = ~0;

  while (budget > 0)
    {
      cake_tin_t *tin = NULL;
      for (i32 t = cs->n_tins - 1; t >= 0; t--)
	{
	  cake_tin_t *candidate = &cs->tins[t];
	  if (candidate->sparse_flow_count + candidate->bulk_flow_count > 0 ||
	      candidate->decaying_flow_head != ~0)
	    {
	      tin = candidate;
	      break;
	    }
	}

      if (!tin)
	break;

      u32 flow_idx = cake_select_flow (tin);
      if (flow_idx == ~0)
	break;

      cake_flow_t *flow = &tin->flows[flow_idx];
      last_flow_idx = flow_idx;

      if (flow->flow_state == CAKE_FLOW_SPARSE)
	{
	  if (cake_flow_queue_len (flow) == 0)
	    {
	      cake_flow_reclaim (vm, tin, cs, flow_idx, &tin->new_flow_head,
				 &tin->new_flow_tail, now_us);
	      continue;
	    }

	  u8 sent = cake_dequeue_one (vm, node, cm, cs, tin, flow, now_us,
				       now_ns, &out_bi[n_out],
				       &out_nexts[n_out], n_aqm_drops,
				       n_ecn_marks, random_seed);
	  if (sent)
	    {
	      n_out++;
	      budget--;
	      sched_dequeued++;
	    }

	  if (cake_flow_queue_len (flow) == 0)
	    cake_flow_reclaim (vm, tin, cs, flow_idx, &tin->new_flow_head,
			       &tin->new_flow_tail, now_us);

	  if (now_ns < cs->global_shaper_time_ns)
	    break;
	  continue;
	}

      if (flow->deficit <= 0)
	flow->deficit += cake_quantum_for_flow (tin, flow);

      while (flow->deficit > 0 && budget > 0)
	{
	  if (cake_flow_queue_len (flow) == 0)
	    {
	      if (flow->flow_state == CAKE_FLOW_BULK)
		{
		  if (flow->dst_host_idx < CAKE_HOSTS &&
		      tin->hosts[flow->dst_host_idx].bulk_flow_count > 0)
		    tin->hosts[flow->dst_host_idx].bulk_flow_count--;

		  flow->flow_state = CAKE_FLOW_DECAYING;
		  cake_flow_list_remove (&tin->old_flow_head,
					 &tin->old_flow_tail, tin->flows,
					 flow_idx);
		  cake_flow_list_append_tail (&tin->decaying_flow_head,
					      &tin->decaying_flow_tail,
					      tin->flows, flow_idx);
		  tin->bulk_flow_count--;
		}
	      else if (flow->flow_state == CAKE_FLOW_DECAYING)
		{
		  cake_flow_reclaim (vm, tin, cs, flow_idx,
				     &tin->decaying_flow_head,
				     &tin->decaying_flow_tail, now_us);
		}
	      break;
	    }

	  u8 sent = cake_dequeue_one (vm, node, cm, cs, tin, flow, now_us,
				       now_ns, &out_bi[n_out],
				       &out_nexts[n_out], n_aqm_drops,
				       n_ecn_marks, random_seed);
	  if (sent)
	    {
	      n_out++;
	      budget--;
	      sched_dequeued++;
	    }

	  if (now_ns < cs->global_shaper_time_ns)
	    goto done;
	}

      if (flow->deficit <= 0 && flow->flow_state == CAKE_FLOW_BULK &&
	  cake_flow_queue_len (flow) > 0)
	{
	  cake_flow_list_remove (&tin->old_flow_head, &tin->old_flow_tail,
				 tin->flows, flow_idx);
	  cake_flow_list_append_tail (&tin->old_flow_head, &tin->old_flow_tail,
				      tin->flows, flow_idx);
	  flow->deficit = 0;
	}

      continue;

    done:
      break;
    }

  if (sched_dequeued > 0 &&
      PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, out_bi[n_out - 1]);
      cake_dequeue_trace_t *t =
	vlib_add_trace (vm, node, b0, sizeof (*t));
      t->sw_if_index = cs->sw_if_index;
      t->n_dequeued = sched_dequeued;
      t->flow_idx = last_flow_idx;
    }

  *n_out_p = n_out;
  return sched_dequeued;
}

VLIB_NODE_FN (cake_dequeue_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cake_main_t *cm = &cake_main;
  u32 thread_index = vm->thread_index;

  if (PREDICT_FALSE (thread_index >= vec_len (cm->per_thread)))
    return 0;

  cake_per_thread_t *pt = vec_elt_at_index (cm->per_thread, thread_index);
  u8 has_standalone = !clib_bitmap_is_zero (pt->active_bitmap);
  u8 has_aggregates = !clib_bitmap_is_zero (pt->active_agg_bitmap);

  if (PREDICT_FALSE (!has_standalone && !has_aggregates))
    return 0;

  f64 now = vlib_time_now (vm);
  u64 now_ns = (u64) (now * 1e9);
  u32 now_us = (u32) (now * 1e6);
  u32 budget = VLIB_FRAME_SIZE;

  u32 out_bi[VLIB_FRAME_SIZE];
  u16 out_nexts[VLIB_FRAME_SIZE];
  u32 n_out = 0;

  u32 deactivate[VLIB_FRAME_SIZE];
  u32 n_deactivate = 0;
  u32 agg_deactivate[VLIB_FRAME_SIZE];
  u32 n_agg_deactivate = 0;

  u32 n_aqm_drops = 0;
  u32 n_ecn_marks = 0;
  u32 n_agg_shaped = 0;
  u32 n_agg_bp = 0;

  u8 standalone_wrapped = 0;
  u8 agg_wrapped = 0;

  while (budget > 0 && !(standalone_wrapped && agg_wrapped))
    {
      if (has_standalone && !standalone_wrapped)
	{
	  uword si = clib_bitmap_next_set (pt->active_bitmap,
					    pt->standalone_cursor);
	  if (si == ~0)
	    {
	      si = clib_bitmap_next_set (pt->active_bitmap, 0);
	      if (si == ~0)
		standalone_wrapped = 1;
	    }

	  if (si != ~0)
	    {
	      pt->standalone_cursor = si + 1;

	      if (PREDICT_FALSE (pool_is_free_index (cm->schedulers, si)))
		{
		  if (n_deactivate < VLIB_FRAME_SIZE)
		    deactivate[n_deactivate++] = si;
		}
	      else
		{
		  cake_sched_t *cs =
		    pool_elt_at_index (cm->schedulers, si);

		  if (cs->aggregate_index != ~0)
		    {
		      standalone_wrapped = 1;
		    }
		  else if (PREDICT_FALSE (cs->owner_thread != thread_index))
		    {
		      if (n_deactivate < VLIB_FRAME_SIZE)
			deactivate[n_deactivate++] = si;
		    }
		  else if (now_ns >= cs->global_shaper_time_ns)
		    {
		      u32 dequeued = cake_dequeue_scheduler (
			vm, node, cm, cs, si, now_ns, now_us, budget,
			out_bi, out_nexts, &n_out, &n_aqm_drops,
			&n_ecn_marks, &pt->random_seed);
		      budget -= dequeued;

		      if (!cake_sched_has_backlog (cs) &&
			  n_deactivate < VLIB_FRAME_SIZE)
			deactivate[n_deactivate++] = si;

		      standalone_wrapped = 1;
		    }
		}
	    }
	}

      if (has_aggregates && !agg_wrapped && budget > 0)
	{
	  uword ai = clib_bitmap_next_set (pt->active_agg_bitmap,
					    pt->agg_cursor);
	  if (ai == ~0)
	    {
	      ai = clib_bitmap_next_set (pt->active_agg_bitmap, 0);
	      if (ai == ~0)
		agg_wrapped = 1;
	    }

	  if (ai != ~0)
	    {
	      pt->agg_cursor = ai + 1;

	      if (PREDICT_FALSE (pool_is_free_index (cm->aggregates, ai)))
		{
		  if (n_agg_deactivate < VLIB_FRAME_SIZE)
		    agg_deactivate[n_agg_deactivate++] = ai;
		  agg_wrapped = 1;
		  continue;
		}

	      cake_aggregate_t *agg =
		pool_elt_at_index (cm->aggregates, ai);

	      if (now_ns > agg->global_shaper_time_ns)
		agg->global_shaper_time_ns = now_ns;

	      if (now_ns < agg->global_shaper_time_ns)
		{
		  agg_wrapped = 1;
		  continue;
		}

	      u32 children_visited = 0;
	      u32 cursor = agg->drr_cursor;
	      if (cursor == ~0 ||
		  pool_is_free_index (cm->schedulers, cursor))
		cursor = agg->active_child_head;

	      while (cursor != ~0 &&
		     children_visited < agg->n_active_children &&
		     budget > 0)
		{
		  cake_sched_t *child =
		    pool_elt_at_index (cm->schedulers, cursor);
		  u32 next_cursor =
		    child->agg_next != ~0 ? child->agg_next
					  : agg->active_child_head;

		  if (child->agg_deficit <= 0)
		    child->agg_deficit += agg->quantum;

		  if (now_ns >= child->global_shaper_time_ns &&
		      now_ns >= agg->global_shaper_time_ns &&
		      child->agg_deficit > 0)
		    {
		      u32 pre_out = n_out;
		      u32 dequeued = cake_dequeue_scheduler (
			vm, node, cm, child, cursor, now_ns, now_us,
			budget < (u32) child->agg_deficit
			  ? budget
			  : (u32) child->agg_deficit,
			out_bi, out_nexts, &n_out, &n_aqm_drops, &n_ecn_marks,
			&pt->random_seed);

		      for (u32 p = pre_out; p < n_out; p++)
			{
			  vlib_buffer_t *b =
			    vlib_get_buffer (vm, out_bi[p]);
			  u32 adj_len = cake_overhead_adjust (
			    child,
			    vlib_buffer_length_in_chain (vm, b));
			  agg->global_shaper_time_ns +=
			    (u64) adj_len * agg->rate_ns_per_byte;
			  child->agg_deficit -= (i32) adj_len;
			  agg->shaped_pkts++;
			  agg->shaped_bytes += adj_len;
			  n_agg_shaped++;
			}

		      budget -= dequeued;
		    }

		  if (!cake_sched_has_backlog (child))
		    {
		      u32 remove_idx = cursor;
		      cursor = next_cursor;

		      cake_agg_child_list_remove (
			cm->schedulers, &agg->active_child_head,
			&agg->active_child_tail, remove_idx);
		      agg->n_active_children--;
		      child->agg_active = 0;

		      if (child->agg_draining)
			cake_agg_complete_detach (cm, agg, child,
						   remove_idx);

		      if (agg->n_active_children == 0)
			break;

		      children_visited++;
		      continue;
		    }

		  if (now_ns < agg->global_shaper_time_ns)
		    {
		      agg->drr_cursor = cursor;
		      break;
		    }

		  cursor = next_cursor;
		  children_visited++;
		}

	      agg->drr_cursor = cursor;

	      if (agg->n_active_children == 0 && agg->n_children == 0 &&
		  n_agg_deactivate < VLIB_FRAME_SIZE)
		agg_deactivate[n_agg_deactivate++] = ai;

	      agg_wrapped = 1;
	    }
	}

      if (!has_standalone)
	standalone_wrapped = 1;
      if (!has_aggregates)
	agg_wrapped = 1;
    }

  for (u32 i = 0; i < n_deactivate; i++)
    pt->active_bitmap =
      clib_bitmap_set (pt->active_bitmap, deactivate[i], 0);

  for (u32 i = 0; i < n_agg_deactivate; i++)
    pt->active_agg_bitmap =
      clib_bitmap_set (pt->active_agg_bitmap, agg_deactivate[i], 0);

  if (n_out > 0)
    vlib_buffer_enqueue_to_next (vm, node, out_bi, out_nexts, n_out);

  vlib_node_increment_counter (vm, node->node_index, CAKE_ERROR_DEQUEUED,
			       n_out);

  if (n_aqm_drops)
    vlib_node_increment_counter (vm, node->node_index, CAKE_ERROR_DROPPED_AQM,
				 n_aqm_drops);
  if (n_ecn_marks)
    vlib_node_increment_counter (vm, node->node_index, CAKE_ERROR_ECN_MARKED,
				 n_ecn_marks);
  if (n_agg_shaped)
    vlib_node_increment_counter (vm, node->node_index, CAKE_ERROR_AGG_SHAPED,
				 n_agg_shaped);

  return n_out;
}

VLIB_REGISTER_NODE (cake_dequeue_node) = {
  .name = "cake-dequeue",
  .vector_size = sizeof (u32),
  .format_trace = format_cake_dequeue_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = CAKE_N_ERROR,
  .error_strings = cake_error_strings,
  .n_next_nodes = CAKE_DEQUEUE_N_NEXT,
  .next_nodes = {
    [CAKE_DEQUEUE_NEXT_REINJECT_IP4] = "ip4-cake-enqueue",
    [CAKE_DEQUEUE_NEXT_REINJECT_IP6] = "ip6-cake-enqueue",
  },
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
