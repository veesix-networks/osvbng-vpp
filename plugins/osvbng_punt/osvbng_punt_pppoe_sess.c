/*
 * Copyright (c) 2025-2026 Veesix Networks
 * Licensed under the Apache License, Version 2.0
 */

/*
 * PPPoE Session (ethertype 0x8864) classifier node.
 *
 * Post-refactor scope: this node only forwards full PPPoE-session
 * frames to `osvbng-pppoe-input` for in-plugin classification +
 * dispatch. All PPPoE session-table lookups, LAC bridge dispatch,
 * and non-IP control-plane punt decisions live inside the PPPoE
 * plugin where they have natural access to the session pool — no
 * cross-plugin memory access here.
 *
 * The node is kept (rather than rewiring the upstream classifier
 * directly to osvbng-pppoe-input) because the PPPoE-Session ethertype
 * registration lives in this plugin and we want a stable insertion
 * point for future per-frame instrumentation that doesn't belong in
 * PPPoE itself.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <osvbng_punt/osvbng_punt.h>

typedef struct
{
  u32 sw_if_index;
} osvbng_punt_pppoe_sess_trace_t;

static u8 *
format_osvbng_punt_pppoe_sess_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  osvbng_punt_pppoe_sess_trace_t *t =
    va_arg (*args, osvbng_punt_pppoe_sess_trace_t *);
  s = format (s, "OSVBNG-PUNT-PPPOE-SESS: sw_if_index %d -> pppoe-input",
	      t->sw_if_index);
  return s;
}

#define foreach_osvbng_punt_pppoe_sess_error                                   \
  _ (FORWARDED, "PPPoE session frames forwarded to pppoe-input")

typedef enum
{
#define _(sym, str) OSVBNG_PUNT_PPPOE_SESS_ERROR_##sym,
  foreach_osvbng_punt_pppoe_sess_error
#undef _
    OSVBNG_PUNT_PPPOE_SESS_N_ERROR,
} osvbng_punt_pppoe_sess_error_t;

static char *osvbng_punt_pppoe_sess_error_strings[] = {
#define _(sym, string) string,
  foreach_osvbng_punt_pppoe_sess_error
#undef _
};

typedef enum
{
  OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT,
  OSVBNG_PUNT_PPPOE_SESS_N_NEXT,
} osvbng_punt_pppoe_sess_next_t;

VLIB_NODE_FN (osvbng_punt_pppoe_sess_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT;
  u32 pkts_forwarded = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      osvbng_punt_pppoe_sess_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  pkts_forwarded++;
	  vlib_validate_buffer_enqueue_x1 (
	    vm, node, next_index, to_next, n_left_to_next, bi0,
	    OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       OSVBNG_PUNT_PPPOE_SESS_ERROR_FORWARDED,
			       pkts_forwarded);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (osvbng_punt_pppoe_sess_node) = {
  .name = "osvbng-punt-pppoe-sess",
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_punt_pppoe_sess_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (osvbng_punt_pppoe_sess_error_strings),
  .error_strings = osvbng_punt_pppoe_sess_error_strings,
  .n_next_nodes = OSVBNG_PUNT_PPPOE_SESS_N_NEXT,
  .next_nodes = {
    [OSVBNG_PUNT_PPPOE_SESS_NEXT_PPPOE_INPUT] = "osvbng-pppoe-input",
  },
};
