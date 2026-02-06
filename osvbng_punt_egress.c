/*
 * Copyright (c) 2025 Veesix Networks
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Egress node for transmitting packets from osvbng to VPP interfaces
 *
 * This node is triggered by eventfd when osvbng writes packets to the
 * egress ring. It dequeues packets, allocates VPP buffers, and sends
 * them directly to the hardware output node (similar to LLDP pattern).
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/file.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <osvbng_punt/osvbng_punt.h>
#include <osvbng_punt/osvbng_punt_shared.h>

/* Maximum packets to process per interrupt */
#define OSVBNG_EGRESS_MAX_BATCH VLIB_FRAME_SIZE

typedef struct
{
  u32 sw_if_index;
  u16 data_length;
} osvbng_egress_trace_t;

static u8 *
format_osvbng_egress_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  osvbng_egress_trace_t *t = va_arg (*args, osvbng_egress_trace_t *);

  s = format (s, "OSVBNG-EGRESS: sw_if_index %d, len %d", t->sw_if_index,
	      t->data_length);
  return s;
}

/*
 * Egress input node - processes packets from osvbng
 *
 * This is an INPUT node that wakes up when signaled via eventfd.
 * It reads packets from the egress ring and transmits them.
 */
VLIB_NODE_FN (osvbng_egress_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vnet_main_t *vnm = pm->vnet_main;
  osvbng_ring_header_t *ring;
  uint64_t head, tail;
  uint64_t mask;
  u32 n_tx = 0;

  if (PREDICT_FALSE (!pm->shm_initialized))
    return 0;

  ring = pm->egress_ring;
  mask = pm->egress_ring_size - 1;

  /* Read head (what osvbng has written) */
  head = atomic_load_explicit (&ring->head, memory_order_acquire);
  tail = pm->egress_tail;

  while (tail != head && n_tx < OSVBNG_EGRESS_MAX_BATCH)
    {
      osvbng_egress_desc_t *desc = &pm->egress_descs[tail & mask];
      vnet_hw_interface_t *hw;
      vlib_buffer_t *b;
      u32 bi;
      u8 *data_ptr;

      /* Validate sw_if_index */
      if (PREDICT_FALSE (
	    pool_is_free_index (vnm->interface_main.sw_interfaces,
				desc->sw_if_index)))
	{
	  vlib_log_warn (pm->log_class,
			 "egress: invalid sw_if_index %d, skipping",
			 desc->sw_if_index);
	  tail++;
	  continue;
	}

      /* Get hardware interface for this sw_if_index */
      hw = vnet_get_sup_hw_interface (vnm, desc->sw_if_index);
      if (PREDICT_FALSE (!hw))
	{
	  vlib_log_warn (pm->log_class,
			 "egress: no hw interface for sw_if_index %d",
			 desc->sw_if_index);
	  tail++;
	  continue;
	}

      /* Allocate VPP buffer */
      if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) != 1))
	{
	  pm->egress_alloc_fail++;
	  break; /* Can't continue without buffers */
	}

      b = vlib_get_buffer (vm, bi);

      /* Copy frame from shared memory */
      data_ptr = (u8 *) pm->shm + desc->data_offset;
      u32 max_len = vlib_buffer_get_default_data_size (vm);
      if (PREDICT_FALSE (desc->data_length > max_len))
	{
	  vlib_log_warn (pm->log_class,
			 "egress: frame too large (%d > %d), truncating",
			 desc->data_length, max_len);
	  clib_memcpy_fast (b->data, data_ptr, max_len);
	  b->current_length = max_len;
	}
      else
	{
	  clib_memcpy_fast (b->data, data_ptr, desc->data_length);
	  b->current_length = desc->data_length;
	}

      /* Set TX interface */
      vnet_buffer (b)->sw_if_index[VLIB_TX] = desc->sw_if_index;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = ~0;

      /* Trace if enabled */
      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  osvbng_egress_trace_t *t =
	    vlib_add_trace (vm, node, b, sizeof (*t));
	  t->sw_if_index = desc->sw_if_index;
	  t->data_length = desc->data_length;
	}

      /*
       * Send directly to interface output node (LLDP pattern)
       *
       * This bypasses the normal packet processing path and sends
       * the frame directly to the hardware output node with full
       * L2 headers already constructed by osvbng.
       */
      {
	vlib_frame_t *f;
	u32 *to_next;

	f = vlib_get_frame_to_node (vm, hw->output_node_index);
	to_next = vlib_frame_vector_args (f);
	to_next[0] = bi;
	f->n_vectors = 1;
	vlib_put_frame_to_node (vm, hw->output_node_index, f);
      }

      tail++;
      n_tx++;
    }

  /* Update our local tail and publish it */
  pm->egress_tail = tail;
  atomic_store_explicit (&ring->tail, tail, memory_order_release);

  /* Clear interrupt pending flag */
  atomic_store_explicit (&ring->interrupt_pending, 0, memory_order_release);

  pm->egress_transmitted += n_tx;

  return n_tx;
}

VLIB_REGISTER_NODE (osvbng_egress_node) = {
  .name = "osvbng-egress",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
  .format_trace = format_osvbng_egress_trace,
};

/*
 * Eventfd read handler - triggers the egress node when osvbng signals
 */
static clib_error_t *
osvbng_egress_eventfd_handler (clib_file_t *f)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  vlib_main_t *vm = pm->vlib_main;
  uint64_t counter;

  /* Read and clear the eventfd counter */
  CLIB_UNUSED (ssize_t rv) = read (f->file_descriptor, &counter,
				   sizeof (counter));

  /* Signal VPP to run the egress node */
  vlib_node_set_interrupt_pending (vm, osvbng_egress_node.index);

  return 0;
}

/*
 * Register the egress eventfd with VPP file polling
 * Called after shared memory initialization
 */
int
osvbng_punt_egress_init (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (!pm->shm_initialized || pm->egress_eventfd < 0)
    {
      vlib_log_err (pm->log_class, "egress init: shm not ready");
      return -1;
    }

  /* Initialize egress tracking */
  pm->egress_tail = 0;
  pm->egress_transmitted = 0;
  pm->egress_alloc_fail = 0;

  /* Register eventfd with VPP file polling */
  clib_file_t cf = {
    .read_function = osvbng_egress_eventfd_handler,
    .file_descriptor = pm->egress_eventfd,
    .description = format (0, "osvbng-egress-eventfd"),
  };
  pm->egress_file_index = clib_file_add (&file_main, &cf);

  vlib_log_notice (pm->log_class, "egress node initialized (eventfd=%d)",
		   pm->egress_eventfd);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
