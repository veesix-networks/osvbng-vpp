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
#define OSVBNG_EGRESS_MAX_IFS 8

typedef struct
{
  u32 output_node_index;
  vlib_frame_t *f;
  u32 *to_next;
  u32 n_vectors;
} osvbng_egress_pending_t;

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
  osvbng_egress_pending_t pending[OSVBNG_EGRESS_MAX_IFS];
  u32 n_pending = 0;
  u32 n_trace;

  if (PREDICT_FALSE (!pm->shm_initialized))
    return 0;

  /* An input node owns its own trace accounting: vlib_add_trace alone
   * records nothing and leaves the buffer unmarked for downstream
   * nodes. Injection is the path an operator traces when a control
   * reply never reaches a subscriber, so it has to work. */
  n_trace = vlib_get_trace_count (vm, node);

  ring = pm->egress_ring;
  mask = pm->egress_ring_size - 1;

  head = atomic_load_explicit (&ring->head, memory_order_acquire);
  tail = pm->egress_tail;

  while (tail != head && n_tx < OSVBNG_EGRESS_MAX_BATCH)
    {
      osvbng_egress_desc_t *desc = &pm->egress_descs[tail & mask];
      vnet_hw_interface_t *hw;
      vlib_buffer_t *b;
      u32 bi;
      u8 *data_ptr;

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

      /* A session teardown races the control plane's last frames (LCP
       * Terminate-Ack, Echo-Reply): the interface may already be admin
       * down or parked hidden for reuse. interface-output would drop the
       * frame anyway - skip the inject instead of transiting a corpse. */
      {
	vnet_sw_interface_t *si_tx =
	  vnet_get_sw_interface (vnm, desc->sw_if_index);
	if (PREDICT_FALSE (!(si_tx->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ||
			   (si_tx->flags & VNET_SW_INTERFACE_FLAG_HIDDEN)))
	  {
	    tail++;
	    continue;
	  }
      }

      hw = vnet_get_sup_hw_interface (vnm, desc->sw_if_index);
      if (PREDICT_FALSE (!hw))
	{
	  vlib_log_warn (pm->log_class,
			 "egress: no hw interface for sw_if_index %d",
			 desc->sw_if_index);
	  tail++;
	  continue;
	}

      if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) != 1))
	{
	  pm->egress_alloc_fail++;
	  break;
	}

      b = vlib_get_buffer (vm, bi);

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

      /* RX must be a real interface: any later drop indexes per-interface
       * counters by it, and error-drop does so unchecked - ~0 there is a
       * wild write and a SIGSEGV. Charge the injected frame to the
       * interface it leaves through. */
      vnet_buffer (b)->sw_if_index[VLIB_TX] = desc->sw_if_index;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = desc->sw_if_index;

      if (PREDICT_FALSE (n_trace > 0 &&
			 vlib_trace_buffer (vm, node, 0, b, 0 /* chain */)))
	{
	  osvbng_egress_trace_t *t =
	    vlib_add_trace (vm, node, b, sizeof (*t));
	  t->sw_if_index = desc->sw_if_index;
	  t->data_length = desc->data_length;
	  vlib_set_trace_count (vm, node, --n_trace);
	}

      u32 out_node = hw->output_node_index;
      osvbng_egress_pending_t *p = NULL;
      for (u32 i = 0; i < n_pending; i++)
	{
	  if (pending[i].output_node_index == out_node)
	    {
	      p = &pending[i];
	      break;
	    }
	}

      if (!p)
	{
	  if (PREDICT_FALSE (n_pending >= OSVBNG_EGRESS_MAX_IFS))
	    {
	      vlib_frame_t *f = vlib_get_frame_to_node (vm, out_node);
	      u32 *to_next = vlib_frame_vector_args (f);
	      to_next[0] = bi;
	      f->n_vectors = 1;
	      vlib_put_frame_to_node (vm, out_node, f);
	      tail++;
	      n_tx++;
	      continue;
	    }
	  p = &pending[n_pending++];
	  p->output_node_index = out_node;
	  p->f = vlib_get_frame_to_node (vm, out_node);
	  p->to_next = vlib_frame_vector_args (p->f);
	  p->n_vectors = 0;
	}

      p->to_next[p->n_vectors++] = bi;

      if (PREDICT_FALSE (p->n_vectors >= VLIB_FRAME_SIZE))
	{
	  p->f->n_vectors = p->n_vectors;
	  vlib_put_frame_to_node (vm, p->output_node_index, p->f);
	  *p = pending[--n_pending];
	}

      tail++;
      n_tx++;
    }

  for (u32 i = 0; i < n_pending; i++)
    {
      pending[i].f->n_vectors = pending[i].n_vectors;
      vlib_put_frame_to_node (vm, pending[i].output_node_index,
			      pending[i].f);
    }

  /* Update our local tail and publish it */
  pm->egress_tail = tail;
  atomic_store_explicit (&ring->tail, tail, memory_order_release);

  /* Clear interrupt pending flag */
  atomic_store_explicit (&ring->interrupt_pending, 0, memory_order_release);

  /* The batch cap can leave frames in the ring, and the daemon only
   * signals on the flag's 0 to 1 edge, so without this self-interrupt
   * a burst larger than one batch would strand its tail until the next
   * inject arrives. Also covers a frame enqueued between the drain and
   * the flag clear. */
  if (atomic_load_explicit (&ring->head, memory_order_acquire) != tail)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  pm->egress_transmitted += n_tx;

  return n_tx;
}

VLIB_REGISTER_NODE (osvbng_egress_node) = {
  .name = "osvbng-egress",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
  /* Without this an input node refuses `trace add`, and injection is
   * exactly the path an operator wants to trace when a control reply
   * does not reach a subscriber. */
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
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
