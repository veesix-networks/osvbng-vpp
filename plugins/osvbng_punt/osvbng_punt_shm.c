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

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/file.h>
#include <vnet/vnet.h>
#include <vlib/global_funcs.h>

#include <osvbng_punt/osvbng_punt.h>
#include <osvbng_punt/osvbng_punt_shared.h>

/* Forward declarations */
static clib_error_t *osvbng_punt_eventfd_connect_handler (clib_file_t *f);

/*
 * Initialize shared memory region
 * Called during plugin initialization
 */
int
osvbng_punt_shm_init (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  osvbng_shm_header_t *hdr;
  int fd;
  uint32_t shm_size;
  uint32_t offset;

  /* Use defaults if not configured */
  if (pm->punt_ring_size == 0)
    pm->punt_ring_size = OSVBNG_SHM_DEFAULT_PUNT_RING_SIZE;
  if (pm->egress_ring_size == 0)
    pm->egress_ring_size = OSVBNG_SHM_DEFAULT_EGRESS_RING_SIZE;
  if (pm->slot_size == 0)
    pm->slot_size = OSVBNG_SHM_DEFAULT_SLOT_SIZE;

  /* One punt ring per VPP thread: the count is only known once the
   * threads exist, which is why shm init runs at main-loop entry. */
  pm->n_punt_rings = vlib_get_n_threads ();
  pm->punt_ring_stride = osvbng_punt_ring_stride (pm->punt_ring_size);

  /* Calculate total shared memory size */
  shm_size =
    osvbng_shm_calc_size (pm->n_punt_rings, pm->punt_ring_size,
			  pm->egress_ring_size, pm->slot_size);

  vlib_log_info (pm->log_class, "creating shared memory: size=%u bytes",
		 shm_size);

  /* Remove any existing shm file */
  unlink (OSVBNG_SHM_PATH);

  /* Create shared memory file */
  fd = open (OSVBNG_SHM_PATH, O_CREAT | O_RDWR | O_TRUNC, 0600);
  if (fd < 0)
    {
      vlib_log_err (pm->log_class, "failed to create shm file %s: %s",
		    OSVBNG_SHM_PATH, strerror (errno));
      return -1;
    }

  /* Set size */
  if (ftruncate (fd, shm_size) < 0)
    {
      vlib_log_err (pm->log_class, "ftruncate failed: %s", strerror (errno));
      close (fd);
      return -1;
    }

  /* Map shared memory */
  pm->shm =
    mmap (NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (pm->shm == MAP_FAILED)
    {
      vlib_log_err (pm->log_class, "mmap failed: %s", strerror (errno));
      close (fd);
      return -1;
    }

  pm->shm_fd = fd;
  pm->shm_size = shm_size;

  /* Initialize header */
  hdr = (osvbng_shm_header_t *) pm->shm;
  clib_memset (hdr, 0, sizeof (*hdr));
  hdr->magic = OSVBNG_SHM_MAGIC;
  hdr->version = OSVBNG_SHM_VERSION;
  hdr->n_punt_rings = pm->n_punt_rings;
  hdr->punt_ring_size = pm->punt_ring_size;
  hdr->punt_ring_stride = pm->punt_ring_stride;
  hdr->egress_ring_size = pm->egress_ring_size;
  hdr->slot_size = pm->slot_size;

  offset = sizeof (osvbng_shm_header_t);

  /* N punt rings, one per thread. */
  hdr->punt_ring_offset = offset;
  offset += pm->n_punt_rings * pm->punt_ring_stride;

  /* Single egress ring. */
  hdr->egress_ring_offset = offset;
  pm->egress_ring = (osvbng_ring_header_t *) ((u8 *) pm->shm + offset);
  clib_memset (pm->egress_ring, 0, sizeof (osvbng_ring_header_t));
  offset += sizeof (osvbng_ring_header_t);
  pm->egress_descs = (osvbng_egress_desc_t *) ((u8 *) pm->shm + offset);
  offset += pm->egress_ring_size * sizeof (osvbng_egress_desc_t);

  /* Data slots: punt (all rings) then egress. */
  hdr->punt_data_offset = offset;
  pm->punt_data_offset = offset;
  offset += pm->n_punt_rings * pm->punt_ring_size * pm->slot_size;
  hdr->egress_data_offset = offset;
  pm->egress_data_offset = offset;

  /* Per-thread ring/desc/data pointers: after this, the punt path
   * never touches memory another thread writes. */
  vec_validate_aligned (pm->per_thread, pm->n_punt_rings - 1,
			CLIB_CACHE_LINE_BYTES);
  for (u32 t = 0; t < pm->n_punt_rings; t++)
    {
      osvbng_punt_per_thread_t *pt = vec_elt_at_index (pm->per_thread, t);
      u8 *ring_base =
	(u8 *) pm->shm + hdr->punt_ring_offset + t * pm->punt_ring_stride;

      pt->ring = (osvbng_ring_header_t *) ring_base;
      pt->descs =
	(osvbng_punt_desc_t *) (ring_base + sizeof (osvbng_ring_header_t));
      pt->data = (u8 *) pm->shm + pm->punt_data_offset +
		 (u64) t * pm->punt_ring_size * pm->slot_size;
      clib_memset (pt->ring, 0, sizeof (*pt->ring));
    }

  vlib_log_info (pm->log_class,
		 "shm layout v%u: %u punt ring(s) of %u @%u stride %u, "
		 "egress %u @%u, slot %u",
		 hdr->version, hdr->n_punt_rings, hdr->punt_ring_size,
		 hdr->punt_ring_offset, hdr->punt_ring_stride,
		 hdr->egress_ring_size, hdr->egress_ring_offset,
		 hdr->slot_size);

  /* Create eventfds */
  pm->punt_eventfd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (pm->punt_eventfd < 0)
    {
      vlib_log_err (pm->log_class, "punt eventfd failed: %s",
		    strerror (errno));
      return -1;
    }

  pm->egress_eventfd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (pm->egress_eventfd < 0)
    {
      vlib_log_err (pm->log_class, "egress eventfd failed: %s",
		    strerror (errno));
      close (pm->punt_eventfd);
      return -1;
    }

  pm->shm_initialized = 1;

  vlib_log_notice (pm->log_class,
		   "shared memory initialized: %s (size=%u, punt_fd=%d, "
		   "egress_fd=%d)",
		   OSVBNG_SHM_PATH, shm_size, pm->punt_eventfd,
		   pm->egress_eventfd);

  return 0;
}

/*
 * Create Unix socket to pass eventfds to osvbng
 * osvbng connects and receives the eventfds via SCM_RIGHTS
 */
int
osvbng_punt_eventfd_socket_init (vlib_main_t *vm)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  struct sockaddr_un addr;
  int fd;

  if (!pm->shm_initialized)
    {
      vlib_log_err (pm->log_class, "shm not initialized");
      return -1;
    }

  /* Remove any existing socket */
  unlink (OSVBNG_SHM_PUNT_EVT_PATH);

  /* Create Unix socket for eventfd passing */
  fd = socket (AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0)
    {
      vlib_log_err (pm->log_class, "socket() failed: %s", strerror (errno));
      return -1;
    }

  clib_memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, OSVBNG_SHM_PUNT_EVT_PATH, sizeof (addr.sun_path) - 1);

  if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    {
      vlib_log_err (pm->log_class, "bind() failed: %s", strerror (errno));
      close (fd);
      return -1;
    }

  if (listen (fd, 1) < 0)
    {
      vlib_log_err (pm->log_class, "listen() failed: %s", strerror (errno));
      close (fd);
      return -1;
    }

  /* Register with VPP file polling */
  clib_file_t cf = {
    .read_function = osvbng_punt_eventfd_connect_handler,
    .file_descriptor = fd,
    .description = format (0, "osvbng-eventfd-listen"),
  };
  pm->eventfd_listen_file_index = clib_file_add (&file_main, &cf);
  pm->eventfd_listen_fd = fd;

  vlib_log_notice (pm->log_class, "eventfd socket listening: %s",
		   OSVBNG_SHM_PUNT_EVT_PATH);

  return 0;
}

/*
 * Handle incoming connection from osvbng
 * Send the punt and egress eventfds via SCM_RIGHTS
 */
static clib_error_t *
osvbng_punt_eventfd_connect_handler (clib_file_t *f)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  int client_fd;
  struct sockaddr_un client_addr;
  socklen_t client_len = sizeof (client_addr);

  client_fd = accept (f->file_descriptor, (struct sockaddr *) &client_addr,
		      &client_len);
  if (client_fd < 0)
    {
      if (errno != EAGAIN && errno != EWOULDBLOCK)
	vlib_log_err (pm->log_class, "accept() failed: %s", strerror (errno));
      return 0;
    }

  vlib_log_info (pm->log_class, "osvbng connected, sending eventfds...");

  /* Send eventfds via SCM_RIGHTS */
  struct msghdr msg = { 0 };
  struct iovec iov;
  char buf[1] = { 'O' }; /* Just a marker byte */
  int fds[2] = { pm->punt_eventfd, pm->egress_eventfd };
  char cmsg_buf[CMSG_SPACE (sizeof (fds))];

  iov.iov_base = buf;
  iov.iov_len = sizeof (buf);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buf;
  msg.msg_controllen = sizeof (cmsg_buf);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR (&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN (sizeof (fds));
  clib_memcpy (CMSG_DATA (cmsg), fds, sizeof (fds));

  if (sendmsg (client_fd, &msg, 0) < 0)
    {
      vlib_log_err (pm->log_class, "sendmsg() failed: %s", strerror (errno));
      close (client_fd);
      return 0;
    }

  pm->client_connected = 1;
  vlib_log_notice (pm->log_class,
		   "eventfds sent to osvbng (punt_fd=%d, egress_fd=%d)",
		   pm->punt_eventfd, pm->egress_eventfd);

  close (client_fd);
  return 0;
}

/*
 * Cleanup shared memory resources
 */
void
osvbng_punt_shm_cleanup (void)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (pm->egress_file_index != ~0)
    {
      clib_file_del (&file_main, clib_file_get (&file_main,
						pm->egress_file_index));
      pm->egress_file_index = ~0;
    }

  if (pm->eventfd_listen_file_index != ~0)
    {
      clib_file_del (&file_main, clib_file_get (&file_main,
						pm->eventfd_listen_file_index));
      pm->eventfd_listen_file_index = ~0;
    }

  if (pm->eventfd_listen_fd >= 0)
    {
      close (pm->eventfd_listen_fd);
      pm->eventfd_listen_fd = -1;
      unlink (OSVBNG_SHM_PUNT_EVT_PATH);
    }

  if (pm->punt_eventfd >= 0)
    {
      close (pm->punt_eventfd);
      pm->punt_eventfd = -1;
    }

  if (pm->egress_eventfd >= 0)
    {
      close (pm->egress_eventfd);
      pm->egress_eventfd = -1;
    }

  if (pm->shm != NULL && pm->shm != MAP_FAILED)
    {
      munmap (pm->shm, pm->shm_size);
      pm->shm = NULL;
    }

  if (pm->shm_fd >= 0)
    {
      close (pm->shm_fd);
      pm->shm_fd = -1;
      unlink (OSVBNG_SHM_PATH);
    }

  pm->shm_initialized = 0;
  pm->client_connected = 0;
}

/*
 * Punt a packet to shared memory (replaces socket-based punt)
 */
int
osvbng_punt_to_shm (vlib_main_t *vm, vlib_buffer_t *b, u32 sw_if_index,
		    osvbng_punt_protocol_t protocol, u16 outer_vlan,
		    u16 inner_vlan)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;
  osvbng_punt_per_thread_t *pt;
  osvbng_ring_header_t *ring;
  osvbng_punt_desc_t *desc;
  uint64_t head, tail, mask;
  uint32_t slot;
  u16 len;
  f64 now;

  if (PREDICT_FALSE (!pm->shm_initialized))
    return -1;

  /* Write only this thread's ring: single writer, no cross-worker
   * cache line, no locks (v2 shm, per-worker rings). */
  pt = osvbng_punt_get_per_thread (vm);
  now = vlib_time_now (vm);

  if (PREDICT_FALSE (!osvbng_punt_policer_allow (pt, now, protocol)))
    return -1;

  ring = pt->ring;
  mask = pm->punt_ring_size - 1;

  head = atomic_load_explicit (&ring->head, memory_order_relaxed);
  tail = atomic_load_explicit (&ring->tail, memory_order_acquire);

  if (PREDICT_FALSE ((head - tail) >= pm->punt_ring_size))
    {
      pt->ring_full++;
      pt->dropped[protocol]++;
      return -1;
    }

  slot = head & mask;
  desc = &pt->descs[slot];

  len = b->current_length;
  if (PREDICT_FALSE (len > pm->slot_size))
    {
      len = pm->slot_size;
      pt->truncated++;
    }
  clib_memcpy_fast (pt->data + (u64) slot * pm->slot_size,
		    vlib_buffer_get_current (b), len);

  desc->data_offset =
    (u32) ((pt->data - (u8 *) pm->shm) + (u64) slot * pm->slot_size);
  desc->data_length = len;
  desc->sw_if_index = sw_if_index;
  desc->protocol = protocol;
  desc->flags = 0;
  desc->outer_vlan = outer_vlan;
  desc->inner_vlan = inner_vlan;
  desc->timestamp = (uint64_t) (now * 1e9);

  /* Release: the descriptor and its frame must be visible before head. */
  atomic_store_explicit (&ring->head, head + 1, memory_order_release);

  /* One shared punt eventfd: any worker signals it on its ring's
   * 0 to 1 edge, the daemon wakes and drains every ring. */
  if (atomic_exchange_explicit (&ring->interrupt_pending, 1,
				memory_order_acq_rel) == 0)
    {
      uint64_t val = 1;
      CLIB_UNUSED (ssize_t written) = write (pm->punt_eventfd, &val,
					     sizeof (val));
    }

  pt->punted[protocol]++;
  return 0;
}

/*
 * CLI command to show shared memory status
 */
static clib_error_t *
osvbng_punt_show_shm_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  osvbng_punt_main_t *pm = &osvbng_punt_main;

  if (!pm->shm_initialized)
    {
      vlib_cli_output (vm, "Shared memory: NOT INITIALIZED");
      return 0;
    }

  osvbng_shm_header_t *hdr = (osvbng_shm_header_t *) pm->shm;

  vlib_cli_output (vm, "OSVBNG Shared Memory Status:");
  vlib_cli_output (vm, "  Path: %s", OSVBNG_SHM_PATH);
  vlib_cli_output (vm, "  Size: %u bytes", pm->shm_size);
  vlib_cli_output (vm, "  Magic: 0x%llx (valid=%s)", hdr->magic,
		   hdr->magic == OSVBNG_SHM_MAGIC ? "yes" : "NO");
  vlib_cli_output (vm, "  Version: %u", hdr->version);
  vlib_cli_output (vm, "  Client connected: %s",
		   pm->client_connected ? "yes" : "no");
  vlib_cli_output (vm, "");

  vlib_cli_output (vm, "Punt Rings: %u (one per thread), %u descriptors each",
		   pm->n_punt_rings, pm->punt_ring_size);
  for (u32 t = 0; t < pm->n_punt_rings; t++)
    {
      osvbng_punt_per_thread_t *pt = vec_elt_at_index (pm->per_thread, t);
      vlib_cli_output (
	vm, "  [%u] head %llu tail %llu pending %llu ring-full %llu trunc %llu",
	t, atomic_load_explicit (&pt->ring->head, memory_order_relaxed),
	atomic_load_explicit (&pt->ring->tail, memory_order_relaxed),
	osvbng_ring_count (pt->ring), pt->ring_full, pt->truncated);
    }
  vlib_cli_output (vm, "");

  vlib_cli_output (vm, "Egress Ring:");
  vlib_cli_output (vm, "  Size: %u descriptors", pm->egress_ring_size);
  vlib_cli_output (vm, "  Head: %llu",
		   atomic_load_explicit (&pm->egress_ring->head,
					 memory_order_relaxed));
  vlib_cli_output (vm, "  Tail: %llu",
		   atomic_load_explicit (&pm->egress_ring->tail,
					 memory_order_relaxed));
  vlib_cli_output (vm, "  Pending: %llu", osvbng_ring_count (pm->egress_ring));
  vlib_cli_output (vm, "  Transmitted: %llu", pm->egress_transmitted);
  vlib_cli_output (vm, "  Alloc failures: %llu", pm->egress_alloc_fail);

  return 0;
}

VLIB_CLI_COMMAND (osvbng_punt_show_shm_command, static) = {
  .path = "show osvbng punt shm",
  .short_help = "show osvbng punt shm",
  .function = osvbng_punt_show_shm_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
