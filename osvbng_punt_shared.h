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

#ifndef __OSVBNG_PUNT_SHARED_H__
#define __OSVBNG_PUNT_SHARED_H__

#include <stdint.h>
#include <stdatomic.h>

/*
 * Shared memory layout for osvbng <-> VPP communication
 *
 * This provides a high-performance, lock-free mechanism for:
 * - Punt: VPP -> osvbng (control packets like ARP, DHCP, PPPoE)
 * - Egress: osvbng -> VPP (control packet responses)
 *
 * Based on VPP's snort plugin architecture with lock-free SPSC rings.
 */

#define OSVBNG_SHM_MAGIC      0x4F53564E47424E47ULL  /* "OSVBNGBN" */
#define OSVBNG_SHM_VERSION    1

/* Default ring sizes (must be power of 2) */
#define OSVBNG_SHM_DEFAULT_PUNT_RING_SIZE    4096
#define OSVBNG_SHM_DEFAULT_EGRESS_RING_SIZE  4096
#define OSVBNG_SHM_DEFAULT_DATA_SLOTS        8192
#define OSVBNG_SHM_DEFAULT_SLOT_SIZE         2048

/* Well-known paths */
#define OSVBNG_SHM_PATH          "/dev/shm/osvbng-dataplane"
#define OSVBNG_SHM_PUNT_EVT_PATH "/run/vpp/osvbng-punt.evt"
#define OSVBNG_SHM_EGRESS_EVT_PATH "/run/vpp/osvbng-egress.evt"

/*
 * Shared memory header - placed at offset 0
 * Cache-line aligned (64 bytes) to prevent false sharing
 */
typedef struct
{
  uint64_t magic;                /* OSVBNG_SHM_MAGIC */
  uint32_t version;              /* OSVBNG_SHM_VERSION */
  uint32_t flags;                /* Reserved for future use */
  uint32_t punt_ring_offset;     /* Offset to punt ring header */
  uint32_t punt_ring_size;       /* Number of punt descriptors */
  uint32_t egress_ring_offset;   /* Offset to egress ring header */
  uint32_t egress_ring_size;     /* Number of egress descriptors */
  uint32_t data_region_offset;   /* Offset to data region */
  uint32_t data_region_size;     /* Total data region size in bytes */
  uint32_t slot_size;            /* Size of each data slot */
  uint32_t punt_data_slots;      /* Number of data slots for punt */
  uint32_t egress_data_slots;    /* Number of data slots for egress */
  uint8_t reserved[12];          /* Pad to 64 bytes */
} __attribute__ ((aligned (64))) osvbng_shm_header_t;

_Static_assert (sizeof (osvbng_shm_header_t) == 64,
		"shm header must be 64 bytes");

/*
 * Ring header for both punt and egress rings
 * Cache-line aligned to prevent false sharing between head/tail
 *
 * Producer writes head, consumer reads head
 * Consumer writes tail, producer reads tail
 * interrupt_pending is used for eventfd coalescing
 */
typedef struct
{
  _Atomic uint64_t head;         /* Next slot to write (producer) */
  _Atomic uint64_t tail;         /* Next slot to read (consumer) */
  _Atomic uint8_t interrupt_pending; /* 1 if eventfd write pending */
  uint8_t reserved[47];          /* Pad to 64 bytes */
} __attribute__ ((aligned (64))) osvbng_ring_header_t;

_Static_assert (sizeof (osvbng_ring_header_t) == 64,
		"ring header must be 64 bytes");

/*
 * Punt descriptor - describes a packet punted from VPP to osvbng
 * 32 bytes for cache efficiency
 */
typedef struct
{
  uint32_t data_offset;          /* Offset from shm base to frame data */
  uint16_t data_length;          /* Frame length (including L2 header) */
  uint32_t sw_if_index;          /* VPP software interface index */
  uint8_t protocol;              /* osvbng_punt_protocol_t */
  uint8_t flags;                 /* Reserved flags */
  uint16_t outer_vlan;           /* Outer VLAN tag (0 if none) */
  uint16_t inner_vlan;           /* Inner VLAN tag (0 if none) */
  uint64_t timestamp;            /* VPP timestamp (nanoseconds) */
  uint8_t reserved[6];           /* Pad to 32 bytes */
} __attribute__ ((packed)) osvbng_punt_desc_t;

_Static_assert (sizeof (osvbng_punt_desc_t) == 32,
		"punt descriptor must be 32 bytes");

/*
 * Egress descriptor - describes a packet to transmit from osvbng
 * 32 bytes for cache efficiency
 */
typedef struct
{
  uint32_t data_offset;          /* Offset from shm base to frame data */
  uint16_t data_length;          /* Frame length (including L2 header) */
  uint32_t sw_if_index;          /* Target VPP interface for TX */
  uint8_t reserved[22];          /* Pad to 32 bytes */
} __attribute__ ((packed)) osvbng_egress_desc_t;

_Static_assert (sizeof (osvbng_egress_desc_t) == 32,
		"egress descriptor must be 32 bytes");

/*
 * Helper macros for ring operations
 */
#define OSVBNG_RING_MASK(size) ((size) - 1)

/* Check if ring has space for n entries */
static inline int
osvbng_ring_has_space (osvbng_ring_header_t *ring, uint32_t ring_size,
		       uint32_t n)
{
  uint64_t head = atomic_load_explicit (&ring->head, memory_order_relaxed);
  uint64_t tail = atomic_load_explicit (&ring->tail, memory_order_acquire);
  return (head - tail + n) <= ring_size;
}

/* Check if ring has n entries available to read */
static inline int
osvbng_ring_has_data (osvbng_ring_header_t *ring, uint32_t n)
{
  uint64_t head = atomic_load_explicit (&ring->head, memory_order_acquire);
  uint64_t tail = atomic_load_explicit (&ring->tail, memory_order_relaxed);
  return (head - tail) >= n;
}

/* Get number of entries in ring */
static inline uint64_t
osvbng_ring_count (osvbng_ring_header_t *ring)
{
  uint64_t head = atomic_load_explicit (&ring->head, memory_order_acquire);
  uint64_t tail = atomic_load_explicit (&ring->tail, memory_order_relaxed);
  return head - tail;
}

/*
 * Calculate total shared memory size needed
 */
static inline uint32_t
osvbng_shm_calc_size (uint32_t punt_ring_size, uint32_t egress_ring_size,
		      uint32_t data_slots, uint32_t slot_size)
{
  uint32_t size = 0;

  /* Header */
  size += sizeof (osvbng_shm_header_t);

  /* Punt ring: header + descriptors */
  size += sizeof (osvbng_ring_header_t);
  size += punt_ring_size * sizeof (osvbng_punt_desc_t);

  /* Egress ring: header + descriptors */
  size += sizeof (osvbng_ring_header_t);
  size += egress_ring_size * sizeof (osvbng_egress_desc_t);

  /* Data region */
  size += data_slots * slot_size;

  return size;
}

#endif /* __OSVBNG_PUNT_SHARED_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
