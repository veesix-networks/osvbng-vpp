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

#ifndef __OSVBNG_PUNT_H__
#define __OSVBNG_PUNT_H__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include <osvbng_punt/osvbng_punt_shared.h>

typedef enum
{
  OSVBNG_PUNT_PROTO_DHCPV4 = 0,
  OSVBNG_PUNT_PROTO_DHCPV6 = 1,
  OSVBNG_PUNT_PROTO_ARP = 2,
  OSVBNG_PUNT_PROTO_PPPOE_DISCOVERY = 3,
  OSVBNG_PUNT_PROTO_PPPOE_SESSION = 4,
  OSVBNG_PUNT_PROTO_IPV6_ND = 5,
  OSVBNG_PUNT_PROTO_L2TP = 6,
  OSVBNG_PUNT_N_PROTO,
} osvbng_punt_protocol_t;

typedef struct
{
  f64 rate;
  u32 burst;
  f64 tokens;
  f64 last_update;
  u64 policed;
} osvbng_punt_policer_t;

typedef struct __attribute__ ((packed))
{
  u32 sw_if_index;
  u8 protocol;
  u8 direction;
  u16 data_len;
  u64 timestamp_ns;
} osvbng_punt_packet_header_t;

typedef struct
{
  u16 msg_id_base;

  uword *enabled_interfaces[OSVBNG_PUNT_N_PROTO];

  /* Shared memory dataplane */
  void *shm;                           /* mmap'd shared memory region */
  int shm_fd;                          /* shared memory file descriptor */
  u32 shm_size;                        /* total shm size in bytes */
  u8 shm_initialized;                  /* 1 if shm is ready */
  u8 client_connected;                 /* 1 if osvbng has connected */

  /* Ring configuration */
  u32 punt_ring_size;                  /* number of punt descriptors */
  u32 egress_ring_size;                /* number of egress descriptors */
  u32 data_slots;                      /* total data slots */
  u32 slot_size;                       /* size of each data slot */
  u32 punt_data_slots;                 /* data slots for punt */
  u32 egress_data_slots;               /* data slots for egress */
  u32 egress_data_offset;              /* offset to egress data region */

  /* Ring pointers (into shm) */
  osvbng_ring_header_t *punt_ring;     /* punt ring header */
  osvbng_punt_desc_t *punt_descs;      /* punt descriptors array */
  osvbng_ring_header_t *egress_ring;   /* egress ring header */
  osvbng_egress_desc_t *egress_descs;  /* egress descriptors array */
  u8 *data_region;                     /* data region start */

  /* Eventfds for signaling */
  int punt_eventfd;                    /* VPP writes, osvbng reads */
  int egress_eventfd;                  /* osvbng writes, VPP reads */

  /* Eventfd socket for passing fds to osvbng */
  int eventfd_listen_fd;
  u32 eventfd_listen_file_index;
  u32 egress_file_index;

  /* Egress state */
  u64 egress_tail;                     /* local copy of egress tail */

  /* Statistics */
  u64 punt_ring_full;                  /* punt ring full drops */
  u64 punt_truncated;                  /* packets truncated */
  u64 egress_transmitted;              /* packets transmitted */
  u64 egress_alloc_fail;               /* buffer allocation failures */

  u32 original_arp_node;
  u32 original_pppoe_disc_node;
  u32 original_pppoe_sess_node;

  u64 packets_punted[OSVBNG_PUNT_N_PROTO];
  u64 packets_dropped[OSVBNG_PUNT_N_PROTO];

  osvbng_punt_policer_t policers[OSVBNG_PUNT_N_PROTO];

  vlib_log_class_t log_class;
  vnet_main_t *vnet_main;
  vlib_main_t *vlib_main;
} osvbng_punt_main_t;

extern osvbng_punt_main_t osvbng_punt_main;

extern vlib_node_registration_t osvbng_punt_arp_node;
extern vlib_node_registration_t osvbng_punt_dhcp_node;
extern vlib_node_registration_t osvbng_punt_dhcp6_node;
extern vlib_node_registration_t osvbng_punt_pppoe_disc_node;
extern vlib_node_registration_t osvbng_punt_pppoe_sess_node;
extern vlib_node_registration_t osvbng_punt_l2tp_node;
extern vlib_node_registration_t osvbng_punt_ipv6_nd_node;

int osvbng_punt_enable_disable (u32 sw_if_index,
				osvbng_punt_protocol_t protocol,
				int enable_disable);

int osvbng_punt_enable_dhcpv4 (u32 sw_if_index);
int osvbng_punt_disable_dhcpv4 (u32 sw_if_index);
int osvbng_punt_enable_dhcpv6 (u32 sw_if_index);
int osvbng_punt_disable_dhcpv6 (u32 sw_if_index);
int osvbng_punt_enable_l2tp (u32 sw_if_index);
int osvbng_punt_disable_l2tp (u32 sw_if_index);
int osvbng_punt_enable_ipv6_nd (u32 sw_if_index);
int osvbng_punt_disable_ipv6_nd (u32 sw_if_index);

/* Control plane policing */
void osvbng_punt_policer_init (void);
int osvbng_punt_policer_configure (osvbng_punt_protocol_t protocol, f64 rate,
				   u32 burst);
int osvbng_punt_policer_allow (osvbng_punt_protocol_t protocol);

/* Shared memory functions */
int osvbng_punt_shm_init (vlib_main_t *vm);
int osvbng_punt_eventfd_socket_init (vlib_main_t *vm);
int osvbng_punt_egress_init (vlib_main_t *vm);
void osvbng_punt_shm_cleanup (void);
int osvbng_punt_to_shm (vlib_main_t *vm, vlib_buffer_t *b, u32 sw_if_index,
			osvbng_punt_protocol_t protocol, u16 outer_vlan,
			u16 inner_vlan);

/* Wrapper for punt nodes - calls osvbng_punt_to_shm with zero VLANs */
static inline int
osvbng_punt_send_packet (vlib_main_t *vm, vlib_buffer_t *b, u32 sw_if_index,
			 osvbng_punt_protocol_t protocol)
{
  return osvbng_punt_to_shm (vm, b, sw_if_index, protocol, 0, 0);
}

/* Egress node registration */
extern vlib_node_registration_t osvbng_egress_node;

#endif /* __OSVBNG_PUNT_H__ */
