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

  u8 *socket_path;
  int socket_fd;

  struct sockaddr_un dest_addr;

  u32 original_arp_node;
  u32 original_pppoe_disc_node;
  u32 original_pppoe_sess_node;

  u64 packets_punted[OSVBNG_PUNT_N_PROTO];
  u64 packets_dropped[OSVBNG_PUNT_N_PROTO];

  vnet_main_t *vnet_main;
  vlib_main_t *vlib_main;
} osvbng_punt_main_t;

extern osvbng_punt_main_t osvbng_punt_main;

extern vlib_node_registration_t osvbng_punt_arp_node;
extern vlib_node_registration_t osvbng_punt_dhcp_node;
extern vlib_node_registration_t osvbng_punt_pppoe_disc_node;
extern vlib_node_registration_t osvbng_punt_pppoe_sess_node;
extern vlib_node_registration_t osvbng_punt_l2tp_node;
extern vlib_node_registration_t osvbng_punt_ipv6_nd_node;

int osvbng_punt_enable_disable (u32 sw_if_index,
				osvbng_punt_protocol_t protocol,
				u8 *socket_path, int enable_disable);

int osvbng_punt_send_packet (vlib_buffer_t * b, u32 sw_if_index,
			     osvbng_punt_protocol_t protocol);

int osvbng_punt_socket_init (u8 * socket_path);

int osvbng_punt_enable_dhcpv4 (u32 sw_if_index, u8 *socket_path);
int osvbng_punt_disable_dhcpv4 (u32 sw_if_index);
int osvbng_punt_enable_l2tp (u32 sw_if_index, u8 *socket_path);
int osvbng_punt_disable_l2tp (u32 sw_if_index);
int osvbng_punt_enable_ipv6_nd (u32 sw_if_index, u8 *socket_path);
int osvbng_punt_disable_ipv6_nd (u32 sw_if_index);

#endif /* __OSVBNG_PUNT_H__ */
