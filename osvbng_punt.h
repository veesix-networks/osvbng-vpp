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
#include <vnet/ip/punt.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>

/* Protocol identifiers for punted packets */
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

/* Packet metadata header sent to userspace via Unix socket */
typedef struct __attribute__ ((packed))
{
  u32 sw_if_index;      /* RX interface index */
  u8 protocol;          /* osvbng_punt_protocol_t */
  u8 direction;         /* 0=RX, 1=TX (future use) */
  u16 data_len;         /* Length of packet data following this header */
  u64 timestamp_ns;     /* Nanosecond timestamp */
} osvbng_punt_packet_header_t;

/* Configuration for each protocol type */
typedef struct
{
  u16 ethertype;        /* For L2 protocols (0x0806=ARP, 0x8863=PPPoE) */
  u8 ip_protocol;       /* For L3/L4 protocols (17=UDP, 58=ICMPv6) */
  u16 l4_port;          /* For UDP/TCP protocols (67=DHCP, 1701=L2TP) */
  u8 use_feature_arc;   /* true=feature arc, false=VPP native punt */
  char *arc_name;       /* Feature arc name ("arp", "ethernet-input") */
  char *node_name;      /* Node name for this protocol */
} osvbng_punt_proto_config_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* Per-interface, per-protocol enable bitmap */
  /* enabled_interfaces[protocol] is a hash of sw_if_index -> 1 */
  uword *enabled_interfaces[OSVBNG_PUNT_N_PROTO];

  /* Destination socket path (Go daemon binds this) */
  u8 *socket_path;
  int socket_fd;

  /* Destination address for sendto() */
  struct sockaddr_un dest_addr;

  /* Protocol configurations */
  osvbng_punt_proto_config_t proto_configs[OSVBNG_PUNT_N_PROTO];

  /* Statistics - packets punted per protocol */
  u64 packets_punted[OSVBNG_PUNT_N_PROTO];
  u64 packets_dropped[OSVBNG_PUNT_N_PROTO];

  /* Convenience */
  vnet_main_t *vnet_main;
  vlib_main_t *vlib_main;
} osvbng_punt_main_t;

extern osvbng_punt_main_t osvbng_punt_main;

/* Node registrations for each protocol */
extern vlib_node_registration_t osvbng_punt_arp_node;
extern vlib_node_registration_t osvbng_punt_dhcp_node;
extern vlib_node_registration_t osvbng_punt_pppoe_disc_node;
extern vlib_node_registration_t osvbng_punt_pppoe_sess_node;
extern vlib_node_registration_t osvbng_punt_l2tp_node;
extern vlib_node_registration_t osvbng_punt_ipv6_nd_node;

/* Enable/disable punt on an interface for a specific protocol */
int osvbng_punt_enable_disable (u32 sw_if_index,
				osvbng_punt_protocol_t protocol,
				u8 *socket_path, int enable_disable);

/* Send packet to userspace via socket */
int osvbng_punt_send_packet (vlib_buffer_t * b, u32 sw_if_index,
			     osvbng_punt_protocol_t protocol);

/* Initialize socket infrastructure */
int osvbng_punt_socket_init (u8 * socket_path);

/* Protocol-specific enable/disable functions */
int osvbng_punt_enable_dhcpv4 (u32 sw_if_index, u8 *socket_path);
int osvbng_punt_disable_dhcpv4 (u32 sw_if_index);
int osvbng_punt_enable_l2tp (u32 sw_if_index, u8 *socket_path);
int osvbng_punt_disable_l2tp (u32 sw_if_index);
int osvbng_punt_enable_ipv6_nd (u32 sw_if_index, u8 *socket_path);
int osvbng_punt_disable_ipv6_nd (u32 sw_if_index);

#endif /* __OSVBNG_PUNT_H__ */
