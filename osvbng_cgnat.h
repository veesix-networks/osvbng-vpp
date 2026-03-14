/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin
 * Carrier-Grade NAT with PBA and Deterministic modes.
 */

#ifndef __included_osvbng_cgnat_h__
#define __included_osvbng_cgnat_h__

#include <vnet/plugin/plugin.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vlib/vlib.h>

#define CGNAT_ALG_FTP  (1 << 0)
#define CGNAT_ALG_TFTP (1 << 1)
#define CGNAT_ALG_PPTP (1 << 2)
#define CGNAT_ALG_SIP  (1 << 3)
#define CGNAT_ALG_RTSP (1 << 4)
#define CGNAT_ALG_DNS  (1 << 5)

#define CGNAT_PROTO_TCP  0
#define CGNAT_PROTO_UDP  1
#define CGNAT_PROTO_ICMP 2
#define CGNAT_PROTO_OTHER 3
#define CGNAT_N_PROTOS 4

typedef enum
{
  CGNAT_POOL_MODE_PBA = 0,
  CGNAT_POOL_MODE_DETERMINISTIC = 1,
} cgnat_pool_mode_t;

typedef enum
{
  CGNAT_ADDRESS_POOLING_PAIRED = 0,
  CGNAT_ADDRESS_POOLING_ARBITRARY = 1,
} cgnat_address_pooling_t;

typedef enum
{
  CGNAT_FILTERING_ENDPOINT_INDEPENDENT = 0,
  CGNAT_FILTERING_ENDPOINT_DEPENDENT = 1,
} cgnat_filtering_t;

typedef enum
{
#define cgnat_error(n, s) CGNAT_ERROR_##n,
#include <osvbng_cgnat/osvbng_cgnat_error.def>
#undef cgnat_error
  CGNAT_N_ERROR,
} cgnat_error_t;

extern char *cgnat_error_strings[];

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ip4_address_t inside_ip;
  ip4_address_t outside_ip;
  ip4_address_t remote_ip;
  u16 inside_port;
  u16 outside_port;
  u16 remote_port;
  u8 proto;
  u8 alg_flags;

  u32 inside_fib_index;
  u32 pool_index;
  u32 mapping_index;

  f64 last_active;
  f64 timeout;

  u64 total_pkts;
  u64 total_bytes;
} cgnat_session_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t src_ip;
      ip4_address_t dst_ip;
      u16 src_port;
      u16 dst_port;
      u8 proto;
      u8 _pad;
      u16 fib_index_lo16;
    };
    u64 as_u64[2];
  };
} cgnat_session_key_t;

STATIC_ASSERT_SIZEOF (cgnat_session_key_t, 16);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ip4_address_t inside_ip;
  ip4_address_t outside_ip;
  u32 inside_vrf_id;
  u32 inside_fib_index;
  u16 port_block_start;
  u16 port_block_end;
  u32 pool_index;
  u32 sw_if_index;

  u16 next_port;
  u32 session_count;

  u64 *port_reuse_timestamps;
} cgnat_mapping_t;

typedef struct
{
  ip4_address_t inside_ip;
  u32 inside_vrf_id;
  u32 inside_fib_index;
} cgnat_bypass_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t ip;
      u32 fib_index;
    };
    u64 as_u64;
  };
} cgnat_bypass_key_t;

typedef struct
{
  ip4_address_t inside_base;
  u32 inside_count;
  ip4_address_t outside_base;
  u32 outside_count;
  u32 sharing_ratio;
  u32 ports_per_host;
  u16 port_range_start;
  u16 port_range_end;
} cgnat_det_params_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 pool_id;
  cgnat_pool_mode_t mode;
  cgnat_address_pooling_t address_pooling;
  cgnat_filtering_t filtering;

  u16 block_size;
  u8 max_blocks_per_sub;
  u32 max_sessions_per_sub;
  u16 port_range_start;
  u16 port_range_end;
  u16 port_reuse_timeout;
  u8 alg_bitmask;

  u32 timeouts[CGNAT_N_PROTOS];

  u32 outside_fib_index;
  u8 outside_fib_valid;

  cgnat_det_params_t *det_params;
  u32 n_det_params;
} cgnat_pool_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t ip;
      u32 fib_index;
    };
    u64 as_u64;
  };
} cgnat_inside_key_t;

typedef enum
{
  CGNAT_IN2OUT_NEXT_DROP,
  CGNAT_IN2OUT_NEXT_LOOKUP,
  CGNAT_IN2OUT_NEXT_HAIRPIN,
  CGNAT_IN2OUT_N_NEXT,
} cgnat_in2out_next_t;

typedef enum
{
  CGNAT_OUT2IN_NEXT_DROP,
  CGNAT_OUT2IN_NEXT_LOOKUP,
  CGNAT_OUT2IN_N_NEXT,
} cgnat_out2in_next_t;

typedef struct
{
  cgnat_pool_t *pools;
  uword *pool_by_id;

  cgnat_mapping_t *mappings;
  clib_bihash_8_8_t inside_lookup;

  cgnat_session_t *sessions;
  clib_bihash_16_8_t session_table_in2out;
  clib_bihash_16_8_t session_table_out2in;

  cgnat_bypass_t *bypasses;
  clib_bihash_8_8_t bypass_table;

  u32 *outside_sw_if_indices;
  u32 *outside_pool_by_sw_if;

  u16 msg_id_base;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  vlib_log_class_t log_class;
} cgnat_main_t;

extern cgnat_main_t cgnat_main;

int cgnat_pool_add_del (cgnat_pool_t *cfg, u8 is_add);
int cgnat_set_outside_fib (u32 pool_id, u32 fib_index);
int cgnat_add_del_subscriber_mapping (u32 pool_id, u32 sw_if_index,
				      ip4_address_t *inside_ip,
				      u32 inside_vrf_id,
				      ip4_address_t *outside_ip,
				      u16 port_start, u16 port_end,
				      u8 enable_feature, u8 is_add);
int cgnat_enable_on_session (u32 pool_id, u32 sw_if_index, u8 is_enable);
int cgnat_set_outside_interface (u32 sw_if_index, u32 pool_id, u8 is_enable);
int cgnat_add_del_bypass (ip4_address_t *ip, u32 vrf_id, u8 is_add);
int cgnat_pool_update (u32 pool_id, u32 max_sessions, u8 alg_bitmask,
		       u32 *timeouts);

cgnat_session_t *cgnat_session_create (cgnat_mapping_t *mapping,
				       ip4_address_t *remote_ip,
				       u16 remote_port, u8 proto,
				       u16 outside_port, f64 now);
cgnat_session_t *cgnat_session_lookup_in2out (ip4_address_t *src_ip,
					      ip4_address_t *dst_ip,
					      u16 src_port, u16 dst_port,
					      u8 proto, u32 fib_index);
cgnat_session_t *cgnat_session_lookup_out2in (ip4_address_t *dst_ip,
					      ip4_address_t *src_ip,
					      u16 dst_port, u16 src_port,
					      u8 proto, u32 fib_index);
void cgnat_session_delete (cgnat_session_t *s);
u16 cgnat_port_alloc (cgnat_mapping_t *m, f64 now);
void cgnat_port_free (cgnat_mapping_t *m, u16 port);
void cgnat_session_expire_walk (vlib_main_t *vm, f64 now);
void cgnat_session_table_init (void);

always_inline cgnat_mapping_t *
cgnat_mapping_lookup (ip4_address_t *inside_ip, u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_8_8_t kv;
  cgnat_inside_key_t key;

  key.ip.as_u32 = inside_ip->as_u32;
  key.fib_index = fib_index;
  kv.key = key.as_u64;
  kv.value = ~0ULL;

  if (clib_bihash_search_inline_8_8 (&cm->inside_lookup, &kv) == 0)
    return pool_elt_at_index (cm->mappings, (u32) kv.value);
  return NULL;
}

always_inline int
cgnat_bypass_check (ip4_address_t *inside_ip, u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_8_8_t kv;
  cgnat_bypass_key_t key;

  key.ip.as_u32 = inside_ip->as_u32;
  key.fib_index = fib_index;
  kv.key = key.as_u64;
  kv.value = 0;

  return (clib_bihash_search_inline_8_8 (&cm->bypass_table, &kv) == 0);
}

always_inline u8
cgnat_proto_from_ip (u8 ip_proto)
{
  switch (ip_proto)
    {
    case IP_PROTOCOL_TCP:
      return CGNAT_PROTO_TCP;
    case IP_PROTOCOL_UDP:
      return CGNAT_PROTO_UDP;
    case IP_PROTOCOL_ICMP:
      return CGNAT_PROTO_ICMP;
    default:
      return CGNAT_PROTO_OTHER;
    }
}

always_inline u32
cgnat_session_timeout (cgnat_pool_t *pool, u8 proto)
{
  if (proto < CGNAT_N_PROTOS)
    return pool->timeouts[proto];
  return pool->timeouts[CGNAT_PROTO_UDP];
}

always_inline int
cgnat_det_forward (cgnat_det_params_t *dp, ip4_address_t *inside_ip,
		   ip4_address_t *outside_ip_out, u16 *port_start_out,
		   u16 *port_end_out)
{
  u32 host_offset =
    clib_net_to_host_u32 (inside_ip->as_u32) -
    clib_net_to_host_u32 (dp->inside_base.as_u32);

  if (host_offset >= dp->inside_count)
    return -1;

  u32 outside_offset = host_offset / dp->sharing_ratio;
  u32 port_index = host_offset % dp->sharing_ratio;

  outside_ip_out->as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32 (dp->outside_base.as_u32) + outside_offset);

  *port_start_out = dp->port_range_start + (dp->ports_per_host * port_index);
  *port_end_out = *port_start_out + dp->ports_per_host - 1;

  return 0;
}

always_inline int
cgnat_det_reverse (cgnat_det_params_t *dp, ip4_address_t *outside_ip,
		   u16 port, ip4_address_t *inside_ip_out)
{
  u32 outside_offset =
    clib_net_to_host_u32 (outside_ip->as_u32) -
    clib_net_to_host_u32 (dp->outside_base.as_u32);

  if (outside_offset >= dp->outside_count)
    return -1;

  if (port < dp->port_range_start || port > dp->port_range_end)
    return -1;

  u32 port_offset = (port - dp->port_range_start) / dp->ports_per_host;
  u32 host_offset = (outside_offset * dp->sharing_ratio) + port_offset;

  if (host_offset >= dp->inside_count)
    return -1;

  inside_ip_out->as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32 (dp->inside_base.as_u32) + host_offset);

  return 0;
}

always_inline cgnat_pool_t *
cgnat_pool_for_outside_ip (ip4_address_t *outside_ip)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;

  pool_foreach (pool, cm->pools)
    {
      if (pool->mode == CGNAT_POOL_MODE_DETERMINISTIC)
	{
	  for (u32 i = 0; i < pool->n_det_params; i++)
	    {
	      cgnat_det_params_t *dp = &pool->det_params[i];
	      u32 off = clib_net_to_host_u32 (outside_ip->as_u32) -
			clib_net_to_host_u32 (dp->outside_base.as_u32);
	      if (off < dp->outside_count)
		return pool;
	    }
	}
    }
  return NULL;
}

#endif /* __included_osvbng_cgnat_h__ */
