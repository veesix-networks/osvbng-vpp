/* Copyright 2026 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng CGNAT Plugin - Session table
 * Flow tracking, LRU expiry, port allocation within blocks.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <osvbng_cgnat/osvbng_cgnat.h>

static inline void
cgnat_session_make_key (cgnat_session_key_t *key, ip4_address_t *src_ip,
			ip4_address_t *dst_ip, u16 src_port, u16 dst_port,
			u8 proto, u32 fib_index)
{
  key->src_ip.as_u32 = src_ip->as_u32;
  key->dst_ip.as_u32 = dst_ip->as_u32;
  key->src_port = src_port;
  key->dst_port = dst_port;
  key->proto = proto;
  key->_pad = 0;
  key->fib_index_lo16 = (u16) fib_index;
}

void
cgnat_session_table_init (void)
{
  cgnat_main_t *cm = &cgnat_main;

  clib_bihash_init_16_8 (&cm->session_table_in2out, "cgnat sessions in2out",
			  64 * 1024, 64 << 20);

  clib_bihash_init_16_8 (&cm->session_table_out2in, "cgnat sessions out2in",
			  64 * 1024, 64 << 20);
}

cgnat_session_t *
cgnat_session_lookup_in2out (ip4_address_t *src_ip, ip4_address_t *dst_ip,
			     u16 src_port, u16 dst_port, u8 proto,
			     u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_16_8_t kv;
  cgnat_session_key_t key;

  cgnat_session_make_key (&key, src_ip, dst_ip, src_port, dst_port, proto,
			  fib_index);
  clib_memcpy (&kv.key, &key, 16);

  if (clib_bihash_search_inline_16_8 (&cm->session_table_in2out, &kv) == 0)
    return pool_elt_at_index (cm->sessions, (u32) kv.value);

  return NULL;
}

cgnat_session_t *
cgnat_session_lookup_out2in (ip4_address_t *dst_ip, ip4_address_t *src_ip,
			     u16 dst_port, u16 src_port, u8 proto,
			     u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_16_8_t kv;
  cgnat_session_key_t key;

  cgnat_session_make_key (&key, dst_ip, src_ip, dst_port, src_port, proto,
			  fib_index);
  clib_memcpy (&kv.key, &key, 16);

  if (clib_bihash_search_inline_16_8 (&cm->session_table_out2in, &kv) == 0)
    return pool_elt_at_index (cm->sessions, (u32) kv.value);

  return NULL;
}

u16
cgnat_port_alloc (cgnat_mapping_t *m, f64 now)
{
  u32 block_size = m->port_block_end - m->port_block_start + 1;

  for (u32 attempts = 0; attempts < block_size; attempts++)
    {
      u16 port = m->next_port;
      u32 port_offset = port - m->port_block_start;

      m->next_port++;
      if (m->next_port > m->port_block_end)
	m->next_port = m->port_block_start;

      if (port_offset < vec_len (m->port_reuse_timestamps))
	{
	  f64 ts = m->port_reuse_timestamps[port_offset];
	  if (ts > 0.0 && (now - ts) < 120.0)
	    continue;
	}

      return port;
    }

  return 0;
}

void
cgnat_port_free (cgnat_mapping_t *m, u16 port)
{
  u32 port_offset = port - m->port_block_start;
  cgnat_main_t *cm = &cgnat_main;

  if (port_offset < vec_len (m->port_reuse_timestamps))
    m->port_reuse_timestamps[port_offset] = vlib_time_now (cm->vlib_main);
}

/* Precompute the L3+L4 checksum deltas for one direction. All inputs in
 * network byte order. is_l4_pseudohdr controls whether the L4 delta includes
 * the IP-address change (TCP/UDP whose checksums cover a pseudo-header
 * containing src/dst) or not (ICMP whose checksum covers only the ICMP
 * header+data). */
static inline void
cgnat_flow_csum_calc (cgnat_flow_t *f, u32 old_addr, u32 new_addr, u16 old_port,
		      u16 new_port, int is_l4_pseudohdr)
{
  ip_csum_t l3 = 0;
  l3 = ip_csum_sub_even (l3, old_addr);
  l3 = ip_csum_add_even (l3, new_addr);
  f->l3_csum_delta = l3;

  ip_csum_t l4 = is_l4_pseudohdr ? l3 : 0;
  l4 = ip_csum_sub_even (l4, old_port);
  l4 = ip_csum_add_even (l4, new_port);
  f->l4_csum_delta = l4;
}

cgnat_session_t *
cgnat_session_create (cgnat_mapping_t *mapping, ip4_address_t *remote_ip,
		      u16 remote_port, u8 proto, u16 outside_port,
		      u16 inside_port, f64 now)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, mapping->pool_index);

  if (mapping->session_count >= pool->max_sessions_per_sub)
    return NULL;

  cgnat_session_t *s;
  pool_get_zero (cm->sessions, s);
  u32 session_index = s - cm->sessions;

  u16 outside_port_n = clib_host_to_net_u16 (outside_port);
  u32 inside_fib = mapping->inside_fib_index;
  u32 out_fib = pool->outside_fib_valid ? pool->outside_fib_index : 0;

  /* i2o: subscriber → outside. Match is the inside-perspective tuple; rewrite
   * replaces saddr/sport with the outside-allocated tuple. */
  s->i2o.saddr = mapping->inside_ip;
  s->i2o.daddr = *remote_ip;
  s->i2o.sport = inside_port;
  s->i2o.dport = remote_port;
  s->i2o.proto = proto;
  s->i2o.fib_index = inside_fib;
  s->i2o.rewrite_saddr = mapping->outside_ip;
  s->i2o.rewrite_daddr = *remote_ip;
  s->i2o.rewrite_sport = outside_port_n;
  s->i2o.rewrite_dport = remote_port;
  s->i2o.rewrite_fib_index = out_fib;

  /* o2i: outside → subscriber. Match is the outside-perspective tuple
   * (outside_ip in the src slot, outside_port in the sport slot — same
   * convention the existing lookup callers use); rewrite replaces daddr/dport
   * with the subscriber's inside tuple. */
  s->o2i.saddr = mapping->outside_ip;
  s->o2i.daddr = *remote_ip;
  s->o2i.sport = outside_port_n;
  s->o2i.dport = remote_port;
  s->o2i.proto = proto;
  s->o2i.fib_index = out_fib;
  s->o2i.rewrite_saddr = mapping->outside_ip;
  s->o2i.rewrite_daddr = mapping->inside_ip;
  s->o2i.rewrite_sport = outside_port_n;
  s->o2i.rewrite_dport = inside_port;
  s->o2i.rewrite_fib_index = inside_fib;

  /* Direction-specific csum deltas. TCP/UDP cover the pseudo-header so their
   * L4 delta carries the L3 component; ICMP echo doesn't. */
  int is_pseudo = (proto == IP_PROTOCOL_TCP || proto == IP_PROTOCOL_UDP);
  cgnat_flow_csum_calc (&s->i2o, mapping->inside_ip.as_u32,
			mapping->outside_ip.as_u32, inside_port,
			outside_port_n, is_pseudo);
  cgnat_flow_csum_calc (&s->o2i, mapping->outside_ip.as_u32,
			mapping->inside_ip.as_u32, outside_port_n,
			inside_port, is_pseudo);

  s->pool_index = mapping->pool_index;
  s->mapping_index = mapping - cm->mappings;
  s->last_active = now;
  s->timeout = cgnat_session_timeout (pool, cgnat_proto_from_ip (proto));

  if (pool->alg_bitmask)
    {
      u8 cgnat_proto = cgnat_proto_from_ip (proto);
      if (cgnat_proto == CGNAT_PROTO_TCP)
	{
	  if (remote_port == clib_host_to_net_u16 (21) &&
	      (pool->alg_bitmask & CGNAT_ALG_FTP))
	    s->alg_flags = CGNAT_ALG_FTP;
	  else if (remote_port == clib_host_to_net_u16 (5060) &&
		   (pool->alg_bitmask & CGNAT_ALG_SIP))
	    s->alg_flags = CGNAT_ALG_SIP;
	  else if (remote_port == clib_host_to_net_u16 (554) &&
		   (pool->alg_bitmask & CGNAT_ALG_RTSP))
	    s->alg_flags = CGNAT_ALG_RTSP;
	  else if (remote_port == clib_host_to_net_u16 (1723) &&
		   (pool->alg_bitmask & CGNAT_ALG_PPTP))
	    s->alg_flags = CGNAT_ALG_PPTP;
	}
      else if (cgnat_proto == CGNAT_PROTO_UDP)
	{
	  if (remote_port == clib_host_to_net_u16 (69) &&
	      (pool->alg_bitmask & CGNAT_ALG_TFTP))
	    s->alg_flags = CGNAT_ALG_TFTP;
	  else if (remote_port == clib_host_to_net_u16 (5060) &&
		   (pool->alg_bitmask & CGNAT_ALG_SIP))
	    s->alg_flags = CGNAT_ALG_SIP;
	  else if (remote_port == clib_host_to_net_u16 (53) &&
		   (pool->alg_bitmask & CGNAT_ALG_DNS))
	    s->alg_flags = CGNAT_ALG_DNS;
	}
    }

  /* Install in2out entry: keyed on i2o.match (inside_ip, remote_ip,
   * inside_port, remote_port, proto, inside_fib). */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_session_make_key (&key, &s->i2o.saddr, &s->i2o.daddr, s->i2o.sport,
			    s->i2o.dport, s->i2o.proto, s->i2o.fib_index);
    clib_memcpy (&kv.key, &key, 16);
    kv.value = session_index;
    clib_bihash_add_del_16_8 (&cm->session_table_in2out, &kv, 1);
  }

  /* Install out2in entry: keyed on o2i.match (outside_ip, remote_ip,
   * outside_port, remote_port, proto, outside_fib). */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_session_make_key (&key, &s->o2i.saddr, &s->o2i.daddr, s->o2i.sport,
			    s->o2i.dport, s->o2i.proto, s->o2i.fib_index);
    clib_memcpy (&kv.key, &key, 16);
    kv.value = session_index;
    clib_bihash_add_del_16_8 (&cm->session_table_out2in, &kv, 1);
  }

  mapping->session_count++;

  return s;
}

void
cgnat_session_delete (cgnat_session_t *s)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_mapping_t *m = pool_elt_at_index (cm->mappings, s->mapping_index);

  /* Remove in2out entry — reconstruct key from i2o flow record (the same
   * tuple session_create installed; safe across SetOutsideVRF moves because
   * SetOutsideVRF now rejects with live sessions present per M4). */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_session_make_key (&key, &s->i2o.saddr, &s->i2o.daddr, s->i2o.sport,
			    s->i2o.dport, s->i2o.proto, s->i2o.fib_index);
    clib_memcpy (&kv.key, &key, 16);
    clib_bihash_add_del_16_8 (&cm->session_table_in2out, &kv, 0);
  }

  /* Remove out2in entry — reconstruct key from o2i flow record. */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_session_make_key (&key, &s->o2i.saddr, &s->o2i.daddr, s->o2i.sport,
			    s->o2i.dport, s->o2i.proto, s->o2i.fib_index);
    clib_memcpy (&kv.key, &key, 16);
    clib_bihash_add_del_16_8 (&cm->session_table_out2in, &kv, 0);
  }

  cgnat_port_free (m, clib_net_to_host_u16 (s->i2o.rewrite_sport));

  if (m->session_count > 0)
    m->session_count--;

  pool_put (cm->sessions, s);
}

typedef struct
{
  f64 now;
  u32 *expired;
} cgnat_expire_ctx_t;

static int
cgnat_expire_walk_cb (clib_bihash_kv_16_8_t *kv, void *arg)
{
  cgnat_expire_ctx_t *ctx = arg;
  cgnat_main_t *cm = &cgnat_main;
  u32 si = (u32) kv->value;

  if (pool_is_free_index (cm->sessions, si))
    return BIHASH_WALK_CONTINUE;

  cgnat_session_t *s = pool_elt_at_index (cm->sessions, si);

  if ((ctx->now - s->last_active) > s->timeout)
    vec_add1 (ctx->expired, si);

  return BIHASH_WALK_CONTINUE;
}

void
cgnat_session_expire_walk (vlib_main_t *vm, f64 now)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_expire_ctx_t ctx = { .now = now, .expired = NULL };

  clib_bihash_foreach_key_value_pair_16_8 (&cm->session_table_in2out,
					   cgnat_expire_walk_cb, &ctx);

  for (u32 i = 0; i < vec_len (ctx.expired); i++)
    {
      u32 si = ctx.expired[i];
      if (!pool_is_free_index (cm->sessions, si))
	{
	  cgnat_session_t *s = pool_elt_at_index (cm->sessions, si);
	  cgnat_session_delete (s);
	}
    }

  vec_free (ctx.expired);
}

static uword
cgnat_expire_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		      vlib_frame_t *f)
{
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 10.0);
      vlib_process_get_events (vm, NULL);

      f64 now = vlib_time_now (vm);
      cgnat_session_expire_walk (vm, now);
    }

  return 0;
}

VLIB_REGISTER_NODE (cgnat_expire_node) = {
  .function = cgnat_expire_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cgnat-expire-process",
};

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
