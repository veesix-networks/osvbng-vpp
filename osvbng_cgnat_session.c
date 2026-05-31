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

  /* Aux fragment rewrite bihash (D14). Smaller than the session tables —
   * one entry per (saddr, daddr, proto, fib) equivalence class, not per
   * flow. 16k buckets / 16MB is comfortably oversized for the typical CGN
   * destination cardinality. */
  clib_bihash_init_16_8 (&cm->frag_aux, "cgnat frag-aux rewrite", 16 * 1024,
			 16 << 20);

  clib_spinlock_init (&cm->frag_rewrite_lock);

  /* Per-thread state allocation. At INIT time vlib_num_workers() may still
   * return 0 (workers spawn after init); size for at least the main thread
   * here so single-worker deployments work. Commit 2 of the multi-worker
   * amendment moves this to a VLIB_MAIN_LOOP_ENTER_FUNCTION that resizes
   * to vlib_num_workers() + 1 once all workers exist. */
  vec_validate_aligned (cm->per_thread_data, 0, CLIB_CACHE_LINE_BYTES);
}

static inline void
cgnat_frag_make_key (cgnat_session_key_t *key, u32 saddr, u32 daddr, u8 proto,
		     u32 fib_index)
{
  key->src_ip.as_u32 = saddr;
  key->dst_ip.as_u32 = daddr;
  key->src_port = 0;
  key->dst_port = 0;
  key->proto = proto;
  key->_pad = 0;
  key->fib_index_lo16 = (u16) fib_index;
}

cgnat_frag_rewrite_t *
cgnat_frag_rewrite_lookup (ip4_address_t saddr, ip4_address_t daddr, u8 proto,
			   u32 fib_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_16_8_t kv;
  cgnat_session_key_t key;

  cgnat_frag_make_key (&key, saddr.as_u32, daddr.as_u32, proto, fib_index);
  clib_memcpy (&kv.key, &key, 16);

  /* aux frag_rewrite_pool is shared across workers — readers are safe under
   * concurrent allocation because pool_elt_at_index is a vec-index + base
   * pointer load (pool_get may realloc on grow but bihash insert is gated
   * by per-bucket lock, ordering the realloc-then-bihash-insert so the
   * lookup sees a consistent state). */
  if (clib_bihash_search_inline_16_8 (&cm->frag_aux, &kv) == 0)
    return pool_elt_at_index (cm->frag_rewrite_pool, (u32) kv.value);

  return NULL;
}

/* Refcount-install an aux rewrite record for (saddr, daddr, proto, fib).
 * Returns the pool index — caller (cgnat_session_create) stashes it on the
 * session for O(1) decrement at delete. Serialised under frag_rewrite_lock
 * because two workers may race to create sessions sharing the same aux
 * tuple; pool_get can realloc and the refcount must be atomic with the
 * insert. The lock is on the slow path only (one acquire per new session)
 * so contention is microscopic. */
static u32
cgnat_frag_rewrite_acquire (ip4_address_t inside_ip, ip4_address_t outside_ip,
			    ip4_address_t remote_ip, u8 proto, u32 inside_fib,
			    u32 outside_fib)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_frag_rewrite_t *r;
  u32 idx;

  clib_spinlock_lock (&cm->frag_rewrite_lock);

  r = cgnat_frag_rewrite_lookup (inside_ip, remote_ip, proto, inside_fib);
  if (r)
    {
      r->refcount++;
      idx = r - cm->frag_rewrite_pool;
      clib_spinlock_unlock (&cm->frag_rewrite_lock);
      return idx;
    }

  /* Allocate + install both directions' aux entries (in2out and out2in
   * fragments arrive on opposite interfaces; both need a key). */
  pool_get_zero (cm->frag_rewrite_pool, r);
  idx = r - cm->frag_rewrite_pool;
  r->inside_ip = inside_ip;
  r->outside_ip = outside_ip;
  r->inside_fib_index = inside_fib;
  r->outside_fib_index = outside_fib;

  ip_csum_t l3_i2o = 0;
  l3_i2o = ip_csum_sub_even (l3_i2o, inside_ip.as_u32);
  l3_i2o = ip_csum_add_even (l3_i2o, outside_ip.as_u32);
  r->l3_csum_delta_i2o = l3_i2o;

  ip_csum_t l3_o2i = 0;
  l3_o2i = ip_csum_sub_even (l3_o2i, outside_ip.as_u32);
  l3_o2i = ip_csum_add_even (l3_o2i, inside_ip.as_u32);
  r->l3_csum_delta_o2i = l3_o2i;

  r->refcount = 1;

  /* In2out fragment key: (inside_ip, remote_ip, proto, inside_fib). */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_frag_make_key (&key, inside_ip.as_u32, remote_ip.as_u32, proto,
			 inside_fib);
    clib_memcpy (&kv.key, &key, 16);
    kv.value = idx;
    clib_bihash_add_del_16_8 (&cm->frag_aux, &kv, 1);
  }

  /* Out2in fragment key: (remote_ip, outside_ip, proto, outside_fib).
   * Note saddr/daddr ordering matches the way out2in lookups present them
   * (packet's actual src/dst — remote in src slot, outside_ip in dst slot). */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_frag_make_key (&key, remote_ip.as_u32, outside_ip.as_u32, proto,
			 outside_fib);
    clib_memcpy (&kv.key, &key, 16);
    kv.value = idx;
    clib_bihash_add_del_16_8 (&cm->frag_aux, &kv, 1);
  }

  clib_spinlock_unlock (&cm->frag_rewrite_lock);
  return idx;
}

static void
cgnat_frag_rewrite_release (u32 frag_rewrite_index, ip4_address_t remote_ip,
			    u8 proto)
{
  cgnat_main_t *cm = &cgnat_main;

  clib_spinlock_lock (&cm->frag_rewrite_lock);

  if (pool_is_free_index (cm->frag_rewrite_pool, frag_rewrite_index))
    {
      clib_spinlock_unlock (&cm->frag_rewrite_lock);
      return;
    }

  cgnat_frag_rewrite_t *r =
    pool_elt_at_index (cm->frag_rewrite_pool, frag_rewrite_index);
  if (r->refcount > 1)
    {
      r->refcount--;
      clib_spinlock_unlock (&cm->frag_rewrite_lock);
      return;
    }

  /* Last reference — evict both directions from the aux bihash. */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_frag_make_key (&key, r->inside_ip.as_u32, remote_ip.as_u32, proto,
			 r->inside_fib_index);
    clib_memcpy (&kv.key, &key, 16);
    clib_bihash_add_del_16_8 (&cm->frag_aux, &kv, 0);
  }
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_frag_make_key (&key, remote_ip.as_u32, r->outside_ip.as_u32, proto,
			 r->outside_fib_index);
    clib_memcpy (&kv.key, &key, 16);
    clib_bihash_add_del_16_8 (&cm->frag_aux, &kv, 0);
  }

  pool_put (cm->frag_rewrite_pool, r);
  clib_spinlock_unlock (&cm->frag_rewrite_lock);
}

/* Resolve a packed bihash value into a session pointer in the owning
 * thread's per-thread pool. Safe to call from any worker — pool_elt_at_index
 * is a vec-index + base load; concurrent pool_get on the owning thread
 * doesn't realloc on top of an active index. */
always_inline cgnat_session_t *
cgnat_session_from_value (u64 value)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 ti = cgnat_value_thread_index (value);
  u32 si = cgnat_value_entry_index (value);
  if (PREDICT_FALSE (ti >= vec_len (cm->per_thread_data)))
    return NULL;
  cgnat_per_thread_data_t *tsm = vec_elt_at_index (cm->per_thread_data, ti);
  if (PREDICT_FALSE (pool_is_free_index (tsm->sessions, si)))
    return NULL;
  return pool_elt_at_index (tsm->sessions, si);
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
    return cgnat_session_from_value (kv.value);

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
    return cgnat_session_from_value (kv.value);

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

      /* Advance via u32 so port_block_end == 65535 doesn't u16-wrap
       * silently to 0 (which would bypass the > end check and let us
       * return ports outside the configured block). */
      u32 next = (u32) m->next_port + 1;
      if (next > m->port_block_end)
	next = m->port_block_start;
      m->next_port = (u16) next;

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
		      u16 inside_port, f64 now, u32 thread_index)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool = pool_elt_at_index (cm->pools, mapping->pool_index);
  cgnat_per_thread_data_t *tsm =
    vec_elt_at_index (cm->per_thread_data, thread_index);

  if (mapping->session_count >= pool->max_sessions_per_sub)
    return NULL;

  cgnat_session_t *s;
  pool_get_zero (tsm->sessions, s);
  u32 session_index = s - tsm->sessions;
  s->thread_index = thread_index;

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
  /* New TCP sessions start in CLOSED state — wait for SYN+ACK from both
   * sides before promoting to ESTABLISHED. Until then they use the short
   * transitory timeout so a half-open SYN flood is reaped in minutes
   * rather than hours. */
  s->tcp_state = CGNAT_TCP_STATE_CLOSED;
  if (proto == IP_PROTOCOL_TCP)
    s->timeout = cgnat_session_timeout_for_tcp (pool, s->tcp_state);
  else
    s->timeout = cgnat_session_timeout (pool, cgnat_proto_from_ip (proto));

  /* Refcount-acquire the aux fragment rewrite record. Non-first fragments
   * (which have no L4 header) fall back to this record for IP-only rewrite. */
  s->frag_rewrite_index = cgnat_frag_rewrite_acquire (
    mapping->inside_ip, mapping->outside_ip, *remote_ip, proto,
    mapping->inside_fib_index, out_fib);

  /* alg_flags stays zero — no ALG packet processing is implemented; the
   * field is retained for #151 wire-format compatibility only. Real ALG
   * handlers (FTP / SIP / PPTP / etc.) are tracked separately and would
   * set this field at session create alongside the actual rewrite logic. */

  /* Install in2out entry: keyed on i2o.match (inside_ip, remote_ip,
   * inside_port, remote_port, proto, inside_fib). */
  {
    clib_bihash_kv_16_8_t kv;
    cgnat_session_key_t key;
    cgnat_session_make_key (&key, &s->i2o.saddr, &s->i2o.daddr, s->i2o.sport,
			    s->i2o.dport, s->i2o.proto, s->i2o.fib_index);
    clib_memcpy (&kv.key, &key, 16);
    kv.value = cgnat_pack_value (thread_index, session_index);
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
    kv.value = cgnat_pack_value (thread_index, session_index);
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

  /* Non-port protos (GRE/ESP/SCTP/...) didn't reserve a port at session
   * create, so don't free one at delete. */
  if (!cgnat_is_unk_proto (s->i2o.proto))
    cgnat_port_free (m, clib_net_to_host_u16 (s->i2o.rewrite_sport));

  /* Refcount-release the aux fragment rewrite record; evict if last. */
  cgnat_frag_rewrite_release (s->frag_rewrite_index, s->i2o.daddr,
			      s->i2o.proto);

  if (m->session_count > 0)
    m->session_count--;

  cgnat_per_thread_data_t *tsm =
    vec_elt_at_index (cm->per_thread_data, s->thread_index);
  pool_put (tsm->sessions, s);
}

void
cgnat_session_expire_walk (vlib_main_t *vm, f64 now)
{
  cgnat_main_t *cm = &cgnat_main;

  /* Walk each per-thread session pool. Commit 1 keeps this as a
   * main-thread sweep that touches per-thread pools directly — safe under
   * the kept single-worker ASSERT (only thread 0 has any sessions). Commit
   * 3 of the amendment replaces this with per-thread expire processes so
   * each worker reaps its own pool without cross-thread access. */
  for (u32 ti = 0; ti < vec_len (cm->per_thread_data); ti++)
    {
      cgnat_per_thread_data_t *tsm = vec_elt_at_index (cm->per_thread_data, ti);
      u32 *expired = NULL;
      cgnat_session_t *s;

      pool_foreach (s, tsm->sessions)
	{
	  if ((now - s->last_active) > s->timeout)
	    vec_add1 (expired, s - tsm->sessions);
	}

      for (u32 i = 0; i < vec_len (expired); i++)
	{
	  u32 si = expired[i];
	  if (!pool_is_free_index (tsm->sessions, si))
	    cgnat_session_delete (pool_elt_at_index (tsm->sessions, si));
	}
      vec_free (expired);
    }
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
