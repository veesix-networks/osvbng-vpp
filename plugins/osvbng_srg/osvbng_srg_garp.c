/* Copyright 2025 Veesix Networks Ltd
 * Licensed under the GNU General Public License v3.0 or later.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * osvbng SRG Plugin - GARP/NA frame construction and batch send
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/arp_packet.h>

#include <osvbng_srg/osvbng_srg.h>
#include <osvbng_srg/osvbng_srg_garp.h>

static const mac_address_t broadcast_mac = {
  .bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
};

/*
 * Write the Ethernet header with VLAN tags from the entry. Tags cannot
 * come from sub-interface rewrite state: subscriber-group sub-interfaces
 * match vlan-any and ethernet_build_rewrite refuses those; the control
 * plane knows each session's exact encap and sends it in the entry.
 * Mirrors the encap cases of the session dataplane: QinQ, single outer,
 * single inner, untagged.
 */
static u32
garp_l2_header (u8 *p, mac_address_t *vmac, const u8 *dst_mac,
		osvbng_srg_garp_entry_arg_t *e, u16 ethertype)
{
  ethernet_header_t *eth = (ethernet_header_t *) p;
  u8 *cur = p + sizeof (*eth);
  u16 outer_tpid = e->outer_tpid ? e->outer_tpid : ETHERNET_TYPE_VLAN;

  clib_memcpy (eth->dst_address, dst_mac, 6);
  clib_memcpy (eth->src_address, vmac->bytes, 6);

  if (e->outer_vlan && e->inner_vlan)
    {
      eth->type = clib_host_to_net_u16 (outer_tpid);
      ethernet_vlan_header_t *svlan = (ethernet_vlan_header_t *) cur;
      svlan->priority_cfi_and_id =
	clib_host_to_net_u16 (e->outer_vlan & 0xFFF);
      svlan->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      cur += sizeof (*svlan);

      ethernet_vlan_header_t *cvlan = (ethernet_vlan_header_t *) cur;
      cvlan->priority_cfi_and_id =
	clib_host_to_net_u16 (e->inner_vlan & 0xFFF);
      cvlan->type = clib_host_to_net_u16 (ethertype);
      cur += sizeof (*cvlan);
    }
  else if (e->outer_vlan || e->inner_vlan)
    {
      u16 vlan_id = e->outer_vlan ? e->outer_vlan : e->inner_vlan;
      eth->type = clib_host_to_net_u16 (e->outer_vlan ? outer_tpid :
					ETHERNET_TYPE_VLAN);
      ethernet_vlan_header_t *tag = (ethernet_vlan_header_t *) cur;
      tag->priority_cfi_and_id = clib_host_to_net_u16 (vlan_id & 0xFFF);
      tag->type = clib_host_to_net_u16 (ethertype);
      cur += sizeof (*tag);
    }
  else
    eth->type = clib_host_to_net_u16 (ethertype);

  return cur - p;
}

/*
 * Build a gratuitous ARP: broadcast ARP reply, sender and target both
 * the subscriber IP, both MACs pointing at the virtual MAC.
 */
static void
osvbng_srg_garp_build (vlib_buffer_t *b, osvbng_srg_garp_entry_arg_t *e,
		       mac_address_t *vmac)
{
  ethernet_arp_header_t *arp;
  u32 l2_len;

  l2_len = garp_l2_header (vlib_buffer_get_current (b), vmac,
			   broadcast_mac.bytes, e, ETHERNET_TYPE_ARP);
  b->current_length += l2_len;
  vlib_buffer_advance (b, l2_len);

  arp = vlib_buffer_get_current (b);
  b->current_length += sizeof (*arp);

  clib_memset (arp, 0, sizeof (*arp));

  arp->l2_type = clib_host_to_net_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet);
  arp->l3_type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  arp->n_l2_address_bytes = 6;
  arp->n_l3_address_bytes = 4;
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
  arp->ip4_over_ethernet[0].mac = *vmac;
  arp->ip4_over_ethernet[0].ip4 = e->ip.ip4;
  arp->ip4_over_ethernet[1].mac = broadcast_mac;
  arp->ip4_over_ethernet[1].ip4 = e->ip.ip4;
}

/*
 * Build an unsolicited Neighbor Advertisement for IPv6.
 *
 * Destination: all-nodes multicast (ff02::1), Ethernet dst 33:33:00:00:00:01.
 * Source: link-local derived from vMAC via EUI-64.
 * ICMPv6 NA with OVERRIDE | ROUTER flags, target link-layer address option.
 */
static void
osvbng_srg_na_build (vlib_main_t *vm, vlib_buffer_t *b,
		     osvbng_srg_garp_entry_arg_t *e, mac_address_t *vmac)
{
  ip6_header_t *ip6h;
  icmp6_neighbor_solicitation_or_advertisement_header_t *na;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *ll_opt;
  int payload_length, bogus_length;
  u32 l2_len;
  u8 dst_mac[6];

  /* All-nodes multicast MAC: 33:33:00:00:00:01 */
  ip6_multicast_ethernet_address (dst_mac, IP6_MULTICAST_GROUP_ID_all_hosts);

  l2_len = garp_l2_header (vlib_buffer_get_current (b), vmac, dst_mac, e,
			   ETHERNET_TYPE_IP6);
  b->current_length += l2_len;
  vlib_buffer_advance (b, l2_len);

  /* IPv6 header */
  ip6h = vlib_buffer_get_current (b);
  b->current_length += sizeof (*ip6h);
  clib_memset (ip6h, 0, sizeof (*ip6h));

  ip6h->ip_version_traffic_class_and_flow_label = 0x00000060;
  ip6h->protocol = IP_PROTOCOL_ICMP6;
  ip6h->hop_limit = 255;

  /* Destination: ff02::1 (all-nodes) */
  ip6_set_reserved_multicast_address (&ip6h->dst_address,
				      IP6_MULTICAST_SCOPE_link_local,
				      IP6_MULTICAST_GROUP_ID_all_hosts);

  /* Source: link-local from vMAC via EUI-64 (fe80::<mac[0]^0x02>XX:XXff:feXX:XXXX) */
  ip6h->src_address.as_u64[0] = clib_host_to_net_u64 (0xfe80000000000000ULL);
  ip6h->src_address.as_u8[8] = vmac->bytes[0] ^ 0x02;
  ip6h->src_address.as_u8[9] = vmac->bytes[1];
  ip6h->src_address.as_u8[10] = vmac->bytes[2];
  ip6h->src_address.as_u8[11] = 0xff;
  ip6h->src_address.as_u8[12] = 0xfe;
  ip6h->src_address.as_u8[13] = vmac->bytes[3];
  ip6h->src_address.as_u8[14] = vmac->bytes[4];
  ip6h->src_address.as_u8[15] = vmac->bytes[5];

  /* ICMPv6 Neighbor Advertisement */
  na = (icmp6_neighbor_solicitation_or_advertisement_header_t *) (ip6h + 1);
  ll_opt =
    (icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *) (na +
								       1);

  payload_length = sizeof (*na) + sizeof (*ll_opt);
  b->current_length += payload_length;
  clib_memset (na, 0, payload_length);

  na->icmp.type = ICMP6_neighbor_advertisement;
  na->target_address = e->ip.ip6;
  na->advertisement_flags = clib_host_to_net_u32 (
    ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE |
    ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER);

  ll_opt->header.type =
    ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
  ll_opt->header.n_data_u64s = 1;
  clib_memcpy (ll_opt->ethernet_address, vmac->bytes, 6);

  ip6h->payload_length = clib_host_to_net_u16 (payload_length);
  na->icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6h, &bogus_length);
}

/*
 * Resolve the interface the frame actually transmits on: the wire (sup
 * hw) parent of the entry's interface. Interfaces registered without a
 * device tx function (per-session midchain interfaces: IPoE, PPPoE
 * sessions) keep output_node_index 0, and interface-output dispatches
 * their zeroed next-slot to local0-output, where the frame dies as
 * "interface is down" (osvbng issue 417). Those must be refused loudly.
 * Returns ~0 when the entry cannot transmit.
 */
static u32
garp_tx_sw_if_index (vnet_main_t *vnm, u32 sw_if_index)
{
  vnet_hw_interface_t *hw;

  if (!vnet_sw_interface_is_valid (vnm, sw_if_index))
    return ~0;

  hw = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (!hw || hw->output_node_index == 0)
    return ~0;

  return hw->sw_if_index;
}

/*
 * Batch send GARP/NA packets.
 *
 * Allocates buffers in VLIB_FRAME_SIZE batches, builds frames with the
 * entry's VLAN encap, and enqueues to interface-output on the wire
 * parent. Entries whose interface cannot transmit are skipped and
 * counted in garp_skipped; the sent counters only ever cover frames
 * handed to a real output path.
 */
int
osvbng_srg_send_garp_batch (vlib_main_t *vm, u8 *srg_name,
			    osvbng_srg_garp_entry_arg_t *entries, u32 count,
			    mac_address_t *virtual_mac)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 srg_index = ~0;
  u32 offset = 0;
  u32 skipped = 0;

  /* Look up SRG for counter attribution */
  uword *p = hash_get_mem (sm->srg_by_name, srg_name);
  if (p)
    srg_index = p[0];

  while (offset < count)
    {
      u32 batch = clib_min (count - offset, VLIB_FRAME_SIZE);
      u32 *bi = 0;
      u32 n_alloc;
      vlib_frame_t *to_frame;
      u32 *to_next;

      vec_validate (bi, batch - 1);

      n_alloc = vlib_buffer_alloc (vm, bi, batch);
      if (PREDICT_FALSE (n_alloc == 0))
	{
	  vlib_log_warn (sm->log_class,
			 "GARP batch: buffer alloc failed, 0 of %u", batch);
	  vec_free (bi);
	  return -1;
	}

      if (PREDICT_FALSE (n_alloc < batch))
	{
	  vlib_log_warn (sm->log_class,
			 "GARP batch: partial alloc %u of %u", n_alloc, batch);
	  batch = n_alloc;
	}

      to_frame =
	vlib_get_frame_to_node (vm, sm->intf_output_node_idx);
      to_frame->n_vectors = 0;
      to_next = vlib_frame_vector_args (to_frame);

      for (u32 i = 0; i < batch; i++)
	{
	  osvbng_srg_garp_entry_arg_t *e = &entries[offset + i];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);
	  u32 tx_sw_if_index = garp_tx_sw_if_index (vnm, e->sw_if_index);

	  if (PREDICT_FALSE (tx_sw_if_index == ~0))
	    {
	      vlib_buffer_free_one (vm, bi[i]);
	      skipped++;
	      if (srg_index != ~0)
		sm->garp_skipped[srg_index]++;
	      continue;
	    }

	  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = tx_sw_if_index;

	  if (e->is_ip6)
	    osvbng_srg_na_build (vm, b, e, virtual_mac);
	  else
	    osvbng_srg_garp_build (b, e, virtual_mac);

	  if (srg_index != ~0)
	    {
	      if (e->is_ip6)
		sm->na_sent[srg_index]++;
	      else
		sm->garp_sent[srg_index]++;
	    }

	  vlib_buffer_reset (b);

	  /* A tagged GARP is 46 to 50 bytes, under the Ethernet minimum.
	   * veth and af_packet carry runts, but DPDK/virtio NICs count
	   * tx undersize and drop them (issue 417 follow-up), so pad. */
	  if (b->current_length < ETHERNET_MIN_PACKET_BYTES)
	    {
	      u32 pad = ETHERNET_MIN_PACKET_BYTES - b->current_length;
	      clib_memset (vlib_buffer_get_current (b) + b->current_length, 0,
			   pad);
	      b->current_length = ETHERNET_MIN_PACKET_BYTES;
	    }

	  to_next[to_frame->n_vectors] = bi[i];
	  to_frame->n_vectors++;
	}

      vlib_put_frame_to_node (vm, sm->intf_output_node_idx, to_frame);

      vec_free (bi);
      offset += batch;
    }

  if (PREDICT_FALSE (skipped > 0))
    vlib_log_warn (sm->log_class,
		   "GARP batch: %u of %u entries skipped, interface cannot "
		   "transmit (session interface instead of access encap?)",
		   skipped, count);

  return 0;
}

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
