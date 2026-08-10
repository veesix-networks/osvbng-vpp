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
 * Build a gratuitous ARP frame for IPv4.
 *
 * Uses ethernet_build_rewrite() which handles VLAN encapsulation (802.1q,
 * QinQ) automatically based on the sub-interface configuration. We then
 * overwrite the source MAC in the Ethernet header with the virtual MAC.
 */
void
osvbng_srg_garp_build (vlib_buffer_t *b, u32 sw_if_index,
		       ip4_address_t *ip4, mac_address_t *vmac)
{
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_header_t *eth;
  ethernet_arp_header_t *arp;
  int rewrite_bytes;
  u8 *rewrite;

  eth = vlib_buffer_get_current (b);

  rewrite =
    ethernet_build_rewrite (vnm, sw_if_index, VNET_LINK_ARP,
			    broadcast_mac.bytes);
  if (PREDICT_FALSE (!rewrite))
    return;

  rewrite_bytes = vec_len (rewrite);
  clib_memcpy (eth, rewrite, rewrite_bytes);
  vec_free (rewrite);

  /* Overwrite source MAC with virtual MAC */
  clib_memcpy (eth->src_address, vmac->bytes, 6);

  b->current_length += rewrite_bytes;
  vlib_buffer_advance (b, rewrite_bytes);

  arp = vlib_buffer_get_current (b);
  b->current_length += sizeof (*arp);

  clib_memset (arp, 0, sizeof (*arp));

  arp->l2_type = clib_host_to_net_u16 (ETHERNET_ARP_HARDWARE_TYPE_ethernet);
  arp->l3_type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);
  arp->n_l2_address_bytes = 6;
  arp->n_l3_address_bytes = 4;
  arp->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);
  arp->ip4_over_ethernet[0].mac = *vmac;
  arp->ip4_over_ethernet[0].ip4 = *ip4;
  arp->ip4_over_ethernet[1].mac = broadcast_mac;
  arp->ip4_over_ethernet[1].ip4 = *ip4;
}

/*
 * Build an unsolicited Neighbor Advertisement for IPv6.
 *
 * Destination: all-nodes multicast (ff02::1), Ethernet dst 33:33:00:00:00:01.
 * Source: link-local derived from vMAC via EUI-64.
 * ICMPv6 NA with OVERRIDE | ROUTER flags, target link-layer address option.
 */
void
osvbng_srg_na_build (vlib_main_t *vm, vlib_buffer_t *b, u32 sw_if_index,
		     ip6_address_t *ip6, mac_address_t *vmac)
{
  vnet_main_t *vnm = vnet_get_main ();
  ethernet_header_t *eth;
  ip6_header_t *ip6h;
  icmp6_neighbor_solicitation_or_advertisement_header_t *na;
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t *ll_opt;
  int payload_length, bogus_length;
  int rewrite_bytes;
  u8 *rewrite;
  u8 dst_mac[6];

  eth = vlib_buffer_get_current (b);

  /* All-nodes multicast MAC: 33:33:00:00:00:01 */
  ip6_multicast_ethernet_address (dst_mac, IP6_MULTICAST_GROUP_ID_all_hosts);
  rewrite =
    ethernet_build_rewrite (vnm, sw_if_index, VNET_LINK_IP6, dst_mac);
  if (PREDICT_FALSE (!rewrite))
    return;

  rewrite_bytes = vec_len (rewrite);
  clib_memcpy (eth, rewrite, rewrite_bytes);
  vec_free (rewrite);

  /* Overwrite source MAC with virtual MAC */
  clib_memcpy (eth->src_address, vmac->bytes, 6);

  b->current_length += rewrite_bytes;
  vlib_buffer_advance (b, rewrite_bytes);

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
  na->target_address = *ip6;
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
 * Batch send GARP/NA packets.
 *
 * Allocates buffers in VLIB_FRAME_SIZE batches, builds frames, and enqueues
 * to interface-output. VPP handles VLAN encapsulation on the TX path.
 * af_flags: 0 = IPv4 (GARP), 1 = IPv6 (NA).
 */
int
osvbng_srg_send_garp_batch (vlib_main_t *vm, u8 *srg_name,
			    u32 *sw_if_indices, ip46_address_t *ip_addrs,
			    u8 *af_flags, u32 count,
			    mac_address_t *virtual_mac)
{
  osvbng_srg_main_t *sm = &osvbng_srg_main;
  u32 srg_index = ~0;
  u32 offset = 0;

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
	  u32 idx = offset + i;
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi[i]);

	  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_indices[idx];

	  if (af_flags[idx])
	    {
	      osvbng_srg_na_build (vm, b, sw_if_indices[idx],
				   &ip_addrs[idx].ip6, virtual_mac);
	      if (srg_index != ~0)
		sm->na_sent[srg_index]++;
	    }
	  else
	    {
	      osvbng_srg_garp_build (b, sw_if_indices[idx],
				     &ip_addrs[idx].ip4, virtual_mac);
	      if (srg_index != ~0)
		sm->garp_sent[srg_index]++;
	    }

	  vlib_buffer_reset (b);

	  to_next[i] = bi[i];
	  to_frame->n_vectors++;
	}

      vlib_put_frame_to_node (vm, sm->intf_output_node_idx, to_frame);

      vec_free (bi);
      offset += batch;
    }

  return 0;
}

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
