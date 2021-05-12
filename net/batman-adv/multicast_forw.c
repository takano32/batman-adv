// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing
 */

#include "multicast.h"
#include "main.h"

#include <linux/byteorder/generic.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/gfp.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <uapi/linux/batadv_packet.h>

#include "originator.h"
#include "routing.h"
#include "send.h"

#define batadv_mcast_forw_tracker_for_each_dest(dest, num_dests) \
	for (; num_dests; num_dests--, (dest) += ETH_ALEN)

/**
 * batadv_mcast_forw_orig_to_neigh() - get next hop neighbor to an orig address
 * @bat_priv: the bat priv with all the soft interface information
 * @orig_addr: the originator MAC address to search the best next hop router for
 *
 * Return: A neighbor node which is the best router towards the given originator
 * address.
 */
static struct batadv_neigh_node *
batadv_mcast_forw_orig_to_neigh(struct batadv_priv *bat_priv, u8 *orig_addr)
{
	struct batadv_neigh_node *neigh_node;
	struct batadv_orig_node *orig_node;

	orig_node = batadv_orig_hash_find(bat_priv, orig_addr);
	if (!orig_node)
		return NULL;

	neigh_node = batadv_find_router(bat_priv, orig_node, NULL);
	batadv_orig_node_put(orig_node);

	return neigh_node;
}

/**
 * batadv_mcast_forw_scrub_dests() - scrub destinations in a tracker TVLV
 * @bat_priv: the bat priv with all the soft interface information
 * @comp_neigh: next hop neighbor to scrub+collect destinations for
 * @dest: start MAC entry in original skb's tracker TVLV
 * @next_dest: start MAC entry in to be sent skb's tracker TVLV
 * @num_dests: number of remaining destination MAC entries to iterate over
 *
 * This sorts destination entries into either the original batman-adv
 * multicast packet or the skb (copy) that is going to be sent to comp_neigh
 * next.
 *
 * In preparation for the next, to be (unicast) transmitted batman-adv multicast
 * packet skb to be sent to the given neighbor node, tries to collect all
 * originator MAC addresses that have the given neighbor node as their next hop
 * in the to be transmitted skb (copy), which next_dest points into. That is we
 * zero all destination entries in next_dest which do not have comp_neigh as
 * their next hop. And zero all destination entries in the original skb that
 * would have comp_neigh as their next hop (to avoid redundant transmissions and
 * duplicated payload later).
 */
static void
batadv_mcast_forw_scrub_dests(struct batadv_priv *bat_priv,
			      struct batadv_neigh_node *comp_neigh, u8 *dest,
			      u8 *next_dest, u16 num_dests)
{
	struct batadv_neigh_node *next_neigh;

	/* skip first entry, this is what we are comparing with */
	eth_zero_addr(dest);
	dest += ETH_ALEN;
	next_dest += ETH_ALEN;
	num_dests--;

	batadv_mcast_forw_tracker_for_each_dest(next_dest, num_dests) {
		if (is_zero_ether_addr(next_dest))
			goto scrub_next;

		if (is_multicast_ether_addr(next_dest)) {
			eth_zero_addr(dest);
			eth_zero_addr(next_dest);
			goto scrub_next;
		}

		next_neigh = batadv_mcast_forw_orig_to_neigh(bat_priv,
							     next_dest);
		if (!next_neigh) {
			eth_zero_addr(next_dest);
			goto scrub_next;
		}

		/* Is this for our next packet to transmit? */
		if (batadv_compare_eth(next_neigh->addr, comp_neigh->addr))
			eth_zero_addr(dest);
		else
			eth_zero_addr(next_dest);

		batadv_neigh_node_put(next_neigh);
scrub_next:
		dest += ETH_ALEN;
	}
}

/**
 * batadv_mcast_forw_packet() - forward a batman-adv multicast packet
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the received or locally generated batman-adv multicast packet
 * @local_xmit: indicates that the packet was locally generated and not received
 *
 * Parses the tracker TVLV of a batman-adv multicast packet and forwards the
 * packet as indicated in this TVLV.
 *
 * Caller needs to set the skb network header to the start of the multicast
 * tracker TVLV (excluding the generic TVLV header) and the skb transport header
 * to the next byte after this multicast tracker TVLV.
 *
 * Caller needs to free the skb.
 *
 * Return: NET_RX_SUCCESS or NET_RX_DROP on success or a negative error
 * code on failure. NET_RX_SUCCESS if the received packet is supposed to be
 * decapsulated and forwarded to the own soft interface, NET_RX_DROP otherwise.
 */
static int batadv_mcast_forw_packet(struct batadv_priv *bat_priv,
				    struct sk_buff *skb, bool local_xmit)
{
	struct batadv_tvlv_mcast_tracker *mcast_tracker;
	struct batadv_neigh_node *neigh_node;
	unsigned long offset, num_dests_off;
	struct sk_buff *nexthop_skb;
	unsigned char *skb_net_hdr;
	bool local_recv = false;
	unsigned int tvlv_len;
	bool xmitted = false;
	u8 *dest, *next_dest;
	u16 num_dests;
	int ret;

	/* check if num_dests is within skb length */
	num_dests_off = offsetof(struct batadv_tvlv_mcast_tracker, num_dests);
	if (num_dests_off > skb_network_header_len(skb))
		return -EINVAL;

	skb_net_hdr = skb_network_header(skb);
	mcast_tracker = (struct batadv_tvlv_mcast_tracker *)skb_net_hdr;
	num_dests = ntohs(mcast_tracker->num_dests);

	dest = (u8 *)mcast_tracker + sizeof(*mcast_tracker);

	/* check if full tracker tvlv is within skb length */
	tvlv_len = sizeof(*mcast_tracker) + ETH_ALEN * num_dests;
	if (tvlv_len > skb_network_header_len(skb))
		return -EINVAL;

	/* invalidate checksum: */
	skb->ip_summed = CHECKSUM_NONE;

	batadv_mcast_forw_tracker_for_each_dest(dest, num_dests) {
		if (is_zero_ether_addr(dest))
			continue;

		/* only unicast originator addresses supported */
		if (is_multicast_ether_addr(dest)) {
			eth_zero_addr(dest);
			continue;
		}

		if (batadv_is_my_mac(bat_priv, dest)) {
			eth_zero_addr(dest);
			local_recv = true;
			continue;
		}

		neigh_node = batadv_mcast_forw_orig_to_neigh(bat_priv, dest);
		if (!neigh_node) {
			eth_zero_addr(dest);
			continue;
		}

		nexthop_skb = skb_copy(skb, GFP_ATOMIC);
		if (!nexthop_skb) {
			batadv_neigh_node_put(neigh_node);
			return -ENOMEM;
		}

		offset = dest - skb->data;
		next_dest = nexthop_skb->data + offset;

		batadv_mcast_forw_scrub_dests(bat_priv, neigh_node, dest,
					      next_dest, num_dests);

		batadv_inc_counter(bat_priv, BATADV_CNT_MCAST_TX);
		batadv_add_counter(bat_priv, BATADV_CNT_MCAST_TX_BYTES,
				   nexthop_skb->len + ETH_HLEN);
		xmitted = true;
		ret = batadv_send_unicast_skb(nexthop_skb, neigh_node);

		batadv_neigh_node_put(neigh_node);

		if (ret < 0)
			return ret;
	}

	if (xmitted) {
		if (local_xmit) {
			batadv_inc_counter(bat_priv, BATADV_CNT_MCAST_TX_LOCAL);
			batadv_add_counter(bat_priv,
					   BATADV_CNT_MCAST_TX_LOCAL_BYTES,
					   skb->len -
					   skb_transport_offset(skb));
		} else {
			batadv_inc_counter(bat_priv, BATADV_CNT_MCAST_FWD);
			batadv_add_counter(bat_priv, BATADV_CNT_MCAST_FWD_BYTES,
					   skb->len + ETH_HLEN);
		}
	}

	if (local_recv)
		return NET_RX_SUCCESS;
	else
		return NET_RX_DROP;
}

/**
 * batadv_mcast_forw_tracker_tvlv_handler() - handle an mcast tracker tvlv
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the received batman-adv multicast packet
 *
 * Parses the tracker TVLV of an incoming batman-adv multicast packet and
 * forwards the packet as indicated in this TVLV.
 *
 * Caller needs to set the skb network header to the start of the multicast
 * tracker TVLV (excluding the generic TVLV header) and the skb transport header
 * to the next byte after this multicast tracker TVLV.
 *
 * Caller needs to free the skb.
 *
 * Return: NET_RX_SUCCESS or NET_RX_DROP on success or a negative error
 * code on failure. NET_RX_SUCCESS if the received packet is supposed to be
 * decapsulated and forwarded to the own soft interface, NET_RX_DROP otherwise.
 */
int batadv_mcast_forw_tracker_tvlv_handler(struct batadv_priv *bat_priv,
					   struct sk_buff *skb)
{
	return batadv_mcast_forw_packet(bat_priv, skb, false);
}
