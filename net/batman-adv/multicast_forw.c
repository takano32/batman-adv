// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing
 */

#include "multicast.h"
#include "main.h"

#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/byteorder/generic.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/gfp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>
#include <linux/limits.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/linux/batadv_packet.h>

#include "bridge_loop_avoidance.h"
#include "originator.h"
#include "routing.h"
#include "send.h"
#include "translation-table.h"

#define batadv_mcast_forw_tracker_for_each_dest(dest, num_dests) \
	for (; num_dests; num_dests--, (dest) += ETH_ALEN)

/**
 * batadv_mcast_forw_orig_entry() - get orig_node from an hlist node
 * @node: the hlist node to get the orig_node from
 * @entry_offset: the offset of the hlist node within the orig_node struct
 *
 * Return: The orig_node containing the hlist node on success, NULL on error.
 */
static struct batadv_orig_node *
batadv_mcast_forw_orig_entry(struct hlist_node *node,
			     size_t entry_offset)
{
	/* sanity check */
	switch (entry_offset) {
	case offsetof(struct batadv_orig_node, mcast_want_all_ipv4_node):
	case offsetof(struct batadv_orig_node, mcast_want_all_ipv6_node):
	case offsetof(struct batadv_orig_node, mcast_want_all_rtr4_node):
	case offsetof(struct batadv_orig_node, mcast_want_all_rtr6_node):
		break;
	default:
		WARN_ON(1);
		return NULL;
	}

	return (struct batadv_orig_node *)((void *)node - entry_offset);
}

/**
 * batadv_mcast_forw_push_dest() - push an originator MAC address onto an skb
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the destination address onto
 * @vid: the vlan identifier
 * @orig_node: the originator node to get the MAC address from
 * @num_dests: a pointer to store the number of pushed addresses in
 *
 * If the orig_node is a BLA backbone gateway, if there is not enough skb
 * headroom available or if num_dests is already at its maximum (65535) then
 * neither the skb nor num_dests is changed. Otherwise the originator's MAC
 * address is pushed onto the given skb and num_dests incremented by one.
 *
 * Return: true if the orig_node is a backbone gateway or if an orig address
 *  was pushed successfully.
 */
static bool batadv_mcast_forw_push_dest(struct batadv_priv *bat_priv,
					struct sk_buff *skb, unsigned short vid,
					struct batadv_orig_node *orig_node,
					unsigned short *num_dests)
{
	BUILD_BUG_ON(sizeof_field(struct batadv_tvlv_mcast_tracker, num_dests)
		     != sizeof(__be16));

	/* Avoid sending to other BLA gateways - they already got the frame from
	 * the LAN side we share with them.
	 * TODO: Refactor to take BLA into account earlier in mode check.
	 */
	if (batadv_bla_is_backbone_gw_orig(bat_priv, orig_node->orig, vid))
		return true;

	if (skb_headroom(skb) < ETH_ALEN || *num_dests == U16_MAX)
		return false;

	skb_push(skb, ETH_ALEN);
	ether_addr_copy(skb->data, orig_node->orig);
	(*num_dests)++;

	return true;
}

/**
 * batadv_mcast_forw_push_dests_list() - push originators from list onto an skb
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the destination addresses onto
 * @vid: the vlan identifier
 * @head: the list to gather originators from
 * @entry_offset: offset of an hlist node in an orig_node structure
 * @num_dests: a pointer to store the number of pushed addresses in
 *
 * Push the MAC addresses of all originators in the given list onto the given
 * skb.
 *
 * Return: true on success, false otherwise.
 */
static int batadv_mcast_forw_push_dests_list(struct batadv_priv *bat_priv,
					     struct sk_buff *skb,
					     unsigned short vid,
					     struct hlist_head *head,
					     size_t entry_offset,
					     unsigned short *num_dests)
{
	struct hlist_node *node;
	struct batadv_orig_node *orig_node;

	rcu_read_lock();
	__hlist_for_each_rcu(node, head) {
		orig_node = batadv_mcast_forw_orig_entry(node, entry_offset);
		if (!orig_node ||
		    !batadv_mcast_forw_push_dest(bat_priv, skb, vid, orig_node,
						 num_dests)) {
			rcu_read_unlock();
			return false;
		}
	}
	rcu_read_unlock();

	return true;
}

/**
 * batadv_mcast_forw_push_tt() - push originators with interest through TT
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the destination addresses onto
 * @vid: the vlan identifier
 * @num_dests: a pointer to store the number of pushed addresses in
 *
 * Push the MAC addresses of all originators which have indicated interest in
 * this multicast packet through the translation table onto the given skb.
 *
 * Return: true on success, false otherwise.
 */
static bool
batadv_mcast_forw_push_tt(struct batadv_priv *bat_priv, struct sk_buff *skb,
			  unsigned short vid, unsigned short *num_dests)
{
	struct batadv_tt_orig_list_entry *orig_entry;

	struct batadv_tt_global_entry *tt_global;
	const u8 *addr = eth_hdr(skb)->h_dest;

	/* ok */
	int ret = true;

	tt_global = batadv_tt_global_hash_find(bat_priv, addr, vid);
	if (!tt_global)
		goto out;

	rcu_read_lock();
	hlist_for_each_entry_rcu(orig_entry, &tt_global->orig_list, list) {
		if (!batadv_mcast_forw_push_dest(bat_priv, skb, vid,
						 orig_entry->orig_node,
						 num_dests)) {
			ret = false;
			break;
		}
	}
	rcu_read_unlock();

	batadv_tt_global_entry_put(tt_global);

out:
	return ret;
}

/**
 * batadv_mcast_forw_push_want_all() - push originators with want-all flag
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the destination addresses onto
 * @vid: the vlan identifier
 * @num_dests: a pointer to store the number of pushed addresses in
 *
 * Push the MAC addresses of all originators which have indicated interest in
 * this multicast packet through the want-all flag onto the given skb.
 *
 * Return: true on success, false otherwise.
 */
static bool batadv_mcast_forw_push_want_all(struct batadv_priv *bat_priv,
					    struct sk_buff *skb,
					    unsigned short vid,
					    unsigned short *num_dests)
{
	struct hlist_head *head = NULL;
	size_t offset;
	int ret;

	switch (eth_hdr(skb)->h_proto) {
	case htons(ETH_P_IP):
		head = &bat_priv->mcast.want_all_ipv4_list;
		offset = offsetof(struct batadv_orig_node,
				  mcast_want_all_ipv4_node);
		break;
	case htons(ETH_P_IPV6):
		head = &bat_priv->mcast.want_all_ipv6_list;
		offset = offsetof(struct batadv_orig_node,
				  mcast_want_all_ipv6_node);
		break;
	default:
		return false;
	}

	ret = batadv_mcast_forw_push_dests_list(bat_priv, skb, vid, head,
						offset, num_dests);
	if (!ret)
		return false;

	return true;
}

/**
 * batadv_mcast_forw_push_want_rtr() - push originators with want-router flag
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the destination addresses onto
 * @vid: the vlan identifier
 * @num_dests: a pointer to store the number of pushed addresses in
 *
 * Push the MAC addresses of all originators which have indicated interest in
 * this multicast packet through the want-all-rtr flag onto the given skb.
 *
 * Return: true on success, false otherwise.
 */
static bool batadv_mcast_forw_push_want_rtr(struct batadv_priv *bat_priv,
					    struct sk_buff *skb,
					    unsigned short vid,
					    unsigned short *num_dests)
{
	struct hlist_head *head = NULL;
	size_t offset;
	int ret;

	switch (eth_hdr(skb)->h_proto) {
	case htons(ETH_P_IP):
		head = &bat_priv->mcast.want_all_rtr4_list;
		offset = offsetof(struct batadv_orig_node,
				  mcast_want_all_rtr4_node);
		break;
	case htons(ETH_P_IPV6):
		head = &bat_priv->mcast.want_all_rtr6_list;
		offset = offsetof(struct batadv_orig_node,
				  mcast_want_all_rtr6_node);
		break;
	default:
		return false;
	}

	ret = batadv_mcast_forw_push_dests_list(bat_priv, skb, vid, head,
						offset, num_dests);
	if (!ret)
		return false;

	return true;
}

/**
 * batadv_mcast_forw_push_dests() - push originator addresses onto an skb
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the destination addresses onto
 * @vid: the vlan identifier
 * @is_routable: indicates whether the destination is routable
 *
 * Push the MAC addresses of all originators which have indicated interest in
 * this multicast packet onto the given skb.
 *
 * Return: The number of destination originator MAC addresses that were pushed
 * onto the given skb.
 */
static int
batadv_mcast_forw_push_dests(struct batadv_priv *bat_priv, struct sk_buff *skb,
			     unsigned short vid, int is_routable)
{
	unsigned short num_dests = 0;

	if (!batadv_mcast_forw_push_tt(bat_priv, skb, vid, &num_dests))
		goto err;

	if (!batadv_mcast_forw_push_want_all(bat_priv, skb, vid, &num_dests))
		goto err;

	if (is_routable &&
	    !batadv_mcast_forw_push_want_rtr(bat_priv, skb, vid, &num_dests))
		goto err;

	return num_dests;
err:
	skb_pull(skb, num_dests * ETH_ALEN);
	return -ENOMEM;
}

/**
 * batadv_mcast_forw_tracker_hdrlen() - calculate tracker TVLV header length
 * @num_dests: the number of destination addresses to taken into account
 *
 * Return: The size of the multicast tracker TVLV structure if the number of
 * destinations is even or that size minus the 2 alignment bytes otherwise.
 */
static int batadv_mcast_forw_tracker_hdrlen(unsigned int num_dests)
{
	struct batadv_tvlv_mcast_tracker *mcast_tracker;
	unsigned int len = sizeof(*mcast_tracker);

	/* new #dests even: with 2 byte padding to TVLV */
	if (!(num_dests % 2))
		return len;
	/* new #dests odd: without 2 byte padding to TVLV */
	else
		return len - sizeof(mcast_tracker->align);
}

/**
 * batadv_mcast_forw_push_tracker() - push a multicast tracker TVLV header
 * @skb: the skb to push the tracker TVLV onto
 * @num_dests: the number of destination addresses to set in the header
 *
 * Pushes a multicast tracker TVLV header onto the given skb, including the
 * generic TVLV header but excluding the destination MAC addresses.
 *
 * The provided num_dests value is taken into consideration to set the
 * num_dests field in the tracker header and to set the appropriate TVLV length
 * value fields. But also to decide whether to add or omit the 2 alignment bytes
 * in the multicast tracker TVLV header, to make the tracker TVLV 4 byte aligned
 * to make the encapsulated IP packet 4 byte aligned.
 *
 * Return: -ENOMEM if there is not enough skb headroom available. Otherwise, on
 * success the number of bytes that were pushed, the total TVLV length value.
 */
static int batadv_mcast_forw_push_tracker(struct sk_buff *skb, int num_dests)
{
	struct batadv_tvlv_mcast_tracker *mcast_tracker;
	unsigned int tvlv_value_len, tracker_hdrlen;
	struct batadv_tvlv_hdr *tvlv_hdr;

	/* odd #dests: no 2 byte padding to TVLV */
	tracker_hdrlen = batadv_mcast_forw_tracker_hdrlen(num_dests);

	if (skb_headroom(skb) < tracker_hdrlen + sizeof(*tvlv_hdr))
		return -ENOMEM;

	tvlv_value_len = tracker_hdrlen + ETH_ALEN * num_dests;
	if (tvlv_value_len + sizeof(*tvlv_hdr) > U16_MAX)
		return -ENOMEM;

	skb_push(skb, tracker_hdrlen);
	mcast_tracker = (struct batadv_tvlv_mcast_tracker *)skb->data;
	mcast_tracker->num_dests = htons(num_dests);

	/* even #dests: with 2 byte padding to TVLV */
	if (!(num_dests % 2))
		memset(mcast_tracker->align, 0, sizeof(mcast_tracker->align));

	skb_reset_network_header(skb);

	skb_push(skb, sizeof(*tvlv_hdr));
	tvlv_hdr = (struct batadv_tvlv_hdr *)skb->data;
	tvlv_hdr->type = BATADV_TVLV_MCAST_TRACKER;
	tvlv_hdr->version = 1;
	tvlv_hdr->len = htons(tvlv_value_len);

	return tvlv_value_len + sizeof(*tvlv_hdr);
}

/**
 * batadv_mcast_forw_push_tvlvs() - push a multicast tracker TVLV onto an skb
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to push the tracker TVLV onto
 * @vid: the vlan identifier
 * @is_routable: indicates whether the destination is routable
 *
 * Pushes a multicast tracker TVLV onto the given skb, including the collected
 * destination MAC addresses and the generic TVLV header.
 *
 * Return: -ENOMEM if there is not enough skb headroom available. Otherwise, on
 * success the number of bytes that were pushed, the total TVLV length value.
 */
static int
batadv_mcast_forw_push_tvlvs(struct batadv_priv *bat_priv, struct sk_buff *skb,
			     unsigned short vid, int is_routable)
{
	int num_dests, tvlv_len;

	num_dests = batadv_mcast_forw_push_dests(bat_priv, skb, vid,
						 is_routable);
	if (num_dests <	0)
		return num_dests;

	tvlv_len = batadv_mcast_forw_push_tracker(skb, num_dests);
	if (tvlv_len < 0)
		skb_pull(skb, num_dests * ETH_ALEN);

	return tvlv_len;
}

/**
 * batadv_mcast_forw_push_hdr() - push a multicast packet header onto an skb
 * @skb: the skb to push the header onto
 * @tvlv_len: the total TVLV length value to set in the header
 *
 * Pushes a batman-adv multicast packet header onto the given skb and sets
 * the provided total TVLV length value in it.
 *
 * Caller needs to ensure enough skb headroom is available.
 *
 * Return: -ENOMEM if there is not enough skb headroom available. Otherwise, on
 * success 0.
 */
static int batadv_mcast_forw_push_hdr(struct sk_buff *skb, int tvlv_len)
{
	struct batadv_mcast_packet *mcast_packet;

	if (skb_headroom(skb) < sizeof(*mcast_packet))
		return -ENOMEM;

	skb_push(skb, sizeof(*mcast_packet));

	mcast_packet = (struct batadv_mcast_packet *)skb->data;
	mcast_packet->version = BATADV_COMPAT_VERSION;
	mcast_packet->ttl = BATADV_TTL;
	mcast_packet->packet_type = BATADV_MCAST;
	mcast_packet->reserved = 0;
	mcast_packet->tvlv_len = htons(tvlv_len);

	return 0;
}

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
	unsigned int tvlv_len, tracker_hdrlen;
	struct batadv_neigh_node *neigh_node;
	unsigned long offset, num_dests_off;
	struct sk_buff *nexthop_skb;
	unsigned char *skb_net_hdr;
	bool local_recv = false;
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

	tracker_hdrlen = batadv_mcast_forw_tracker_hdrlen(num_dests);
	dest = (u8 *)mcast_tracker + tracker_hdrlen;

	/* check if full tracker tvlv is within skb length */
	tvlv_len = tracker_hdrlen + ETH_ALEN * num_dests;
	if (tvlv_len > skb_network_header_len(skb))
		return -EINVAL;

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

/**
 * batadv_mcast_forw_packet_hdrlen() - multicast packet header length
 * @num_dests: number of destination nodes
 *
 * Calculates the total batman-adv multicast packet header length for a given
 * number of destination nodes (excluding the outter ethernet frame).
 *
 * Return: The calculated total batman-adv multicast packet header length.
 */
unsigned int batadv_mcast_forw_packet_hdrlen(unsigned int num_dests)
{
	return num_dests * ETH_ALEN +
	       batadv_mcast_forw_tracker_hdrlen(num_dests) +
	       sizeof(struct batadv_tvlv_hdr) +
	       sizeof(struct batadv_mcast_packet);
}

/**
 * batadv_mcast_forw_expand_head() - expand headroom for an mcast packet
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the multicast packet to send
 *
 * Tries to expand an skb's headroom so that its head to tail is 1298
 * bytes (minimum IPv6 MTU + vlan ethernet header size) large.
 *
 * Return: -EINVAL if the given skb's length is too large or -ENOMEM on memory
 * allocation failure. Otherwise, on success, zero is returned.
 */
static int batadv_mcast_forw_expand_head(struct batadv_priv *bat_priv,
					 struct sk_buff *skb)
{
	int hdr_size = VLAN_ETH_HLEN + IPV6_MIN_MTU - skb->len;

	 /* TODO: Could be tightened to actual number of destination nodes?
	  * But it's tricky, number of destinations might have increased since
	  * we last checked.
	  */
	if (hdr_size < 0) {
		/* batadv_mcast_forw_mode_check_count() should ensure we do not
		 * end up here
		 */
		WARN_ON(1);
		return -EINVAL;
	}

	if (skb_headroom(skb) < hdr_size &&
	    pskb_expand_head(skb, hdr_size, 0, GFP_ATOMIC) < 0)
		return -ENOMEM;

	return 0;
}

/**
 * batadv_mcast_forw_push() - encapsulate skb in a batman-adv multicast packet
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the multicast packet to encapsulate and send
 * @vid: the vlan identifier
 * @is_routable: indicates whether the destination is routable
 *
 * Encapsulates the given multicast packet in a batman-adv multicast packet.
 * A multicast tracker TVLV with destination originator addresses for any node
 * that signaled interest in it, that is either via the translation table or the
 * according want-all flags, is attached accordingly.
 *
 * Return: true on success, false otherwise.
 */
bool batadv_mcast_forw_push(struct batadv_priv *bat_priv, struct sk_buff *skb,
			    unsigned short vid, int is_routable)
{
	int tvlv_len;

	if (batadv_mcast_forw_expand_head(bat_priv, skb) < 0)
		return false;

	skb_reset_transport_header(skb);

	tvlv_len = batadv_mcast_forw_push_tvlvs(bat_priv, skb, vid,
						is_routable);
	if (tvlv_len < 0)
		return false;

	if (batadv_mcast_forw_push_hdr(skb, tvlv_len) < 0) {
		skb_pull(skb, tvlv_len);
		return false;
	}

	return true;
}

/**
 * batadv_mcast_forw_mcsend() - send a self prepared batman-adv multicast packet
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the multicast packet to encapsulate and send
 *
 * Transmits a batman-adv multicast packet that was locally prepared and
 * consumes/frees it.
 *
 * Return: NET_XMIT_DROP on memory allocation failure. NET_XMIT_SUCCESS
 * otherwise.
 */
int batadv_mcast_forw_mcsend(struct batadv_priv *bat_priv,
			     struct sk_buff *skb)
{
	int ret = batadv_mcast_forw_packet(bat_priv, skb, true);

	if (ret < 0) {
		kfree_skb(skb);
		return NET_XMIT_DROP;
	}

	consume_skb(skb);
	return NET_XMIT_SUCCESS;
}
