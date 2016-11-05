/* Copyright (C) 2016  B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "aggregation.h"
#include "main.h"

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "send.h"
#include "tvlv.h"

/**
 * batadv_aggr_hardif_start - schedule aggregation packet transmission
 * @hard_iface: the hard interface to schedule the transmission on
 *
 * Schedules an aggregation packet transmission for the next aggregation
 * interval, plus/minus some jitter.
 */
void batadv_aggr_hardif_start(struct batadv_hard_iface *hard_iface)
{
	unsigned int msecs = BATADV_MAX_AGGREGATION_MS * 1000;

	/* msecs * [0.9, 1.1] */
	msecs += prandom_u32() % (msecs / 5) - (msecs / 10);
	queue_delayed_work(batadv_event_workqueue, &hard_iface->aggr.work,
			   msecs_to_jiffies(msecs / 1000));
}

/**
 * batadv_aggr_hardif_start_urgent - schedule urgent aggregate transmission
 * @hard_iface: the hard interface to schedule the transmission on
 *
 * Schedules an urgent aggregation packet transmission, plus/minus some jitter.
 * That is at some time between an interval 10 to 20 times faster than the
 * regular aggregation interval.
 */
static void
batadv_aggr_hardif_start_urgent(struct batadv_hard_iface *hard_iface)
{
	unsigned int msecs = BATADV_MAX_AGGREGATION_MS * 1000;

	/* msecs * [0.05, 0.1] */
	msecs = (msecs / 20) + prandom_u32() % (msecs / 20);
	queue_delayed_work(batadv_event_workqueue, &hard_iface->aggr.work,
			   msecs_to_jiffies(msecs / 1000));
}

/**
 * batadv_aggr_skb_queue_free - free all elements in an skb queue
 * @head: the skb queue to empty
 *
 * Empties an skb queue and frees all the skbs it contained.
 */
static void batadv_aggr_skb_queue_free(struct sk_buff_head *head)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(head)))
		kfree_skb(skb);
}

/**
 * batadv_aggr_hardif_stop - shutdown an aggregation routine
 * @hard_iface: the interface to stop aggregation on
 *
 * Stops an aggregation timer and destroys the packets queued
 * on the given interface.
 */
void batadv_aggr_hardif_stop(struct batadv_hard_iface *hard_iface)
{
	cancel_delayed_work_sync(&hard_iface->aggr.work);

	spin_lock_bh(&hard_iface->aggr.aggr_list_lock);
	batadv_aggr_skb_queue_free(&hard_iface->aggr.aggr_list);
	spin_unlock_bh(&hard_iface->aggr.aggr_list_lock);
}

/**
 * batadv_aggr_chunk_reserve - reserve space in an aggregation packet
 * @hard_iface: the interface to reserve on
 * @skb: the to be aggregated packet to reserve for
 * @size: size of the aggregation packet
 *
 * Tries to reserve space in the aggregation packet for the given skb.
 * If reservation was successful, then the size of the to be allocated
 * aggregation packet is increased accordingly.
 *
 * Return: True if there was enough space in the aggregation packet left,
 * false otherwise.
 */
static bool batadv_aggr_chunk_reserve(struct batadv_hard_iface *hard_iface,
				      struct sk_buff *skb,
				      int *size)
{
	unsigned int len = skb->len + sizeof(struct batadv_tvlv_hdr);

	len -= sizeof(((struct batadv_aggr_packet *)0)->packet_type);
	len -= sizeof(((struct batadv_aggr_packet *)0)->version);

	if (*size + len > hard_iface->net_dev->mtu)
		return false;

	*size += len;
	return true;
}

/**
 * batadv_aggr_get_chunk - gets a chunk of packets from the aggregation queue
 * @hard_iface: the interface to get to be aggregated packets from
 * @head: queue to stage a chunk of to be aggregated+transmitted packets on
 * @size: size of the aggregation packet
 *
 * Tries to grab as many packets from the aggregation queue as fit into a
 * single aggregation packet.
 *
 * Return: True if there are no packets in the aggregation queue
 * of the provided interface left afterwards, false otherwise.
 */
static bool batadv_aggr_get_chunk(struct batadv_hard_iface *hard_iface,
				  struct sk_buff_head *head,
				  int *size)
{
	struct sk_buff *skb, *skb_tmp;
	bool emptied = true;

	*size = sizeof(struct batadv_aggr_packet);

	if (skb_queue_empty(&hard_iface->aggr.aggr_list))
		return emptied;

	spin_lock_bh(&hard_iface->aggr.aggr_list_lock);
	skb_queue_walk_safe(&hard_iface->aggr.aggr_list, skb, skb_tmp) {
		if (!batadv_aggr_chunk_reserve(hard_iface, skb, size)) {
			emptied = false;
			break;
		}

		skb_unlink(skb, &hard_iface->aggr.aggr_list);
		skb_queue_tail(head, skb);
	}
	spin_unlock_bh(&hard_iface->aggr.aggr_list_lock);

	return emptied;
}

/**
 * batadv_aggr_alloc_skb - allocate an aggregation packet
 * @size: size of the to be allocated packet (excluding ethernet header)
 *
 * Allocates a broadcast aggregation packet.
 *
 * Return: An aggregation packet on success, NULL otherwise.
 */
static struct sk_buff *batadv_aggr_alloc_skb(int size)
{
	struct batadv_aggr_packet *aggr_packet;
	struct sk_buff *skb;
	unsigned char *skb_buff;
	unsigned int offset;

	skb = dev_alloc_skb(size + ETH_HLEN + NET_IP_ALIGN);
	if (!skb)
		return NULL;

	skb_reserve(skb, ETH_HLEN + NET_IP_ALIGN);
	skb_reset_network_header(skb);

	skb_buff = skb_put(skb, sizeof(*aggr_packet));
	aggr_packet = (struct batadv_aggr_packet *)skb_buff;
	aggr_packet->packet_type = BATADV_BCAST_AGGR;
	aggr_packet->version = BATADV_COMPAT_VERSION;

	offset = skb_network_offset(skb) + sizeof(*aggr_packet);
	skb_set_transport_header(skb, offset);

	return skb;
}

/**
 * batadv_aggr_get_pkttypes - get the packet type of a batman packet
 * @skb: the packet to get the type from
 *
 * Return: The packet type of the provided batman packet.
 */
static u8 batadv_aggr_get_pkttype(struct sk_buff *skb)
{
	struct batadv_aggr_packet *packet;

	packet = (struct batadv_aggr_packet *)skb_network_header(skb);

	return packet->packet_type;
}

/**
 * batadv_aggr_put_tvlvhdr - append a tvlv header to an skb
 * @skb: the aggregation packet to append the tvlv header to
 * @type: the packet (= tvlv) type to set in the tvlv header
 * @len: the size of the to be added tvlv data
 *
 * Appends a tvlv header to the given aggregation packet and sets its type and
 * length as provided.
 */
static void batadv_aggr_put_tvlvhdr(struct sk_buff *skb, u8 type,
				    unsigned int len)
{
	struct batadv_tvlv_hdr *tvlv_hdr;

	tvlv_hdr = (struct batadv_tvlv_hdr *)skb_put(skb, sizeof(*tvlv_hdr));

	tvlv_hdr->type = type;
	tvlv_hdr->version = 1;
	tvlv_hdr->len = htons(len);
}

/**
 * batadv_aggr_queue_is_full - check for slots left in aggregation queue
 * @hard_iface: the interface to check
 *
 * Return: True if if the queue is full, false otherwise.
 */
static inline bool
batadv_aggr_queue_is_full(struct batadv_hard_iface *hard_iface)
{
	struct sk_buff_head *head = &hard_iface->aggr.aggr_list;

	return skb_queue_len(head) >= BATADV_AGGR_QUEUE_LEN;
}

/**
 * batadv_aggr_squash_chunk - squash packets into an aggregate
 * @head: a list of to be squashed packets
 * @size: the size of the to be created aggregation packet
 *  (excluding the ethernet header)
 *
 * Allocates an aggregation packet and squashes the provided list of broadcast
 * packets into it. The provided list of packets is freed/consumed.
 *
 * Return: An aggregation packet ready for transmission on success, NULL
 * otherwise.
 */
static struct sk_buff *
batadv_aggr_squash_chunk(struct sk_buff_head *head,
			 int size)
{
	struct sk_buff *skb, *skb_tmp, *skb_aggr;
	struct batadv_aggr_packet *aggr_packet;
	unsigned int len, offset, tvlv_len = 0;
	unsigned char *to;
	u8 type;

	if (skb_queue_empty(head))
		return NULL;

	skb_aggr = batadv_aggr_alloc_skb(size);
	if (!skb_aggr) {
		batadv_aggr_skb_queue_free(head);
		return NULL;
	}

	aggr_packet = (struct batadv_aggr_packet *)skb_network_header(skb_aggr);

	skb_queue_walk_safe(head, skb, skb_tmp) {
		offset = skb_network_offset(skb);
		offset += sizeof(aggr_packet->packet_type);
		offset += sizeof(aggr_packet->version);
		len = skb->len - offset;
		type = batadv_aggr_get_pkttype(skb);

		batadv_aggr_put_tvlvhdr(skb_aggr, type, len);
		to = skb_put(skb_aggr, len);
		skb_copy_bits(skb, offset, to, len);
		skb_unlink(skb, head);
		consume_skb(skb);

		tvlv_len += len + sizeof(struct batadv_tvlv_hdr);
	}

	aggr_packet->tvlv_len = htons(tvlv_len);

	return skb_aggr;
}

/**
 * __batadv_aggr_send_chunk - send a prepared aggregation packet
 * @hard_iface: the interface to transmit on
 * @skb: the prepared aggregation packet to send
 */
static void __batadv_aggr_send_chunk(struct batadv_hard_iface *hard_iface,
				     struct sk_buff *skb)
{
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);

	batadv_inc_counter(bat_priv, BATADV_CNT_AGGR_TX);
	batadv_add_counter(bat_priv, BATADV_CNT_AGGR_TX_BYTES,
			   skb->len + ETH_HLEN);

	/* ToDo: Track transmission failures? */
	batadv_send_skb_packet(skb, hard_iface, batadv_broadcast_addr);
}

/**
 * batadv_aggr_send_chunk - prepare and transmit an aggregation packet
 * @hard_iface: the interface to transmit on
 *
 * Fetches as many packets from the aggregation queue of the provided interface
 * as fit into a single aggregation packet. Then aggregates them into such an
 * aggregation packet and transmits the final aggregate.
 *
 * Return: True if there are no packets in the aggregation queue
 * of the provided interface left afterwards, false otherwise.
 */
static bool batadv_aggr_send_chunk(struct batadv_hard_iface *hard_iface)
{
	struct sk_buff_head head;
	struct sk_buff *skb;
	int size = 0;
	bool emptied;

	skb_queue_head_init(&head);
	emptied = batadv_aggr_get_chunk(hard_iface, &head, &size);

	skb = batadv_aggr_squash_chunk(&head, size);
	if (!skb)
		goto out;

	__batadv_aggr_send_chunk(hard_iface, skb);

out:
	return emptied;
}

/**
 * batadv_aggr_work - periodic aggregation worker
 * @work: work queue item
 *
 * Prepares and sends out an aggregation packet. In the end rearms the timer
 * either to the next aggregation interval, or if there were still packets left
 * in the aggregation queue, sets it to an earlier time.
 */
static void batadv_aggr_work(struct work_struct *work)
{
	struct batadv_hard_iface_aggr *aggr;
	struct batadv_hard_iface *hard_iface;
	struct batadv_priv *bat_priv;
	bool emptied;

	aggr = container_of(work, struct batadv_hard_iface_aggr, work.work);
	hard_iface = container_of(aggr, struct batadv_hard_iface, aggr);
	bat_priv = netdev_priv(hard_iface->soft_iface);

	emptied = batadv_aggr_send_chunk(hard_iface);
	if (emptied) {
		batadv_aggr_hardif_start(hard_iface);
	} else {
		batadv_inc_counter(bat_priv, BATADV_CNT_AGGR_URGENT);
		batadv_aggr_hardif_start_urgent(hard_iface);
	}
}

/**
 * batadv_aggr_queue - queue a broadcast packet for aggregation
 * @skb: the packet to queue
 * @hard_iface: the interface to queue on
 *
 * Return: NET_XMIT_SUCCESS if the skb was queued, NET_XMIT_DROP otherwise.
 * The former consumes the skb.
 */
int batadv_aggr_queue(struct sk_buff *skb, struct batadv_hard_iface *hard_iface)
{
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);

	if (!atomic_read(&bat_priv->aggregation))
		return NET_XMIT_DROP;

	if (atomic_read(&bat_priv->aggr_num_disabled))
		return NET_XMIT_DROP;

	if (batadv_aggr_queue_is_full(hard_iface)) {
		batadv_inc_counter(bat_priv, BATADV_CNT_AGGR_QUEUE_FULL);
		return NET_XMIT_DROP;
	}

	spin_lock_bh(&hard_iface->aggr.aggr_list_lock);
	skb_queue_tail(&hard_iface->aggr.aggr_list, skb);
	spin_unlock_bh(&hard_iface->aggr.aggr_list_lock);

	batadv_inc_counter(bat_priv, BATADV_CNT_AGGR_PARTS_TX);
	batadv_add_counter(bat_priv, BATADV_CNT_AGGR_PARTS_TX_BYTES,
			   skb->len + ETH_HLEN);

	return NET_XMIT_SUCCESS;
}

/**
 * batadv_aggr_purge_orig - reset originator aggregation state modifications
 * @orig: the originator which is going to get purged
 */
void batadv_aggr_purge_orig(struct batadv_orig_node *orig)
{
	struct batadv_priv *bat_priv = orig->bat_priv;

	if (!test_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capabilities) &&
	    test_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capa_initialized))
		atomic_dec(&bat_priv->aggr_num_disabled);
}

/**
 * batadv_aggr_hardif_init - initialize an interface for aggregation
 * @hard_iface: the interface to initialize
 */
void batadv_aggr_hardif_init(struct batadv_hard_iface *hard_iface)
{
	INIT_DELAYED_WORK(&hard_iface->aggr.work, batadv_aggr_work);
	skb_queue_head_init(&hard_iface->aggr.aggr_list);
	spin_lock_init(&hard_iface->aggr.aggr_list_lock);
}

/**
 * batadv_aggr_add_counter_rx - update aggregation rx statistics
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the skb to count
 *
 * Updates statistics for received aggregation packets with the given skb.
 */
void batadv_aggr_add_counter_rx(struct batadv_priv *bat_priv,
				struct sk_buff *skb)
{
	batadv_inc_counter(bat_priv, BATADV_CNT_AGGR_RX);
	batadv_add_counter(bat_priv, BATADV_CNT_AGGR_RX_BYTES,
			   skb->len + ETH_HLEN);
}

/**
 * batadv_aggr_put_ethhdr - append a mac header to skb
 * @skb: the packet to append to
 * @h_source: the ethernet source address to set
 *
 * Appends a mac header to the given skb with the ethernet source address
 * set to the provided h_source and the ethernet destination address to
 * a broadcast one. Furthermore, sets the ethernet type to ETH_P_BATMAN.
 *
 * Also sets the skb mac header pointer to the beginning of the appended mac
 * header.
 */
static void batadv_aggr_put_ethhdr(struct sk_buff *skb, unsigned char *h_source)
{
	struct ethhdr *ethhdr;

	skb_reset_mac_header(skb);

	ethhdr = (struct ethhdr *)skb_put(skb, ETH_HLEN);
	ethhdr->h_proto = htons(ETH_P_BATMAN);
	ether_addr_copy(ethhdr->h_source, h_source);
	ether_addr_copy(ethhdr->h_dest, batadv_broadcast_addr);
}

/**
 * batadv_aggr_put_batadv - append batman header and data to skb
 * @skb: the packet to append to
 * @data: the data to append after the batman header
 * @data_len: the length of the data to append
 * @packet_type: the packet type to set in the batman header
 *
 * First appends a batman header consisting of the given packet type and the
 * compatibility version to the given skb. Then copies the given data behind
 * this minimal batman header in the skb.
 *
 * Also sets the skb network header pointer to the beginning of the batman
 * header.
 */
static void batadv_aggr_put_batadv(struct sk_buff *skb, void *data,
				   u16 data_len, u8 packet_type)
{
	u8 version = BATADV_COMPAT_VERSION;
	u8 *pos;

	skb_reset_network_header(skb);
	skb_reset_mac_len(skb);

	pos = (u8 *)skb_put(skb, sizeof(packet_type));
	*pos = packet_type;
	pos = (u8 *)skb_put(skb, sizeof(version));
	*pos = version;

	pos = (u8 *)skb_put(skb, data_len);
	memcpy(pos, data, data_len);
}

/**
 * batadv_aggr_tvlv_handler - process incoming aggregation tvlv container
 * @bat_priv: the bat priv with all the soft interface information
 * @tvlv_value: tvlv buffer containing an aggregated packet
 * @tvlv_value_len: length of the aggregated packet
 * @ctx: handler specific context information
 *  (here: recv_if, h_source and packet type of aggregated packet)
 *
 * De-aggregates the given, specific broadcast packet and transparently
 * forwards it for broadcast packet reception.
 *
 * Return: NET_RX_SUCCESS on success, NET_RX_DROP otherwise.
 */
static int batadv_aggr_tvlv_handler(struct batadv_priv *bat_priv,
				    void *tvlv_value, u16 tvlv_value_len,
				    void *ctx)
{
	struct batadv_aggr_ctx *aggr_ctx = ctx;
	struct batadv_hard_iface *recv_if = aggr_ctx->recv_if;
	struct sk_buff *skb;
	unsigned int size;
	u8 version = BATADV_COMPAT_VERSION;
	u8 packet_type = aggr_ctx->handler.tvlv_type;

	/* disallow aggr-in-aggr-in-... to avoid stack overflows */
	if (packet_type == BATADV_BCAST_AGGR)
		return NET_RX_DROP;

	size = NET_IP_ALIGN + ETH_HLEN;
	size += sizeof(packet_type) + sizeof(version);
	size += tvlv_value_len;

	skb = dev_alloc_skb(size);
	if (!skb)
		return NET_RX_DROP;

	skb_reserve(skb, NET_IP_ALIGN);
	batadv_aggr_put_ethhdr(skb, aggr_ctx->h_source);
	skb_pull(skb, ETH_HLEN);
	batadv_aggr_put_batadv(skb, tvlv_value, tvlv_value_len, packet_type);

	skb->protocol = htons(ETH_P_BATMAN);
	skb->dev = recv_if->net_dev;

	batadv_inc_counter(bat_priv, BATADV_CNT_AGGR_PARTS_RX);
	batadv_add_counter(bat_priv, BATADV_CNT_AGGR_PARTS_RX_BYTES,
			   skb->len + ETH_HLEN);

	return batadv_batman_skb_recv(skb, recv_if->net_dev,
				      &recv_if->batman_adv_ptype, NULL);
}

/**
 * batadv_aggr_ogm_handler - process incoming aggregation tvlv container
 * @bat_priv: the bat priv with all the soft interface information
 * @tvlv_value: tvlv buffer containing an aggregated broadcast packet
 * @tvlv_value_len: tvlv buffer length
 * @ctx: handler specific context information
 *  (here: recv_if, h_source and packet type of aggregate)
 *
 * Parses an aggregation tvlv attached to an originator message and updates
 * aggregation capabilities accordingly.
 *
 * Return: Always NET_RX_SUCCESS.
 */
static int batadv_aggr_ogm_handler(struct batadv_priv *bat_priv,
				   void *tvlv_value, u16 tvlv_value_len,
				   void *ctx)
{
	struct batadv_orig_node *orig = ctx;
	bool orig_aggr_enabled = !!tvlv_value;
	bool orig_initialized;

	orig_initialized = test_bit(BATADV_ORIG_CAPA_HAS_AGGR,
				    &orig->capa_initialized);

	/* If aggregation support is turned on decrease the disabled aggregation
	 * node counter only if we had increased it for this node before. If
	 * this is a completely new orig_node no need to decrease the counter.
	 */
	if (orig_aggr_enabled &&
	    !test_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capabilities)) {
		if (orig_initialized)
			atomic_dec(&bat_priv->aggr_num_disabled);
		set_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capabilities);
	/* If aggregation support is being switched off or if this is an initial
	 * OGM without aggregation support then increase the disabled
	 * aggregation node counter.
	 */
	} else if (!orig_aggr_enabled &&
		   (test_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capabilities) ||
		    !orig_initialized)) {
		atomic_inc(&bat_priv->aggr_num_disabled);
		clear_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capabilities);
	}

	set_bit(BATADV_ORIG_CAPA_HAS_AGGR, &orig->capa_initialized);

	return NET_RX_SUCCESS;
}

/**
 * batadv_aggr_mesh_init - initialise the generic aggregation engine
 * @bat_priv: the bat priv with all the soft interface information
 *
 * Return: 0 on success or a negative error code in case of failure
 */
int batadv_aggr_mesh_init(struct batadv_priv *bat_priv)
{
	batadv_tvlv_handler_register2(bat_priv, batadv_aggr_tvlv_handler,
				      BATADV_BCAST_AGGR, BATADV_TVLV_ANY, 1,
				      BATADV_TVLV_HANDLER_MORECTX);
	batadv_tvlv_handler_register2(bat_priv, batadv_aggr_ogm_handler,
				      BATADV_IV_OGM, BATADV_TVLV_AGGR, 1,
				      BATADV_TVLV_HANDLER_CIFNOTFND);
	batadv_tvlv_handler_register2(bat_priv, batadv_aggr_ogm_handler,
				      BATADV_OGM2, BATADV_TVLV_AGGR, 1,
				      BATADV_TVLV_HANDLER_CIFNOTFND);

	batadv_tvlv_container_register(bat_priv, BATADV_TVLV_AGGR, 1, NULL, 0);

	return 0;
}

/**
 * batadv_mcast_free - shutdown the generic aggregation engine
 * @bat_priv: the bat priv with all the soft interface information
 */
void batadv_aggr_mesh_free(struct batadv_priv *bat_priv)
{
	batadv_tvlv_container_unregister(bat_priv, BATADV_TVLV_AGGR, 1);
	batadv_tvlv_handler_unregister2(bat_priv, BATADV_OGM2, BATADV_TVLV_AGGR,
					1);
	batadv_tvlv_handler_unregister2(bat_priv, BATADV_IV_OGM,
					BATADV_TVLV_AGGR, 1);
	batadv_tvlv_handler_unregister2(bat_priv, BATADV_BCAST_AGGR,
					BATADV_TVLV_ANY, 1);
}
