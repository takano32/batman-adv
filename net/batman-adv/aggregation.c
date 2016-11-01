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

#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>

#include "tvlv.h"

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
	batadv_tvlv_handler_unregister2(bat_priv, BATADV_BCAST_AGGR,
					BATADV_TVLV_ANY, 1);
}
