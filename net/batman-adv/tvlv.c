/* Copyright (C) 2007-2017  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
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

#include "main.h"

#include <linux/byteorder/generic.h>
#include <linux/etherdevice.h>
#include <linux/fs.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/pkt_sched.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>

#include "originator.h"
#include "packet.h"
#include "send.h"
#include "tvlv.h"

/**
 * batadv_tvlv_handler_release - release tvlv handler from lists and queue for
 *  free after rcu grace period
 * @ref: kref pointer of the tvlv
 */
static void batadv_tvlv_handler_release(struct kref *ref)
{
	struct batadv_tvlv_handler *tvlv_handler;

	tvlv_handler = container_of(ref, struct batadv_tvlv_handler, refcount);
	kfree_rcu(tvlv_handler, rcu);
}

/**
 * batadv_tvlv_handler_put - decrement the tvlv container refcounter and
 *  possibly release it
 * @tvlv_handler: the tvlv handler to free
 */
static void batadv_tvlv_handler_put(struct batadv_tvlv_handler *tvlv_handler)
{
	kref_put(&tvlv_handler->refcount, batadv_tvlv_handler_release);
}

/**
 * batadv_tvlv_handler_get - retrieve tvlv handler from the tvlv handler list
 *  based on the provided type and version (both need to match)
 * @bat_priv: the bat priv with all the soft interface information
 * @packet_type: packet type to look for
 * @tvlv_type: tvlv handler type to look for
 * @tvlv_version: tvlv handler version to look for
 *
 * Return: tvlv handler if found or NULL otherwise.
 */
static struct batadv_tvlv_handler *
batadv_tvlv_handler_get(struct batadv_priv *bat_priv, int packet_type,
			u8 tvlv_type, u8 tvlv_version)
{
	struct batadv_tvlv_handler *tvlv_handler_tmp, *tvlv_handler = NULL;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tvlv_handler_tmp,
				 &bat_priv->tvlv.handler_list, list) {
		if (tvlv_handler_tmp->packet_type != packet_type)
			continue;

		if (tvlv_handler_tmp->tvlv_type != tvlv_type)
			continue;

		if (tvlv_handler_tmp->tvlv_version != tvlv_version)
			continue;

		if (!kref_get_unless_zero(&tvlv_handler_tmp->refcount))
			continue;

		tvlv_handler = tvlv_handler_tmp;
		break;
	}
	rcu_read_unlock();

	return tvlv_handler;
}

/**
 * batadv_tvlv_container_release - release tvlv from lists and free
 * @ref: kref pointer of the tvlv
 */
static void batadv_tvlv_container_release(struct kref *ref)
{
	struct batadv_tvlv_container *tvlv;

	tvlv = container_of(ref, struct batadv_tvlv_container, refcount);
	kfree(tvlv);
}

/**
 * batadv_tvlv_container_put - decrement the tvlv container refcounter and
 *  possibly release it
 * @tvlv: the tvlv container to free
 */
static void batadv_tvlv_container_put(struct batadv_tvlv_container *tvlv)
{
	kref_put(&tvlv->refcount, batadv_tvlv_container_release);
}

/**
 * batadv_tvlv_container_get - retrieve tvlv container from the tvlv container
 *  list based on the provided type and version (both need to match)
 * @bat_priv: the bat priv with all the soft interface information
 * @type: tvlv container type to look for
 * @version: tvlv container version to look for
 *
 * Has to be called with the appropriate locks being acquired
 * (tvlv.container_list_lock).
 *
 * Return: tvlv container if found or NULL otherwise.
 */
static struct batadv_tvlv_container *
batadv_tvlv_container_get(struct batadv_priv *bat_priv, u8 type, u8 version)
{
	struct batadv_tvlv_container *tvlv_tmp, *tvlv = NULL;

	lockdep_assert_held(&bat_priv->tvlv.container_list_lock);

	hlist_for_each_entry(tvlv_tmp, &bat_priv->tvlv.container_list, list) {
		if (tvlv_tmp->tvlv_hdr.type != type)
			continue;

		if (tvlv_tmp->tvlv_hdr.version != version)
			continue;

		kref_get(&tvlv_tmp->refcount);
		tvlv = tvlv_tmp;
		break;
	}

	return tvlv;
}

/**
 * batadv_tvlv_container_list_size - calculate the size of the tvlv container
 *  list entries
 * @bat_priv: the bat priv with all the soft interface information
 *
 * Has to be called with the appropriate locks being acquired
 * (tvlv.container_list_lock).
 *
 * Return: size of all currently registered tvlv containers in bytes.
 */
static u16 batadv_tvlv_container_list_size(struct batadv_priv *bat_priv)
{
	struct batadv_tvlv_container *tvlv;
	u16 tvlv_len = 0;

	lockdep_assert_held(&bat_priv->tvlv.container_list_lock);

	hlist_for_each_entry(tvlv, &bat_priv->tvlv.container_list, list) {
		tvlv_len += sizeof(struct batadv_tvlv_hdr);
		tvlv_len += ntohs(tvlv->tvlv_hdr.len);
	}

	return tvlv_len;
}

/**
 * batadv_tvlv_container_remove - remove tvlv container from the tvlv container
 *  list
 * @bat_priv: the bat priv with all the soft interface information
 * @tvlv: the to be removed tvlv container
 *
 * Has to be called with the appropriate locks being acquired
 * (tvlv.container_list_lock).
 */
static void batadv_tvlv_container_remove(struct batadv_priv *bat_priv,
					 struct batadv_tvlv_container *tvlv)
{
	lockdep_assert_held(&bat_priv->tvlv.container_list_lock);

	if (!tvlv)
		return;

	hlist_del(&tvlv->list);

	/* first call to decrement the counter, second call to free */
	batadv_tvlv_container_put(tvlv);
	batadv_tvlv_container_put(tvlv);
}

/**
 * batadv_tvlv_container_unregister - unregister tvlv container based on the
 *  provided type and version (both need to match)
 * @bat_priv: the bat priv with all the soft interface information
 * @type: tvlv container type to unregister
 * @version: tvlv container type to unregister
 */
void batadv_tvlv_container_unregister(struct batadv_priv *bat_priv,
				      u8 type, u8 version)
{
	struct batadv_tvlv_container *tvlv;

	spin_lock_bh(&bat_priv->tvlv.container_list_lock);
	tvlv = batadv_tvlv_container_get(bat_priv, type, version);
	batadv_tvlv_container_remove(bat_priv, tvlv);
	spin_unlock_bh(&bat_priv->tvlv.container_list_lock);
}

/**
 * batadv_tvlv_container_register - register tvlv type, version and content
 *  to be propagated with each (primary interface) OGM
 * @bat_priv: the bat priv with all the soft interface information
 * @type: tvlv container type
 * @version: tvlv container version
 * @tvlv_value: tvlv container content
 * @tvlv_value_len: tvlv container content length
 *
 * If a container of the same type and version was already registered the new
 * content is going to replace the old one.
 */
void batadv_tvlv_container_register(struct batadv_priv *bat_priv,
				    u8 type, u8 version,
				    void *tvlv_value, u16 tvlv_value_len)
{
	struct batadv_tvlv_container *tvlv_old, *tvlv_new;

	if (!tvlv_value)
		tvlv_value_len = 0;

	tvlv_new = kzalloc(sizeof(*tvlv_new) + tvlv_value_len, GFP_ATOMIC);
	if (!tvlv_new)
		return;

	tvlv_new->tvlv_hdr.version = version;
	tvlv_new->tvlv_hdr.type = type;
	tvlv_new->tvlv_hdr.len = htons(tvlv_value_len);

	memcpy(tvlv_new + 1, tvlv_value, ntohs(tvlv_new->tvlv_hdr.len));
	INIT_HLIST_NODE(&tvlv_new->list);
	kref_init(&tvlv_new->refcount);

	spin_lock_bh(&bat_priv->tvlv.container_list_lock);
	tvlv_old = batadv_tvlv_container_get(bat_priv, type, version);
	batadv_tvlv_container_remove(bat_priv, tvlv_old);

	kref_get(&tvlv_new->refcount);
	hlist_add_head(&tvlv_new->list, &bat_priv->tvlv.container_list);
	spin_unlock_bh(&bat_priv->tvlv.container_list_lock);

	/* don't return reference to new tvlv_container */
	batadv_tvlv_container_put(tvlv_new);
}

/**
 * batadv_tvlv_realloc_packet_buff - reallocate packet buffer to accommodate
 *  requested packet size
 * @packet_buff: packet buffer
 * @packet_buff_len: packet buffer size
 * @min_packet_len: requested packet minimum size
 * @additional_packet_len: requested additional packet size on top of minimum
 *  size
 *
 * Return: true of the packet buffer could be changed to the requested size,
 * false otherwise.
 */
static bool batadv_tvlv_realloc_packet_buff(unsigned char **packet_buff,
					    int *packet_buff_len,
					    int min_packet_len,
					    int additional_packet_len)
{
	unsigned char *new_buff;

	new_buff = kmalloc(min_packet_len + additional_packet_len, GFP_ATOMIC);

	/* keep old buffer if kmalloc should fail */
	if (!new_buff)
		return false;

	memcpy(new_buff, *packet_buff, min_packet_len);
	kfree(*packet_buff);
	*packet_buff = new_buff;
	*packet_buff_len = min_packet_len + additional_packet_len;

	return true;
}

/**
 * batadv_tvlv_container_ogm_append - append tvlv container content to given
 *  OGM packet buffer
 * @bat_priv: the bat priv with all the soft interface information
 * @packet_buff: ogm packet buffer
 * @packet_buff_len: ogm packet buffer size including ogm header and tvlv
 *  content
 * @packet_min_len: ogm header size to be preserved for the OGM itself
 *
 * The ogm packet might be enlarged or shrunk depending on the current size
 * and the size of the to-be-appended tvlv containers.
 *
 * Return: size of all appended tvlv containers in bytes.
 */
u16 batadv_tvlv_container_ogm_append(struct batadv_priv *bat_priv,
				     unsigned char **packet_buff,
				     int *packet_buff_len, int packet_min_len)
{
	struct batadv_tvlv_container *tvlv;
	struct batadv_tvlv_hdr *tvlv_hdr;
	u16 tvlv_value_len;
	void *tvlv_value;
	bool ret;

	spin_lock_bh(&bat_priv->tvlv.container_list_lock);
	tvlv_value_len = batadv_tvlv_container_list_size(bat_priv);

	ret = batadv_tvlv_realloc_packet_buff(packet_buff, packet_buff_len,
					      packet_min_len, tvlv_value_len);

	if (!ret)
		goto end;

	if (!tvlv_value_len)
		goto end;

	tvlv_value = (*packet_buff) + packet_min_len;

	hlist_for_each_entry(tvlv, &bat_priv->tvlv.container_list, list) {
		tvlv_hdr = tvlv_value;
		tvlv_hdr->type = tvlv->tvlv_hdr.type;
		tvlv_hdr->version = tvlv->tvlv_hdr.version;
		tvlv_hdr->len = tvlv->tvlv_hdr.len;
		tvlv_value = tvlv_hdr + 1;
		memcpy(tvlv_value, tvlv + 1, ntohs(tvlv->tvlv_hdr.len));
		tvlv_value = (u8 *)tvlv_value + ntohs(tvlv->tvlv_hdr.len);
	}

end:
	spin_unlock_bh(&bat_priv->tvlv.container_list_lock);
	return tvlv_value_len;
}

/**
 * batadv_tvlv_call_handler - parse the given tvlv buffer to call the
 *  appropriate handlers
 * @bat_priv: the bat priv with all the soft interface information
 * @tvlv_handler: tvlv callback function handling the tvlv content
 * @ogm_source: flag indicating whether the tvlv is an ogm or a unicast packet
 * @orig_node: orig node emitting the ogm packet
 * @src: source mac address of the unicast packet
 * @dst: destination mac address of the unicast packet
 * @tvlv_value: tvlv content
 * @tvlv_value_len: tvlv content length
 *
 * Return: success if handler was not found or the return value of the handler
 * callback.
 */
static int batadv_tvlv_call_handler(struct batadv_priv *bat_priv,
				    struct batadv_tvlv_handler *tvlv_handler,
				    bool ogm_source,
				    struct batadv_orig_node *orig_node,
				    u8 *src, u8 *dst,
				    void *tvlv_value, u16 tvlv_value_len)
{
	if (!tvlv_handler)
		return NET_RX_SUCCESS;

	if (ogm_source) {
		if (!tvlv_handler->ogm_handler)
			return NET_RX_SUCCESS;

		if (!orig_node)
			return NET_RX_SUCCESS;

		tvlv_handler->ogm_handler(bat_priv, orig_node,
					  BATADV_NO_FLAGS,
					  tvlv_value, tvlv_value_len);
		tvlv_handler->flags |= BATADV_TVLV_HANDLER_CALLED;
	} else {
		if (!src)
			return NET_RX_SUCCESS;

		if (!dst)
			return NET_RX_SUCCESS;

		if (!tvlv_handler->unicast_handler)
			return NET_RX_SUCCESS;

		return tvlv_handler->unicast_handler(bat_priv, src,
						     dst, tvlv_value,
						     tvlv_value_len);
	}

	return NET_RX_SUCCESS;
}

/**
 * batadv_tvlv_call_handler2 - call the appropriate tvlv handler
 * @bat_priv: the bat priv with all the soft interface information
 * @packet_type: packet type to look and call for
 * @tvlv_type: tvlv handler type to look and call for
 * @tvlv_version: tvlv handler version to look and call for
 * @tvlv_value: tvlv content
 * @tvlv_value_len: tvlv content length
 * @ctx: handler specific context information
 *
 * Return: NET_RX_SUCCESS if handler was found and called successfully,
 * NET_RX_DROP otherwise.
 */
static int batadv_tvlv_call_handler2(struct batadv_priv *bat_priv,
				     u8 packet_type, u8 tvlv_type,
				     u8 tvlv_version, void *tvlv_value,
				     u16 tvlv_value_len, void *ctx)
{
	struct batadv_tvlv_handler *tvlv_handler;
	int ret;

	tvlv_handler = batadv_tvlv_handler_get(bat_priv, packet_type, tvlv_type,
					       tvlv_version);
	if (!tvlv_handler)
		return NET_RX_DROP;

	ret = tvlv_handler->handler(bat_priv, tvlv_value, tvlv_value_len, ctx);
	tvlv_handler->flags |= BATADV_TVLV_HANDLER_CALLED;

	batadv_tvlv_handler_put(tvlv_handler);

	return ret;
}

/**
 * batadv_tvlv_call_unfound_handlers - call any handler not called yet
 * @bat_priv: the bat priv with all the soft interface information
 * @packet_type: the packet type to call handlers of unfound TVLVs for
 * @ctx: handler specific context information
 *
 * For any registered TVLV handler with a CIFNOTFND flag: If a matching
 * tvlv type was not found in a specific packet (type) then this calls the
 * according handler with an empty (NULL) tvlv_value and tvlv_value_len of
 * zero now.
 */
static void batadv_tvlv_call_unfound_handlers(struct batadv_priv *bat_priv,
					      int packet_type, void *ctx)
{
	struct batadv_tvlv_handler *tvlv_handler;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tvlv_handler,
				 &bat_priv->tvlv.handler_list, list) {
		if (tvlv_handler->packet_type != packet_type)
			continue;

		if ((tvlv_handler->flags & BATADV_TVLV_HANDLER_CIFNOTFND) &&
		    !(tvlv_handler->flags & BATADV_TVLV_HANDLER_CALLED))
			tvlv_handler->handler(bat_priv, NULL, 0, ctx);

		tvlv_handler->flags &= ~BATADV_TVLV_HANDLER_CALLED;
	}
	rcu_read_unlock();
}

/**
 * batadv_tvlv_containers_process2 - parse and process TVLV content of a packet
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the packet to parse and process TVLV data from
 * @packet_type: the packet type to call handlers for
 * @tvlv_offset: offset from the skb data pointer to the first tvlv header
 * @tvlv_value_len: total tvlv content length (sum of all tvlv headers+values)
 * @ctx: handler specific context information
 *
 * This function parses TVLV options of the given skb and tries to call the
 * appropriate, registered handlers.
 *
 * In the end, all not yet called handlers (because no appropriate TVLV was
 * found in the packet) which were registered with a CIFNOTFND flag are
 * called with empty tvlv_value pointers.
 *
 * Return: NET_RX_SUCCESS if all TVLVs were known and parsed, as well as
 * any TVLV handler called successfully. Returns NET_RX_DROP otherwise.
 */
int batadv_tvlv_containers_process2(struct batadv_priv *bat_priv,
				    struct sk_buff *skb, u8 packet_type,
				    unsigned int tvlv_offset,
				    u16 tvlv_value_len, void *ctx)
{
	struct batadv_tvlv_hdr *tvlv_hdr, tvlv_hdr_buff;
	u8 *tvlv_value, tvlv_value_buff[256];
	u16 tvlv_value_cont_len;
	int ret = NET_RX_SUCCESS;

	while (tvlv_value_len >= sizeof(*tvlv_hdr)) {
		tvlv_hdr = skb_header_pointer(skb, tvlv_offset,
					      sizeof(tvlv_hdr_buff),
					      &tvlv_hdr_buff);
		if (!tvlv_hdr)
			return NET_RX_DROP;

		tvlv_value_cont_len = ntohs(tvlv_hdr->len);
		tvlv_offset += sizeof(*tvlv_hdr);
		tvlv_value_len -= sizeof(*tvlv_hdr);

		if (tvlv_value_cont_len > tvlv_value_len)
			return NET_RX_DROP;

		/* check for sufficient space either in stack buffer or
		 * in skb's linear data buffer
		 */
		if (tvlv_value_cont_len > sizeof(tvlv_value_buff) &&
		    !pskb_may_pull(skb, tvlv_offset + tvlv_value_cont_len))
			return NET_RX_DROP;

		tvlv_value = skb_header_pointer(skb, tvlv_offset,
						tvlv_value_cont_len,
						tvlv_value_buff);
		if (!tvlv_value)
			return NET_RX_DROP;

		ret |= batadv_tvlv_call_handler2(bat_priv, packet_type,
						 tvlv_hdr->type,
						 tvlv_hdr->version, tvlv_value,
						 tvlv_value_cont_len, ctx);

		tvlv_offset += tvlv_value_cont_len;
		tvlv_value_len -= tvlv_value_cont_len;
	}

	batadv_tvlv_call_unfound_handlers(bat_priv, packet_type, ctx);

	return ret;
}

/**
 * batadv_tvlv_containers_process - parse the given tvlv buffer to call the
 *  appropriate handlers
 * @bat_priv: the bat priv with all the soft interface information
 * @ogm_source: flag indicating whether the tvlv is an ogm or a unicast packet
 * @orig_node: orig node emitting the ogm packet
 * @src: source mac address of the unicast packet
 * @dst: destination mac address of the unicast packet
 * @tvlv_value: tvlv content
 * @tvlv_value_len: tvlv content length
 *
 * Return: success when processing an OGM or the return value of all called
 * handler callbacks.
 */
int batadv_tvlv_containers_process(struct batadv_priv *bat_priv,
				   bool ogm_source,
				   struct batadv_orig_node *orig_node,
				   u8 *src, u8 *dst,
				   void *tvlv_value, u16 tvlv_value_len)
{
	struct batadv_tvlv_handler *tvlv_handler;
	struct batadv_tvlv_hdr *tvlv_hdr;
	u16 tvlv_value_cont_len;
	u8 cifnotfound = BATADV_TVLV_HANDLER_CIFNOTFND;
	int ret = NET_RX_SUCCESS;

	while (tvlv_value_len >= sizeof(*tvlv_hdr)) {
		tvlv_hdr = tvlv_value;
		tvlv_value_cont_len = ntohs(tvlv_hdr->len);
		tvlv_value = tvlv_hdr + 1;
		tvlv_value_len -= sizeof(*tvlv_hdr);

		if (tvlv_value_cont_len > tvlv_value_len)
			break;

		tvlv_handler = batadv_tvlv_handler_get(bat_priv, -1,
						       tvlv_hdr->type,
						       tvlv_hdr->version);

		ret |= batadv_tvlv_call_handler(bat_priv, tvlv_handler,
						ogm_source, orig_node,
						src, dst, tvlv_value,
						tvlv_value_cont_len);
		if (tvlv_handler)
			batadv_tvlv_handler_put(tvlv_handler);
		tvlv_value = (u8 *)tvlv_value + tvlv_value_cont_len;
		tvlv_value_len -= tvlv_value_cont_len;
	}

	if (!ogm_source)
		return ret;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tvlv_handler,
				 &bat_priv->tvlv.handler_list, list) {
		if (tvlv_handler->packet_type != -1)
			continue;

		if ((tvlv_handler->flags & BATADV_TVLV_HANDLER_CIFNOTFND) &&
		    !(tvlv_handler->flags & BATADV_TVLV_HANDLER_CALLED))
			tvlv_handler->ogm_handler(bat_priv, orig_node,
						  cifnotfound, NULL, 0);

		tvlv_handler->flags &= ~BATADV_TVLV_HANDLER_CALLED;
	}
	rcu_read_unlock();

	return NET_RX_SUCCESS;
}

/**
 * batadv_tvlv_ogm_receive - process an incoming ogm and call the appropriate
 *  handlers
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: ogm packet containing the tvlv containers
 * @orig_node: orig node emitting the ogm packet
 *
 * Caller needs to ensure that the skb network header points to the appropriate
 * OGM header.
 */
void batadv_tvlv_ogm_receive(struct batadv_priv *bat_priv,
			     struct sk_buff *skb,
			     struct batadv_orig_node *orig_node)
{
	struct batadv_ogm_packet *ogm_packet;
	unsigned int tvlv_offset;
	void *tvlv_value;
	u16 tvlv_value_len;

	ogm_packet = (struct batadv_ogm_packet *)skb_network_header(skb);
	if (!ogm_packet)
		return;

	tvlv_value_len = ntohs(ogm_packet->tvlv_len);
	if (!tvlv_value_len)
		return;

	tvlv_offset = skb_network_offset(skb) + sizeof(*ogm_packet);
	tvlv_value = ogm_packet + 1;

	batadv_tvlv_containers_process(bat_priv, true, orig_node, NULL, NULL,
				       tvlv_value, tvlv_value_len);
	batadv_tvlv_containers_process2(bat_priv, skb, BATADV_IV_OGM,
					tvlv_offset, tvlv_value_len, orig_node);
}

/**
 * batadv_tvlv_handler_register - register a tvlv handler
 * @bat_priv: the bat priv with all the soft interface information
 * @handler: TVLV handler callback function
 * @packet_type: packet type to register this handler for
 * @tvlv_type: tvlv handler type to be registered
 * @tvlv_version: tvlv handler version to be registered
 * @flags: flags to enable or disable TVLV API behavior
 *
 * Registers a handler for incoming packets of the provided packet type.
 * When a packet of this type with a matching TVLV (both tvlv type and version)
 * is received then the registered handler is called with the according TVLV
 * value, length and packet context.
 *
 * If 'flags' is set to BATADV_TVLV_HANDLER_CIFNOTFND:
 * Then the handler might be called with an empty tvlv_value (NULL) and
 * tvlv_value_len (zero) if a packet with a matching packet type but no
 * matching TVLV was received.
 */
void batadv_tvlv_handler_register2(struct batadv_priv *bat_priv,
				   int (*handler)(struct batadv_priv *bat_priv,
						  void *tvlv_value,
						  u16 tvlv_value_len,
						  void *ctx),
				   u8 packet_type, u8 tvlv_type,
				   u8 tvlv_version, u8 flags)
{
	struct batadv_tvlv_handler *tvlv_handler;

	tvlv_handler = batadv_tvlv_handler_get(bat_priv, packet_type, tvlv_type,
					       tvlv_version);
	if (tvlv_handler) {
		batadv_tvlv_handler_put(tvlv_handler);
		return;
	}

	tvlv_handler = kzalloc(sizeof(*tvlv_handler), GFP_ATOMIC);
	if (!tvlv_handler)
		return;

	tvlv_handler->ogm_handler = NULL;
	tvlv_handler->unicast_handler = NULL;
	tvlv_handler->handler = handler;
	tvlv_handler->packet_type = packet_type;
	tvlv_handler->tvlv_type = tvlv_type;
	tvlv_handler->tvlv_version = tvlv_version;
	tvlv_handler->flags = flags;
	kref_init(&tvlv_handler->refcount);
	INIT_HLIST_NODE(&tvlv_handler->list);

	spin_lock_bh(&bat_priv->tvlv.handler_list_lock);
	kref_get(&tvlv_handler->refcount);
	hlist_add_head_rcu(&tvlv_handler->list, &bat_priv->tvlv.handler_list);
	spin_unlock_bh(&bat_priv->tvlv.handler_list_lock);

	/* don't return reference to new tvlv_handler */
	batadv_tvlv_handler_put(tvlv_handler);
}

/**
 * batadv_tvlv_handler_register - register tvlv handler based on the provided
 *  type and version (both need to match) for ogm tvlv payload and/or unicast
 *  payload
 * @bat_priv: the bat priv with all the soft interface information
 * @optr: ogm tvlv handler callback function. This function receives the orig
 *  node, flags and the tvlv content as argument to process.
 * @uptr: unicast tvlv handler callback function. This function receives the
 *  source & destination of the unicast packet as well as the tvlv content
 *  to process.
 * @tvlv_type: tvlv handler type to be registered
 * @tvlv_version: tvlv handler version to be registered
 * @flags: flags to enable or disable TVLV API behavior
 */
void batadv_tvlv_handler_register(struct batadv_priv *bat_priv,
				  void (*optr)(struct batadv_priv *bat_priv,
					       struct batadv_orig_node *orig,
					       u8 flags,
					       void *tvlv_value,
					       u16 tvlv_value_len),
				  int (*uptr)(struct batadv_priv *bat_priv,
					      u8 *src, u8 *dst,
					      void *tvlv_value,
					      u16 tvlv_value_len),
				  u8 tvlv_type, u8 tvlv_version,
				  u8 flags)
{
	struct batadv_tvlv_handler *tvlv_handler;

	tvlv_handler = batadv_tvlv_handler_get(bat_priv, -1, tvlv_type,
					       tvlv_version);
	if (tvlv_handler) {
		batadv_tvlv_handler_put(tvlv_handler);
		return;
	}

	tvlv_handler = kzalloc(sizeof(*tvlv_handler), GFP_ATOMIC);
	if (!tvlv_handler)
		return;

	tvlv_handler->ogm_handler = optr;
	tvlv_handler->unicast_handler = uptr;
	tvlv_handler->handler = NULL;
	tvlv_handler->packet_type = -1;
	tvlv_handler->tvlv_type = tvlv_type;
	tvlv_handler->tvlv_version = tvlv_version;
	tvlv_handler->flags = flags;
	kref_init(&tvlv_handler->refcount);
	INIT_HLIST_NODE(&tvlv_handler->list);

	spin_lock_bh(&bat_priv->tvlv.handler_list_lock);
	kref_get(&tvlv_handler->refcount);
	hlist_add_head_rcu(&tvlv_handler->list, &bat_priv->tvlv.handler_list);
	spin_unlock_bh(&bat_priv->tvlv.handler_list_lock);

	/* don't return reference to new tvlv_handler */
	batadv_tvlv_handler_put(tvlv_handler);
}

/**
 * batadv_tvlv_handler_unregister2 - unregister a tvlv handler
 * @bat_priv: the bat priv with all the soft interface information
 * @packet_type: packet type to unregister for
 * @tvlv_type: tvlv handler type to be unregistered
 * @tvlv_version: tvlv handler version to be unregistered
 *
 * Unregisters a TVLV handler based on the provided packet type, tvlv type
 * and version (all need to match).
 */
void batadv_tvlv_handler_unregister2(struct batadv_priv *bat_priv,
				     u8 packet_type, u8 tvlv_type,
				     u8 tvlv_version)
{
	struct batadv_tvlv_handler *tvlv_handler;

	tvlv_handler = batadv_tvlv_handler_get(bat_priv, packet_type, tvlv_type,
					       tvlv_version);
	if (!tvlv_handler)
		return;

	batadv_tvlv_handler_put(tvlv_handler);
	spin_lock_bh(&bat_priv->tvlv.handler_list_lock);
	hlist_del_rcu(&tvlv_handler->list);
	spin_unlock_bh(&bat_priv->tvlv.handler_list_lock);
	batadv_tvlv_handler_put(tvlv_handler);
}

/**
 * batadv_tvlv_handler_unregister - unregister tvlv handler based on the
 *  provided type and version (both need to match)
 * @bat_priv: the bat priv with all the soft interface information
 * @tvlv_type: tvlv handler type to be unregistered
 * @tvlv_version: tvlv handler version to be unregistered
 */
void batadv_tvlv_handler_unregister(struct batadv_priv *bat_priv,
				    u8 tvlv_type, u8 tvlv_version)
{
	struct batadv_tvlv_handler *tvlv_handler;

	tvlv_handler = batadv_tvlv_handler_get(bat_priv, -1, tvlv_type,
					       tvlv_version);
	if (!tvlv_handler)
		return;

	batadv_tvlv_handler_put(tvlv_handler);
	spin_lock_bh(&bat_priv->tvlv.handler_list_lock);
	hlist_del_rcu(&tvlv_handler->list);
	spin_unlock_bh(&bat_priv->tvlv.handler_list_lock);
	batadv_tvlv_handler_put(tvlv_handler);
}

/**
 * batadv_tvlv_unicast_send - send a unicast packet with tvlv payload to the
 *  specified host
 * @bat_priv: the bat priv with all the soft interface information
 * @src: source mac address of the unicast packet
 * @dst: destination mac address of the unicast packet
 * @type: tvlv type
 * @version: tvlv version
 * @tvlv_value: tvlv content
 * @tvlv_value_len: tvlv content length
 */
void batadv_tvlv_unicast_send(struct batadv_priv *bat_priv, u8 *src,
			      u8 *dst, u8 type, u8 version,
			      void *tvlv_value, u16 tvlv_value_len)
{
	struct batadv_unicast_tvlv_packet *unicast_tvlv_packet;
	struct batadv_tvlv_hdr *tvlv_hdr;
	struct batadv_orig_node *orig_node;
	struct sk_buff *skb;
	unsigned char *tvlv_buff;
	unsigned int tvlv_len;
	ssize_t hdr_len = sizeof(*unicast_tvlv_packet);

	orig_node = batadv_orig_hash_find(bat_priv, dst);
	if (!orig_node)
		return;

	tvlv_len = sizeof(*tvlv_hdr) + tvlv_value_len;

	skb = netdev_alloc_skb_ip_align(NULL, ETH_HLEN + hdr_len + tvlv_len);
	if (!skb)
		goto out;

	skb->priority = TC_PRIO_CONTROL;
	skb_reserve(skb, ETH_HLEN);
	tvlv_buff = skb_put(skb, sizeof(*unicast_tvlv_packet) + tvlv_len);
	unicast_tvlv_packet = (struct batadv_unicast_tvlv_packet *)tvlv_buff;
	unicast_tvlv_packet->packet_type = BATADV_UNICAST_TVLV;
	unicast_tvlv_packet->version = BATADV_COMPAT_VERSION;
	unicast_tvlv_packet->ttl = BATADV_TTL;
	unicast_tvlv_packet->reserved = 0;
	unicast_tvlv_packet->tvlv_len = htons(tvlv_len);
	unicast_tvlv_packet->align = 0;
	ether_addr_copy(unicast_tvlv_packet->src, src);
	ether_addr_copy(unicast_tvlv_packet->dst, dst);

	tvlv_buff = (unsigned char *)(unicast_tvlv_packet + 1);
	tvlv_hdr = (struct batadv_tvlv_hdr *)tvlv_buff;
	tvlv_hdr->version = version;
	tvlv_hdr->type = type;
	tvlv_hdr->len = htons(tvlv_value_len);
	tvlv_buff += sizeof(*tvlv_hdr);
	memcpy(tvlv_buff, tvlv_value, tvlv_value_len);

	batadv_send_skb_to_orig(skb, orig_node, NULL);
out:
	batadv_orig_node_put(orig_node);
}
