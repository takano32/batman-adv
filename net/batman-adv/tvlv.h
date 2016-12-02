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

#ifndef _NET_BATMAN_ADV_TVLV_H_
#define _NET_BATMAN_ADV_TVLV_H_

#include "main.h"

#include <linux/types.h>

struct sk_buff;

void batadv_tvlv_container_register(struct batadv_priv *bat_priv,
				    u8 type, u8 version,
				    void *tvlv_value, u16 tvlv_value_len);
u16 batadv_tvlv_container_ogm_append(struct batadv_priv *bat_priv,
				     unsigned char **packet_buff,
				     int *packet_buff_len, int packet_min_len);
void batadv_tvlv_ogm_receive(struct batadv_priv *bat_priv,
			     struct sk_buff *skb,
			     struct batadv_orig_node *orig_node);
void batadv_tvlv_container_unregister(struct batadv_priv *bat_priv,
				      u8 type, u8 version);

void batadv_tvlv_handler_register2(struct batadv_priv *bat_priv,
				   int (*handler)(struct batadv_priv *bat_priv,
						  void *tvlv_value,
						  u16 tvlv_value_len,
						  void *ctx),
				   u8 packet_type, u8 tvlv_type,
				   u8 tvlv_version, u8 flags);
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
				  u8 tvlv_type, u8 tvlv_version, u8 flags);
void batadv_tvlv_handler_unregister2(struct batadv_priv *bat_priv,
				     u8 packet_type, u8 tvlv_type,
				     u8 tvlv_version);
void batadv_tvlv_handler_unregister(struct batadv_priv *bat_priv,
				    u8 tvlv_type, u8 tvlv_version);
int batadv_tvlv_containers_process(struct batadv_priv *bat_priv,
				   bool ogm_source,
				   struct batadv_orig_node *orig_node,
				   u8 *src, u8 *dst,
				   void *tvlv_buff, u16 tvlv_buff_len);
int batadv_tvlv_containers_process2(struct batadv_priv *bat_priv,
				    struct sk_buff *skb, u8 packet_type,
				    unsigned int tvlv_offset,
				    u16 tvlv_value_len, void *ctx);
void batadv_tvlv_unicast_send(struct batadv_priv *bat_priv, u8 *src,
			      u8 *dst, u8 type, u8 version,
			      void *tvlv_value, u16 tvlv_value_len);

#endif /* _NET_BATMAN_ADV_TVLV_H_ */
