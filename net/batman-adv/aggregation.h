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

#ifndef _NET_BATMAN_ADV_AGGREGATION_H_
#define _NET_BATMAN_ADV_AGGREGATION_H_

#include "main.h"

struct sk_buff;

#ifdef CONFIG_BATMAN_ADV_AGGR

void batadv_aggr_add_counter_rx(struct batadv_priv *bat_priv,
				struct sk_buff *skb);

void batadv_aggr_hardif_start(struct batadv_hard_iface *hard_iface);
void batadv_aggr_hardif_stop(struct batadv_hard_iface *hard_iface);

int batadv_aggr_queue(struct sk_buff *skb,
		      struct batadv_hard_iface *hard_iface);

void batadv_aggr_purge_orig(struct batadv_orig_node *orig);
void batadv_aggr_hardif_init(struct batadv_hard_iface *hard_iface);
int batadv_aggr_mesh_init(struct batadv_priv *bat_priv);
void batadv_aggr_mesh_free(struct batadv_priv *bat_priv);

#else

static inline void batadv_aggr_add_counter_rx(struct batadv_priv *bat_priv,
					      struct sk_buff *skb)
{
}

static inline void
batadv_aggr_hardif_start(struct batadv_hard_iface *hard_iface)
{
}

static inline void batadv_aggr_hardif_stop(struct batadv_hard_iface *hard_iface)
{
}

static inline int batadv_aggr_queue(struct sk_buff *skb,
				    struct batadv_hard_iface *hard_iface)
{
	return NET_XMIT_DROP;
}

static inline void batadv_aggr_purge_orig(struct batadv_orig_node *orig)
{
}

static inline void batadv_aggr_hardif_init(struct batadv_hard_iface *hard_iface)
{
}

static inline int batadv_aggr_mesh_init(struct batadv_priv *bat_priv)
{
	return 0;
}

static inline void batadv_aggr_mesh_free(struct batadv_priv *bat_priv)
{
}

#endif /* CONFIG_BATMAN_ADV_AGGR */

#endif /* _NET_BATMAN_ADV_AGGREGATION_H_ */
