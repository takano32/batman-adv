/* Copyright (C) 2013-2017  B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing, Marek Lindner
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

#ifndef _NET_BATMAN_ADV_BAT_V_ELP_H_
#define _NET_BATMAN_ADV_BAT_V_ELP_H_

#include "main.h"

#include <linux/types.h>

struct sk_buff;
struct work_struct;

int batadv_v_elp_mesh_init(struct batadv_priv *bat_priv);
void batadv_v_elp_mesh_free(struct batadv_priv *bat_priv);
int batadv_v_elp_init(void);
void batadv_v_elp_free(void);
int batadv_v_elp_iface_enable(struct batadv_hard_iface *hard_iface);
void batadv_v_elp_iface_disable(struct batadv_hard_iface *hard_iface);
void batadv_v_elp_iface_activate(struct batadv_hard_iface *primary_iface,
				 struct batadv_hard_iface *hard_iface);
void batadv_v_elp_primary_iface_set(struct batadv_hard_iface *primary_iface);
int batadv_v_elp_packet_recv(struct sk_buff *skb,
			     struct batadv_hard_iface *if_incoming);
bool batadv_v_elp_nhh_cmp(struct batadv_hardif_neigh_node *hardif_neigh);
bool batadv_v_elp_rx_ingress_bad(struct batadv_hardif_neigh_node *hardif_neigh);
bool batadv_v_elp_rx_egress_bad(struct batadv_hardif_neigh_node *hardif_neigh);
bool batadv_v_elp_tx_ingress_bad(struct batadv_hardif_neigh_node *hardif_neigh);
bool batadv_v_elp_tx_egress_bad(struct batadv_hardif_neigh_node *hardif_neigh);
bool batadv_v_elp_no_broadcast(struct batadv_hard_iface *if_outgoing,
			       struct batadv_hardif_neigh_node *hardif_neigh,
			       bool inverse_metric);
void batadv_v_elp_throughput_metric_update(struct work_struct *work);

#endif /* _NET_BATMAN_ADV_BAT_V_ELP_H_ */
