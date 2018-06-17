/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#include "tap_rss.h"
#include "bpf_api.h"
#include "rss_bpf_api.h"

/** Create IPv4 address */
#define IPv4(a, b, c, d) ((__u32)(((a) & 0xff) << 24) | \
		(((b) & 0xff) << 16) | \
		(((c) & 0xff) << 8)  | \
		((d) & 0xff))

#define PORT(a, b) ((__u16)(((a) & 0xff) << 8) | \
		((b) & 0xff))

/*
 * The queue number is offset by a unique QUEUE_OFFSET, to distinguish
 * packets that have gone through this rule (skb->cb[1] != 0) from others.
 */
#define QUEUE_OFFSET		0x7cafe800
#define PIN_GLOBAL_NS		2

#define KEY_IDX			0
#define BPF_MAP_ID_KEY	1

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct virtio_net_hdr_rss {
    __u32 rss_hash_function;
    __u32 hash_function_flags;
    uint8_t rss_hash_key[40];
    __u32 rss_indirection_table_length;
    uint8_t rss_indirection_table[128];
};

struct bpf_elf_map __attribute__((section("maps"), used))
map_rss = {
	.type           =       BPF_MAP_TYPE_ARRAY,
	.id             =       BPF_MAP_ID_KEY,
	.size_key       =       sizeof(__u32),
	.size_value     =       sizeof(struct virtio_net_hdr_rss),
	.max_elem       =       1,
	.pinning        =       PIN_GLOBAL_NS,

};

/*
__section("cls_q") int
match_q(struct __sk_buff *skb)
{
	__u32 queue = skb->cb[1];
	volatile __u32 q = 0xdeadbeef;
	__u32 match_queue = QUEUE_OFFSET + q;

	if (queue != match_queue)
		return TC_ACT_OK;
	skb->cb[1] = 0;
	return TC_ACT_UNSPEC;
}
*/

struct ipv4_l3_l4_tuple {
	__u32    src_addr;
	__u32    dst_addr;
	__u16    dport;
	__u16    sport;
} __attribute__((packed));

struct ipv6_l3_l4_tuple {
	__u8        src_addr[16];
	__u8        dst_addr[16];
	__u16       dport;
	__u16       sport;
} __attribute__((packed));

static const __u8 def_rss_key[] = {
	0xd1, 0x81, 0xc6, 0x2c,
	0xf7, 0xf4, 0xdb, 0x5b,
	0x19, 0x83, 0xa2, 0xfc,
	0x94, 0x3e, 0x1a, 0xdb,
	0xd9, 0x38, 0x9e, 0x6b,
	0xd1, 0x03, 0x9c, 0x2c,
	0xa7, 0x44, 0x99, 0xad,
	0x59, 0x3d, 0x56, 0xd9,
	0xf3, 0x25, 0x3c, 0x06,
	0x2a, 0xdc, 0x1f, 0xfc,
};

static __u32  __attribute__((always_inline))
rte_softrss_be(const __u32 *input_tuple, const uint8_t *rss_key,
		__u8 input_len)
{
	__u32 i, j, hash = 0;
#pragma unroll
	for (j = 0; j < input_len; j++) {
#pragma unroll
		for (i = 0; i < 32; i++) {
			if (input_tuple[j] & (1 << (31 - i))) {
				hash ^= ((const __u32 *)rss_key)[j] << i |
				(__u32)((uint64_t)
				(((const __u32 *)rss_key)[j + 1])
					>> (32 - i));
			}
		}
	}
	return hash;
}

static int __attribute__((always_inline))
rss_l3_l4(struct __sk_buff *skb)
{
//	void *data_end = (void *)(long)skb->data_end;
//	void *data = (void *)(long)skb->data;
	__u64 proto = load_half(skb, 12);
	__u64 nhoff = ETH_HLEN;
	__u32 key_idx = 0xdeadbeef;
	__u32 hash = 0;
	struct virtio_net_hdr_rss * rss_conf;
	struct rss_key *rsskey;
	int j = 0;
	__u8 *key = 0;
	__u32 len = 0;
	__u32 queue = 0;
	__u32 q = 0;

	rss_conf = (struct virtio_net_hdr_rss *) map_lookup_elem(&map_rss, &key_idx);
	if (!rss_conf) {
		printt("hash(): rss key is not configured\n");
		return -2;
	}
	key = (__u8 *)rss_conf->rss_hash_key;

	if (proto == ETH_P_8021AD) {
		proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct vlan_hdr);
	}

	if (proto == ETH_P_8021Q) {
		proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct vlan_hdr);
	}

	if (likely(proto == ETH_P_IP)) {
		//__u8 *src_dst_addr =  load_byte(skb, nhoff + offsetof(struct iphdr, saddr));
		//__u8 *src_dst_port =  load_byte(skb, nhoff + sizeof(struct iphdr));
		struct ipv4_l3_l4_tuple v4_tuple = {
			.src_addr = IPv4(load_byte(skb, nhoff + offsetof(struct iphdr, saddr)),
					 load_byte(skb, nhoff + offsetof(struct iphdr, saddr) + 1),
					 load_byte(skb, nhoff + offsetof(struct iphdr, saddr) + 2),
					 load_byte(skb, nhoff + offsetof(struct iphdr, saddr) + 3)),
			.dst_addr = IPv4(load_byte(skb, nhoff + offsetof(struct iphdr, daddr)),
					 load_byte(skb, nhoff + offsetof(struct iphdr, daddr) + 1),
					 load_byte(skb, nhoff + offsetof(struct iphdr, daddr) + 2),
					 load_byte(skb, nhoff + offsetof(struct iphdr, daddr) + 3)),
			.sport = PORT(load_byte(skb, nhoff + sizeof(struct iphdr)),
				      load_byte(skb, nhoff + sizeof(struct iphdr) + 1)),
			.dport = PORT(load_byte(skb, nhoff + sizeof(struct iphdr) + 2),
				      load_byte(skb, nhoff + sizeof(struct iphdr) + 3))
		};
		__u8 input_len = sizeof(v4_tuple) / sizeof(__u32);
		if (rss_conf->hash_function_flags & (1 << HASH_FIELD_IPV4_L3))
			input_len--;
		hash = rte_softrss_be((__u32 *)&v4_tuple, key, 3);
	} else if (proto == htons(ETH_P_IPV6)) {
	//	__u8 *src_dst_addr = data + off +
	//				offsetof(struct ipv6hdr, saddr);
	//	__u8 *src_dst_port = data + off +
		//			sizeof(struct ipv6hdr);
		struct ipv6_l3_l4_tuple v6_tuple;
		for (j = 0; j < 4; j++)
			*((uint32_t *)&v6_tuple.src_addr + j) =
				load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + j);
		for (j = 0; j < 4; j++)
			*((uint32_t *)&v6_tuple.dst_addr + j) =
				load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + j);
		v6_tuple.sport = PORT(load_byte(skb, nhoff + sizeof(struct ipv6hdr)),
				      load_byte(skb, nhoff + sizeof(struct ipv6hdr) + 1));
		v6_tuple.dport = PORT(load_byte(skb, nhoff + sizeof(struct ipv6hdr) + 2),
				      load_byte(skb, nhoff + sizeof(struct ipv6hdr) + 3));

		__u8 input_len = sizeof(v6_tuple) / sizeof(__u32);
		if (rss_conf->hash_function_flags & (1 << HASH_FIELD_IPV6_L3))
			input_len--;
		hash = rte_softrss_be((__u32 *)&v6_tuple, key, 9);
	} else {
		return -1;
	}

	queue = rsskey->queues[(hash % rsskey->nb_queues) &
				       (TAP_MAX_QUEUES - 1)];
	printt("queue: 0x%x hash: 0x%x\n" ,queue, hash);
	return queue;
}

#define RSS(L)                                          \
        __section(#L) int                               \
                L ## _hash(struct __sk_buff *skb)       \
        {                                               \
                return rss_ ## L (skb);                 \
        }

RSS(l3_l4)

BPF_LICENSE("Dual BSD/GPL");
