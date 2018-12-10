/*
 * RSS ebpf code for virtio-net
 *
 * Copyright (c) 2018 RedHat.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * This code is heavily based on the following bpf code from dpdk
 * https://git.dpdk.org/dpdk/tree/drivers/net/tap/tap_bpf_program.c
 *
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

#include "bpf_api.h"
#include "rss_tap_bpf.h"

/** Create IPv4 address */
#define IPv4(a, b, c, d) ((__u32)(((a) & 0xff) << 24) | \
    (((b) & 0xff) << 16) | \
    (((c) & 0xff) << 8)  | \
    ((d) & 0xff))

#define PORT(a, b) ((__u16)(((a) & 0xff) << 8) | \
    ((b) & 0xff))

#define KEY_IDX      0

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

//struct bpf_elf_map __attribute__((section("maps"), used))
struct bpf_elf_map __attribute__((section("maps"), used)) map_rss = {
  .type           =       BPF_MAP_TYPE_ARRAY,
  .size_key       =       sizeof(__u32),
  .size_value     =       sizeof(struct rss_key),
  .max_elem       =       1,
};

//struct bpf_elf_map __attribute__((section("maps"), used))
struct bpf_elf_map __attribute__((section("maps"), used)) map_rss_key = {
  .type           =       BPF_MAP_TYPE_ARRAY,
  .size_key       =       sizeof(__u32),
  .size_value     =       sizeof(__u8),
  .max_elem       =       RSS_MAX_KEY_SIZE,
};

//struct bpf_elf_map __attribute__((section("maps"), used))
struct bpf_elf_map __attribute__((section("maps"), used)) map_rss_indirection = {
  .type           =       BPF_MAP_TYPE_ARRAY,
  .size_key       =       sizeof(__u32),
  .size_value     =       sizeof(__u32),
  .max_elem       =       RSS_MAX_INDIRECTION_SIZE,
};

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

static __u32  __attribute__((always_inline))
rte_softrss_be(const __u32 *input_tuple, __u8 input_len)
{
    __u32 i, j, k, hash = 0, key_curr, key_next;
    __u32 * elem;
#pragma unroll
    for (j = 0; j < input_len; j++) {
      elem = map_lookup_elem(&map_rss_key, &j);
      key_curr = elem ? *elem : 0;
      k = j + 1;
      elem = map_lookup_elem(&map_rss_key, &k);
      key_next = elem ? *elem : 0;
#pragma clang loop unroll_count(32)
        for (i = 0; i < 32; i++) {
            if (input_tuple[j] & (1 << (31 - i))) {
                hash ^= key_curr << i |
                (uint64_t) (( key_next >> (32 - i)));
            }
        }
    }
    return hash;
}

/*
static void __attribute__((always_inline))
fill_key_to_array(__u8 *array)
{
    __u32 i = 0;
    __u8 *elem;

#pragma clang loop unroll_count(RSS_MAX_KEY_SIZE)
    for(i = 0; i < RSS_MAX_KEY_SIZE; i++)
    {
        elem = map_lookup_elem(&map_rss_key, &i);
        array[i] = elem == NULL ? '0' : *elem;
    }
}
*/

static int __attribute__((always_inline))
rss_l3_l4(struct __sk_buff *skb)
{
    __u64 proto = load_half(skb, 12);
    __u64 nhoff = ETH_HLEN;
    __u32 key_idx = 0xdeadbeef;
    __u32 hash = 0;
    int j = 0;
    __u32 * queue;
//    __u8 key[RSS_MAX_KEY_SIZE];
    struct rss_key *rss_key;

    rss_key = (struct rss_key *) map_lookup_elem(&map_rss, &key_idx);
    if (!rss_key) {
        return -1;
    }

  //  fill_key_to_array(key);

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
		if (rss_key->hash_fields & (1 << HASH_FIELD_IPV4_L3))
			input_len--;
		hash = rte_softrss_be((__u32 *)&v4_tuple, 3);
	} else if (proto == htons(ETH_P_IPV6)) {
		struct ipv6_l3_l4_tuple v6_tuple;
#pragma clang loop unroll_count(4)
		for (j = 0; j < 4; j++)
			*((uint32_t *)&v6_tuple.src_addr + j) =
				load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + j);
#pragma clang loop unroll_count(4)
		for (j = 0; j < 4; j++)
        {
			*((uint32_t *)&v6_tuple.dst_addr + j) =
				load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + j);
		    v6_tuple.sport = PORT(load_byte(skb, nhoff + sizeof(struct ipv6hdr)),
				      load_byte(skb, nhoff + sizeof(struct ipv6hdr) + 1));
		    v6_tuple.dport = PORT(load_byte(skb, nhoff + sizeof(struct ipv6hdr) + 2),
				      load_byte(skb, nhoff + sizeof(struct ipv6hdr) + 3));
        }
		__u8 input_len = sizeof(v6_tuple) / sizeof(__u32);
		if (rss_key->hash_fields & (1 << HASH_FIELD_IPV6_L3))
			input_len--;
		hash = rte_softrss_be((__u32 *)&v6_tuple, 9);
	} else {
		return -1;
	}
    __u32 indirection_index = hash % rss_key->nb_queues;
    queue = (__u32 *) map_lookup_elem(&map_rss_indirection, &indirection_index);

    return queue == NULL ? -1 : (int) *queue;
}

#define RSS(L)                                          \
        __section(#L) int                               \
                L ## _hash(struct __sk_buff *skb)       \
        {                                               \
            return rss_ ## L(skb);                     \
        }

RSS(l3_l4)

BPF_LICENSE("Dual BSD/GPL");
