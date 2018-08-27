/*
 * RSS ebpf header for virtio-net
 *
 * Copyright (c) 2018 RedHat.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * This code is heavily based on the following bpf code from dpdk
 * https://git.dpdk.org/dpdk/tree/drivers/net/tap/
 *
 */

#ifndef RSS_TAP_BPF_H
#define RSS_TAP_BPF_H

/* hashed fields for RSS */
enum hash_field {
  HASH_FIELD_IPV4_L3,  /* IPv4 src/dst addr */
  HASH_FIELD_IPV4_L3_L4,  /* IPv4 src/dst addr + L4 src/dst ports */
  HASH_FIELD_IPV6_L3,  /* IPv6 src/dst addr */
  HASH_FIELD_IPV6_L3_L4,  /* IPv6 src/dst addr + L4 src/dst ports */
  HASH_FIELD_L2_SRC,  /* Ethernet src addr */
  HASH_FIELD_L2_DST,  /* Ethernet dst addr */
  HASH_FIELD_L3_SRC,  /* L3 src addr */
  HASH_FIELD_L3_DST,  /* L3 dst addr */
  HASH_FIELD_L4_SRC,  /* TCP/UDP src ports */
  HASH_FIELD_L4_DST,  /* TCP/UDP dst ports */
};

struct rss_key {
  __u32 hash_fields;
  __u32 nb_queues;
    __u32 *indirection_table;
    __u32 indirection_table_size;
  __u8 *key;
  __u32 key_size;
} __attribute__((packed));

#endif
