/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 6WIND S.A.
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/resource.h>

#include <rte_byteorder.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_eth_tap.h>
#include <tap/tap_flow.h>
#include <tap/tap_autoconf.h>
#include <tap/tap_tcmsgs.h>
#include <tap/tap_rss.h>

#ifndef HAVE_TC_FLOWER
/*
 * For kernels < 4.2, this enum is not defined. Runtime checks will be made to
 * avoid sending TC messages the kernel cannot understand.
 */
enum {
	TCA_FLOWER_UNSPEC,
	TCA_FLOWER_CLASSID,
	TCA_FLOWER_INDEV,
	TCA_FLOWER_ACT,
	TCA_FLOWER_KEY_ETH_DST,         /* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_DST_MASK,    /* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_SRC,         /* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_SRC_MASK,    /* ETH_ALEN */
	TCA_FLOWER_KEY_ETH_TYPE,        /* be16 */
	TCA_FLOWER_KEY_IP_PROTO,        /* u8 */
	TCA_FLOWER_KEY_IPV4_SRC,        /* be32 */
	TCA_FLOWER_KEY_IPV4_SRC_MASK,   /* be32 */
	TCA_FLOWER_KEY_IPV4_DST,        /* be32 */
	TCA_FLOWER_KEY_IPV4_DST_MASK,   /* be32 */
	TCA_FLOWER_KEY_IPV6_SRC,        /* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_SRC_MASK,   /* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_DST,        /* struct in6_addr */
	TCA_FLOWER_KEY_IPV6_DST_MASK,   /* struct in6_addr */
	TCA_FLOWER_KEY_TCP_SRC,         /* be16 */
	TCA_FLOWER_KEY_TCP_DST,         /* be16 */
	TCA_FLOWER_KEY_UDP_SRC,         /* be16 */
	TCA_FLOWER_KEY_UDP_DST,         /* be16 */
};
#endif
#ifndef HAVE_TC_VLAN_ID
enum {
	/* TCA_FLOWER_FLAGS, */
	TCA_FLOWER_KEY_VLAN_ID = TCA_FLOWER_KEY_UDP_DST + 2, /* be16 */
	TCA_FLOWER_KEY_VLAN_PRIO,       /* u8   */
	TCA_FLOWER_KEY_VLAN_ETH_TYPE,   /* be16 */
};
#endif
/*
 * For kernels < 4.2 BPF related enums may not be defined.
 * Runtime checks will be carried out to gracefully report on TC messages that
 * are rejected by the kernel. Rejection reasons may be due to:
 * 1. enum is not defined
 * 2. enum is defined but kernel is not configured to support BPF system calls,
 *    BPF classifications or BPF actions.
 */
#ifndef HAVE_TC_BPF
enum {
	TCA_BPF_UNSPEC,
	TCA_BPF_ACT,
	TCA_BPF_POLICE,
	TCA_BPF_CLASSID,
	TCA_BPF_OPS_LEN,
	TCA_BPF_OPS,
};
#endif
#ifndef HAVE_TC_BPF_FD
enum {
	TCA_BPF_FD = TCA_BPF_OPS + 1,
	TCA_BPF_NAME,
};
#endif
#ifndef HAVE_TC_ACT_BPF
#define tc_gen \
	__u32                 index; \
	__u32                 capab; \
	int                   action; \
	int                   refcnt; \
	int                   bindcnt

struct tc_act_bpf {
	tc_gen;
};

enum {
	TCA_ACT_BPF_UNSPEC,
	TCA_ACT_BPF_TM,
	TCA_ACT_BPF_PARMS,
	TCA_ACT_BPF_OPS_LEN,
	TCA_ACT_BPF_OPS,
};

#endif
#ifndef HAVE_TC_ACT_BPF_FD
enum {
	TCA_ACT_BPF_FD = TCA_ACT_BPF_OPS + 1,
	TCA_ACT_BPF_NAME,
};
#endif

/* RSS key management */
enum bpf_rss_key_e {
	KEY_CMD_GET = 1,
	KEY_CMD_RELEASE,
	KEY_CMD_INIT,
	KEY_CMD_DEINIT,
};

enum key_status_e {
	KEY_STAT_UNSPEC,
	KEY_STAT_USED,
	KEY_STAT_AVAILABLE,
};

#define ISOLATE_HANDLE 1
#define REMOTE_PROMISCUOUS_HANDLE 2

struct rte_flow {
	LIST_ENTRY(rte_flow) next; /* Pointer to the next rte_flow structure */
	struct rte_flow *remote_flow; /* associated remote flow */
	int bpf_fd[SEC_MAX]; /* list of bfs fds per ELF section */
	uint32_t key_idx; /* RSS rule key index into BPF map */
	struct nlmsg msg;
};

struct convert_data {
	uint16_t eth_type;
	uint16_t ip_proto;
	uint8_t vlan;
	struct rte_flow *flow;
};

struct remote_rule {
	struct rte_flow_attr attr;
	struct rte_flow_item items[2];
	struct rte_flow_action actions[2];
	int mirred;
};

struct action_data {
	char id[16];

	union {
		struct tc_gact gact;
		struct tc_mirred mirred;
		struct skbedit {
			struct tc_skbedit skbedit;
			uint16_t queue;
		} skbedit;
		struct bpf {
			struct tc_act_bpf bpf;
			int bpf_fd;
			const char *annotation;
		} bpf;
	};
};



#define MAX_RSS_KEYS 256
#define KEY_IDX_OFFSET (3 * MAX_RSS_KEYS)
#define SEC_NAME_CLS_Q "cls_q"

const char *sec_name[SEC_MAX] = {
	[SEC_L3_L4] = "l3_l4",
};


int pmd_init(struct pmd_internals *p)
{
	p = (* struct pmd_internals) malloc(sizeof(struct pmd_internals));
	p->if_index = if_nametoindex("cc1_72");
	p->nlsk_fd = tap_nl_init(0); 
	return 0;
}

/**
 * Enable RSS on tap: create TC rules for queuing.
 *
 * @param[in, out] pmd
 *   Pointer to private structure.
 *
 * @param[in] attr
 *   Pointer to rte_flow to get flow group
 *
 * @param[out] error
 *   Pointer to error reporting if not NULL.
 *
 * @return 0 on success, negative value on failure.
 */
int rss_enable(struct rss_internals *rss_internals)
{
	struct rte_flow *rss_flow = NULL;
	struct nlmsg *msg = NULL;
	/* 4096 is the maximum number of instructions for a BPF program */
	char annotation[64];
	int i;
	int err = 0;

	/* unlimit locked memory */
	struct rlimit memlock_limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	setrlimit(RLIMIT_MEMLOCK, &memlock_limit);

	 /* Get a new map key for a new RSS rule */
	err = bpf_rss_key(KEY_CMD_INIT, NULL);
	if (err < 0) {
		rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Failed to initialize BPF RSS keys");

		return -1;
	}

	/*
	 *  Create BPF RSS MAP
	 */
	pmd->map_fd = tap_flow_bpf_rss_map_create(sizeof(__u32), /* key size */
				sizeof(struct rss_key),
				MAX_RSS_KEYS);
	if (pmd->map_fd < 0) {
		TAP_LOG(ERR,
			"Failed to create BPF map (%d): %s",
				errno, strerror(errno));
		rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Kernel too old or not configured "
			"to support BPF maps");

		return -ENOTSUP;
	}

	/*
	 * Add a rule per queue to match reclassified packets and direct them to
	 * the correct queue.
	 */
	for (i = 0; i < pmd->dev->data->nb_rx_queues; i++) {
		pmd->bpf_fd[i] = tap_flow_bpf_cls_q(i);
		if (pmd->bpf_fd[i] < 0) {
			TAP_LOG(ERR,
				"Failed to load BPF section %s for queue %d",
				SEC_NAME_CLS_Q, i);
			rte_flow_error_set(
				error, ENOTSUP, RTE_FLOW_ERROR_TYPE_HANDLE,
				NULL,
				"Kernel too old or not configured "
				"to support BPF programs loading");

			return -ENOTSUP;
		}

		rss_flow = rte_malloc(__func__, sizeof(struct rte_flow), 0);
		if (!rss_flow) {
			TAP_LOG(ERR,
				"Cannot allocate memory for rte_flow");
			return -1;
		}
		msg = &rss_flow->msg;
		tc_init_msg(msg, pmd->if_index, RTM_NEWTFILTER, NLM_F_REQUEST |
			    NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
		msg->t.tcm_info = TC_H_MAKE(0, htons(ETH_P_ALL));
		tap_flow_set_handle(rss_flow);
		uint16_t group = attr->group << GROUP_SHIFT;
		uint16_t prio = group | (i + PRIORITY_OFFSET);
		msg->t.tcm_info = TC_H_MAKE(prio << 16, msg->t.tcm_info);
		msg->t.tcm_parent = TC_H_MAKE(MULTIQ_MAJOR_HANDLE, 0);

		tap_nlattr_add(&msg->nh, TCA_KIND, sizeof("bpf"), "bpf");
		if (tap_nlattr_nested_start(msg, TCA_OPTIONS) < 0)
			return -1;
		tap_nlattr_add32(&msg->nh, TCA_BPF_FD, pmd->bpf_fd[i]);
		snprintf(annotation, sizeof(annotation), "[%s%d]",
			SEC_NAME_CLS_Q, i);
		tap_nlattr_add(&msg->nh, TCA_BPF_NAME, strlen(annotation) + 1,
			   annotation);
		/* Actions */
		{
			struct action_data adata = {
				.id = "skbedit",
				.skbedit = {
					.skbedit = {
						.action = TC_ACT_PIPE,
					},
					.queue = i,
				},
			};
			if (add_actions(rss_flow, 1, &adata, TCA_BPF_ACT) < 0)
				return -1;
		}
		tap_nlattr_nested_finish(msg); /* nested TCA_OPTIONS */

		/* Netlink message is now ready to be sent */
		if (tap_nl_send(pmd->nlsk_fd, &msg->nh) < 0)
			return -1;
		err = tap_nl_recv_ack(pmd->nlsk_fd);
		if (err < 0) {
			TAP_LOG(ERR,
				"Kernel refused TC filter rule creation (%d): %s",
				errno, strerror(errno));
			return err;
		}
		LIST_INSERT_HEAD(&pmd->rss_flows, rss_flow, next);
	}

	pmd->rss_enabled = 1;
	return err;
}

/**
 * Manage bpf RSS keys repository with operations: init, get, release
 *
 * @param[in] cmd
 *   Command on RSS keys: init, get, release
 *
 * @param[in, out] key_idx
 *   Pointer to RSS Key index (out for get command, in for release command)
 *
 * @return -1 if couldn't get, release or init the RSS keys, 0 otherwise.
 */
int bpf_rss_key(enum bpf_rss_key_e cmd, __u32 *key_idx)
{
	__u32 i;
	int err = 0;
	static __u32 num_used_keys;
	static __u32 rss_keys[MAX_RSS_KEYS] = {KEY_STAT_UNSPEC};
	static __u32 rss_keys_initialized;
	__u32 key;

	switch (cmd) {
	case KEY_CMD_GET:
		if (!rss_keys_initialized) {
			err = -1;
			break;
		}

		if (num_used_keys == RTE_DIM(rss_keys)) {
			err = -1;
			break;
		}

		*key_idx = num_used_keys % RTE_DIM(rss_keys);
		while (rss_keys[*key_idx] == KEY_STAT_USED)
			*key_idx = (*key_idx + 1) % RTE_DIM(rss_keys);

		rss_keys[*key_idx] = KEY_STAT_USED;

		/*
		 * Add an offset to key_idx in order to handle a case of
		 * RSS and non RSS flows mixture.
		 * If a non RSS flow is destroyed it has an eBPF map
		 * index 0 (initialized on flow creation) and might
		 * unintentionally remove RSS entry 0 from eBPF map.
		 * To avoid this issue, add an offset to the real index
		 * during a KEY_CMD_GET operation and subtract this offset
		 * during a KEY_CMD_RELEASE operation in order to restore
		 * the real index.
		 */
		*key_idx += KEY_IDX_OFFSET;
		num_used_keys++;
	break;

	case KEY_CMD_RELEASE:
		if (!rss_keys_initialized)
			break;

		/*
		 * Subtract offest to restore real key index
		 * If a non RSS flow is falsely trying to release map
		 * entry 0 - the offset subtraction will calculate the real
		 * map index as an out-of-range value and the release operation
		 * will be silently ignored.
		 */
		key = *key_idx - KEY_IDX_OFFSET;
		if (key >= RTE_DIM(rss_keys))
			break;

		if (rss_keys[key] == KEY_STAT_USED) {
			rss_keys[key] = KEY_STAT_AVAILABLE;
			num_used_keys--;
		}
	break;

	case KEY_CMD_INIT:
		for (i = 0; i < RTE_DIM(rss_keys); i++)
			rss_keys[i] = KEY_STAT_AVAILABLE;

		rss_keys_initialized = 1;
		num_used_keys = 0;
	break;

	case KEY_CMD_DEINIT:
		for (i = 0; i < RTE_DIM(rss_keys); i++)
			rss_keys[i] = KEY_STAT_UNSPEC;

		rss_keys_initialized = 0;
		num_used_keys = 0;
	break;

	default:
		break;
	}

	return err;
}

/**
 * Add RSS hash calculations and queue selection
 *
 * @param[in, out] pmd
 *   Pointer to internal structure. Used to set/get RSS map fd
 *
 * @param[in] rss
 *   Pointer to RSS flow actions
 *
 * @param[out] error
 *   Pointer to error reporting if not NULL.
 *
 * @return 0 on success, negative value on failure
 */
int rss_add_actions(struct rte_flow *flow, struct pmd_internals *pmd,
			   const struct rte_flow_action_rss *rss,
			   struct rte_flow_error *error)
{
	/* 4096 is the maximum number of instructions for a BPF program */
	unsigned int i;
	int err;
	struct rss_key rss_entry = { .hash_fields = 0,
				     .key_size = 0 };

	/* Check supported RSS features */
	if (rss->func != RTE_ETH_HASH_FUNCTION_DEFAULT)
		return rte_flow_error_set
			(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			 "non-default RSS hash functions are not supported");
	if (rss->level)
		return rte_flow_error_set
			(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			 "a nonzero RSS encapsulation level is not supported");

	/* Get a new map key for a new RSS rule */
	err = bpf_rss_key(KEY_CMD_GET, &flow->key_idx);
	if (err < 0) {
		rte_flow_error_set(
			error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Failed to get BPF RSS key");

		return -1;
	}

	/* Update RSS map entry with queues */
	rss_entry.nb_queues = rss->queue_num;
	for (i = 0; i < rss->queue_num; i++)
		rss_entry.queues[i] = rss->queue[i];
	rss_entry.hash_fields =
		(1 << HASH_FIELD_IPV4_L3_L4) | (1 << HASH_FIELD_IPV6_L3_L4);

	/* Add this RSS entry to map */
	err = tap_flow_bpf_update_rss_elem(pmd->map_fd,
				&flow->key_idx, &rss_entry);

	if (err) {
		TAP_LOG(ERR,
			"Failed to update BPF map entry #%u (%d): %s",
			flow->key_idx, errno, strerror(errno));
		rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Kernel too old or not configured "
			"to support BPF maps updates");

		return -ENOTSUP;
	}


	/*
	 * Load bpf rules to calculate hash for this key_idx
	 */

	flow->bpf_fd[SEC_L3_L4] =
		tap_flow_bpf_calc_l3_l4_hash(flow->key_idx, pmd->map_fd);
	if (flow->bpf_fd[SEC_L3_L4] < 0) {
		TAP_LOG(ERR,
			"Failed to load BPF section %s (%d): %s",
				sec_name[SEC_L3_L4], errno, strerror(errno));
		rte_flow_error_set(
			error, ENOTSUP, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Kernel too old or not configured "
			"to support BPF program loading");

		return -ENOTSUP;
	}

	/* Actions */
	{
		struct action_data adata[] = {
			{
				.id = "bpf",
				.bpf = {
					.bpf_fd = flow->bpf_fd[SEC_L3_L4],
					.annotation = sec_name[SEC_L3_L4],
					.bpf = {
						.action = TC_ACT_PIPE,
					},
				},
			},
		};

		if (add_actions(flow, RTE_DIM(adata), adata,
			TCA_FLOWER_ACT) < 0)
			return -1;
	}

	return 0;
}
