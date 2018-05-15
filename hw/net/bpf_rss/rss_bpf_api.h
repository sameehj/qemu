#include <stdlib.h>
#include <linux/bpf.h>

static int bpf_load(enum bpf_prog_type type, const struct bpf_insn *insns,
		size_t insns_cnt, const char *license);

int tap_flow_bpf_calc_l3_l4_hash(__u32 key_idx, int map_fd);

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			unsigned int size);
int tap_flow_bpf_rss_map_create(unsigned int key_size,
		unsigned int value_size,
		unsigned int max_entries);
int tap_flow_bpf_update_rss_elem(int fd, void *key, void *value);
