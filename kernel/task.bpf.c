//+build ignore
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct data {
    int pid;
    int uid;
    bool blocked;
} __attribute__((packed));

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
}  __attribute__((packed));

struct lpm_value {
    __u16 id;
    __u64 counter;
}  __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct lpm_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipv4_lpm_map SEC(".maps");

struct raw_data {
    char command[16];
    __u32 ipv4;
    __u32 pid;
    __u32 uid;
    __u8 blocked;
    struct lpm_value lpm_value; //0 if not blocked
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void *ipv4_lookup(__u32 ipaddr) {
    struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .data = ipaddr
    };

    return bpf_map_lookup_elem(&ipv4_lpm_map, &key);
}

#define FOUND 1
#define NOT_FOUND -1
#define FOUND_UPDATE_ERROR -2

static __always_inline long ipv4_update(__u32 ipaddr, struct lpm_value val) {
    struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .data = ipaddr
    };

    return bpf_map_update_elem(&ipv4_lpm_map, &key, &val, BPF_EXIST);
}

static __always_inline int ipv4_check_and_update(__u32 user_ipv4, struct lpm_value *ret_pval) {

    void *pv = ipv4_lookup(user_ipv4);
    if (!pv) {
        bpf_printk("[not found]: user_ip4:%u", user_ipv4);
        return NOT_FOUND;
    }

    struct lpm_value *pval = pv;

    ret_pval->id = pval->id;
    ret_pval->counter = ++pval->counter;

    long ret = ipv4_update(user_ipv4, *pval);
    if (ret != 0) {
        bpf_printk("[update failed]: user_ip4:%u", user_ipv4);
        return FOUND_UPDATE_ERROR;
    }

    bpf_printk("[found]: user_ipv4:%u", user_ipv4);
    return FOUND; //process further inside bpf
}

SEC("cgroup/connect4")
int cgroup_sock_prog(struct bpf_sock_addr *ctx)
{
    struct raw_data *rdp;
    rdp = bpf_ringbuf_reserve(&events, sizeof(struct raw_data), 0);
    if (!rdp) {
        return 0;
    }

    rdp->blocked = false;
    rdp->pid = bpf_get_current_pid_tgid() >> 32;
    rdp->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(rdp->command, sizeof(rdp->command));


    __u32 user_ip4 = ctx->user_ip4;
    bpf_printk("[egress]: user_ip4:%u", user_ip4);
    rdp->ipv4 = user_ip4;

    struct lpm_value ret_val = {};
    int found = ipv4_check_and_update(user_ip4, &ret_val);
    if (found == FOUND) {
        rdp->blocked = 1;
        rdp->lpm_value = ret_val;
    }

    bpf_ringbuf_submit(rdp, 0);

    if  (found == FOUND) {
        bpf_printk("[egress]: user_ip4:%u blocked", user_ip4);
        return 0; //block
    }

    return 1; //accept
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";