// SPDX-License-Identifier: GPL-2.0-or-later
#include "stdlib.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define RX_QUEUES 4

#define ONE_SECOND 1e6 // 1s = 1e9 ns
#define RATE 1e6       // 1 MB/s

struct phantom_queue {
    __u64 time;
    __u32 counter;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct phantom_queue);
    __uint(max_entries, RX_QUEUES + 1);
} xdp_general_map SEC(".maps");


static __u64 try_increment_counter(
    __u64 key, struct phantom_queue* queue_read
) {
    // this function should give us better performance
    __u64 now = bpf_ktime_get_coarse_ns();
    __u64 last_refresh = queue_read->time;

    if (now - last_refresh > ONE_SECOND) {
        __u64 res = __sync_val_compare_and_swap(
            &queue_read->time, last_refresh, now
        );

        if (res == last_refresh) {
            // success, reset the counter
            bpf_trace_printk("timer reset: won race", 22);
            queue_read->counter = 0;
        } else {
            bpf_trace_printk("timer reset: lost race", 23);
        }
    }
    // todo: use packet size as increment
    __u64 increment = 1;
    // see https://github.com/llvm/llvm-project/issues/35921 vs
    // https://docs.ebpf.io/linux/concepts/concurrency/
    // atomic add seems to be broken right now
    // we could alternatively use compare and swap, but the performance would probably suck
    
    // __u64 new_counter = __sync_fetch_and_add(&queue_read->counter,
    // increment);
    __sync_fetch_and_add(&queue_read->counter, increment);
    __u64 new_counter = queue_read->counter;
    bpf_trace_printk(
        "Packet counters: QUEUE: %u, COUNTER: %u, TIME: %u", 50, key,
        new_counter, last_refresh
    );
    if (new_counter < RATE) {
        // we are allowed to continue, send the packages
        // todo use bytecount instead of 1
        bpf_trace_printk("counter increment: success", 27);
        return 0;
    } else {
        // our package did not fit, so we drop it
        // note: it may be that a smaller packet would have fit
        // to be super-correct we would have to subtract our increment from the
        // counter again this would add a lot of work for dropping packets, so
        // we leave it.
        bpf_trace_printk("counter increment: failure", 27);
        return 1;
    }
}

SEC("xdp")
int bc_pqp_xdp(struct xdp_md* ctx) {
    bpf_trace_printk("===== BC-PQP on queue %u =====", 31, ctx->rx_queue_index);

    if (ctx->rx_queue_index >= RX_QUEUES) {
        bpf_trace_printk(
            "Unexpected rx queue index: %u >= %u", 36, ctx->rx_queue_index,
            RX_QUEUES
        );
        goto pass;
    }
    // per queue
    /*
    __u32 key = ctx->rx_queue_index;
    struct phantom_queue* queue_read = (struct phantom_queue*)
        bpf_map_lookup_elem(&xdp_general_map, &key);
    if (queue_read == NULL) {
        bpf_trace_printk("Could not read queue-specific element from map", 47);
    } else {
        __u64 result = try_increment_counter(key, queue_read);
        if (result == 0) {
            goto pass;
        } else {
            goto drop;
        }
    }*/

    // total
    __u32 key = RX_QUEUES;
    struct phantom_queue* queue_read = (struct phantom_queue*)
        bpf_map_lookup_elem(&xdp_general_map, &key);
    if (queue_read == NULL) {
        bpf_trace_printk("Could not read total element from map", 38);
    } else {
        __u64 result = try_increment_counter(key, queue_read);
        if (result == 0) {
            goto pass;
        } else {
            goto drop;
        }
    }


drop:
    bpf_trace_printk("We are dropping the packet.", 28);
    return XDP_DROP;
pass:
    bpf_trace_printk("We are passing the packet to the kernel.", 41);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
