// SPDX-License-Identifier: GPL-2.0-or-later
#include <limits.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define RX_QUEUES 4

#define ONE_SECOND 1000000000L // 1s = 1e9 ns
#define BURST_TIME 100000000L
#define RATE 1e6 // 1 MB/s

#define DEBUG
#ifdef DEBUG
#define log(...) bpf_trace_printk(__VA_ARGS__)
#else
#define log(...)
#endif

struct phantom_queue {
    // how many bytes are currently in this queue
    __s64 occupancy;
    // how many bytes fit in this queue
    __u64 capacity;
    // timestamp of the packet that was sent last
    __u64 time;
    // how many bytes are drained per second
    __u64 rate;
    // how much of the occupancy is actually magic
    __u64 magic;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct phantom_queue);
    __uint(max_entries, RX_QUEUES + 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_general_map SEC(".maps");

static __u64 calculate_drain(__u64 now, __u64 previous, __u64 rate) {
    __s64 timespan = now - previous;
    if (timespan < (__s64)0) {
        return 0;
    }
    __s64 res = timespan * rate;
    if (res < 0) {
        res = INT_MAX;
    }
    return res / ONE_SECOND;
}

static void burst_control(__u32 key, struct phantom_queue* queue) {
    __u64 occupancy = queue->occupancy;
    __u64 capacity = queue->capacity;
    __u64 r_i = queue->capacity; // todo if we have multiple queues we have to
                                 // estimate this somehow. Maybe with a policer
                                 // that updates a map?
    __u64 x_i = r_i * BURST_TIME / ONE_SECOND;
    // calculate thresholds (0.5, 1.5)
    __u64 x_i_half = x_i >> 1;
    __u64 x_i_plus = x_i, x_i_minus = x_i;
    x_i_plus += x_i_half;
    x_i_minus -= x_i_half;

    if (occupancy > x_i_plus) {
        // fill queue with magic packets
        if (queue->magic == 0) {
            __u64 magic = capacity - occupancy;
            __u64 res = __sync_val_compare_and_swap(&queue->magic, 0, magic);
            if (res == 0) {
                // race won, add magic
                __sync_fetch_and_add(&queue->occupancy, magic);
                log(
                    "added %ld magic bytes to queue %d with occupancy %ld", 53,
                    magic, key, occupancy
                );
            }
        }

    } else if (occupancy < x_i_minus) {
        // remove magic packets
        __u64 magic = queue->magic;

        if (magic != 0) {
            // only drain magic packets if there are any
            __u64 res = __sync_val_compare_and_swap(&queue->magic, magic, 0);
            if (res == magic) {
                // race won, we get to decrement the occupancy
                __sync_fetch_and_sub(&queue->occupancy, magic);
                log(
                    "subtracted %ld magic bytes from queue %d with occupancy "
                    "%ld",
                    60, magic, key, occupancy
                );
            }
        }
    }
}

static __u64 try_increment_counter(
    __u32 key, struct phantom_queue* queue, __u64 packet_size
) {
    burst_control(key, queue);
    
    __u64 now = bpf_ktime_get_ns();
    __u64 previous = queue->time;
    __u64 rate = queue->rate;
    __s64 occupancy = queue->occupancy;
    __u64 drain = calculate_drain(now, previous, rate);

    __s64 diff = 0;
    __u64 prev = __sync_val_compare_and_swap(&queue->time, previous, now);

    if (prev == previous) {
        // the winner adds the drain
        // if we lose someone else will
        diff = -drain;
    }

    __u64 rv;

    // check upper bound
    if (occupancy + diff + ((__s64)packet_size) <= (__s64)queue->capacity) {
        diff += packet_size;
        rv = 0;
        log("counter increment: success", 27);
    } else {
        rv = 1;
        log("counter increment: failure", 27);
    }
    // check lower bound
    if (occupancy + diff > 0) {
        __sync_fetch_and_add(&queue->occupancy, diff);
    } else if (occupancy > 0) {
        __sync_fetch_and_sub(&queue->occupancy, occupancy);
    }
    log("occ: %li, pkt: %lu", 19, occupancy, packet_size);
    log("drain: %li, diff: %li", 22, drain, diff);

    return rv;
}

static __u32 classify_packet(struct xdp_md* ctx) { return 0; }
static __u32 calculate_size(struct xdp_md* ctx) {
    return ctx->data_end - ctx->data;
}

static __u32 initialize(struct phantom_queue* queue) {
    // capacity was already set
    queue->rate = RATE;
    queue->time = bpf_ktime_get_ns();
    return 0;
}


SEC("xdp")
int bc_pqp_xdp(struct xdp_md* ctx) {
    log("===== BC-PQP on rx-queue %u =====", 34, ctx->rx_queue_index);


    __u32 key = classify_packet(ctx);
    __u64 packet_size = calculate_size(ctx);
    struct phantom_queue* queue = (struct phantom_queue*)bpf_map_lookup_elem(
        &xdp_general_map, &key
    );
    if (queue == NULL) {
        log("Could not read element %u from map", 35, key);
        goto abort;
    } else {
        if (queue->capacity == 0) {
            // we are first, start timer and initialize capacity
            __u32 res = __sync_val_compare_and_swap(&queue->capacity, 0, RATE);
            if (!res) {
                // race won, we can initialize our queue
                res = initialize(queue);
                if (res) {
                    log("failed to initialize queue %u", 30, key);
                    goto abort;
                }
            }
        }

        __u64 result = try_increment_counter(key, queue, packet_size);
        if (!result) {
            goto pass;
        } else {
            goto drop;
        }
    }
abort:
    log("We are aborting", 16);
    return XDP_ABORTED;
drop:
    log("We are dropping the packet.", 28);
    return XDP_DROP;
pass:
    log("We are passing the packet to the kernel.", 41);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
