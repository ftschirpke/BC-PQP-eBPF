// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

// flags allowed in bpf_timer_init, see also
// - https://github.com/tpapagian/go-ebpf-timer/blob/main/fentry.c
// - https://docs.ebpf.io/linux/concepts/timers/
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 7


#define RX_QUEUES 4

#define ONE_SECOND 1e9 // 1s = 1e9 ns
#define RATE 1e6       // 1 MB/s
// burst control
#define UPPER_THRESHOLD (1.5 * RATE)
#define LOWER_THRESHOLD (0.5 * RATE)
#define BURST_TIME_MS 10

struct phantom_queue {
    // how many bytes were send (if occupancy > capacity, how many bytes were
    // requested)
    __u64 occupancy;
    // how many bytes we want to allow
    __u64 capacity;
    // the last time the policer adjusted the occupancy/rate
    __u64 refresh;
    // how much magic is currently in this queue
    __u64 magic;
    // the policer of this queue
    struct bpf_timer policer;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct phantom_queue);
    __uint(max_entries, RX_QUEUES + 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_general_map SEC(".maps");

/*
The policer (one per phantom queue) is responsible for draining the queue
at the desired rate (with the desired policy).
*/
static __u32 policer_callback(
    void* map, __u32* key, struct phantom_queue* queue
) {
    // reset occupancy, don't touch magic packets
    if (queue->occupancy >= RATE) {
        __sync_fetch_and_sub(&queue->occupancy, ((__u64)RATE) - queue->magic);
    } else {
        queue->occupancy = 0 + queue->magic;
    }


    // set last refresh, needed for burst control
    queue->refresh = bpf_ktime_get_ns();

    // reset the timer
    __u64 res = bpf_timer_start(&queue->policer, ONE_SECOND, 0);
    if (res) {
        bpf_trace_printk(
            "error: could not reset policer in callback %ld", 47, res
        );
        return 0;
    }
    bpf_trace_printk("reset occupancy for queue %u", 29, *key);

    return 0;
}

static void burst_control(__u32 key, struct phantom_queue* queue) {
    // todo it is not obvious to me that all magic packets will be removed again
    __u64 occupancy = queue->occupancy;
    __u64 capacity = queue->capacity;
    __u64 interval_ms = (bpf_ktime_get_ns() - queue->refresh) >> 10;

    // the rate for this queue (per bytes/ms)
    // todo: queue->capacity vs r_i?
    __u64 r_i = queue->capacity / interval_ms;
    // capacity (bytes) for this queue in the BURST_TIME_MS window
    __u64 x_i = r_i * BURST_TIME_MS;
    // calculate thresholds
    __u64 x_i_half = x_i >> 1;
    __u64 x_i_plus = x_i, x_i_minus = x_i;
    x_i_plus += x_i_half;
    x_i_minus -= x_i_half;
    if (occupancy > x_i_plus) {
        // fill queue with magic packets
        if (queue->magic == 0) {
            // we can only have one magic in the queue?
            __u64 magic = capacity - occupancy;
            __u64 res = __sync_val_compare_and_swap(&queue->magic, 0, magic);
            if (res == 0) {
                // race won, add magic
                __sync_fetch_and_add(&queue->occupancy, magic);
                bpf_trace_printk(
                    "added %ld magic bytes to queue %d with occupancy %ld", 53,
                    magic, key, occupancy
                );
            }
        }

    } else if (occupancy < x_i_minus) {
        // remove magic packets
        // todo: what happens if the queue was reset in the meantime and we
        // can't subtract that many

        __u64 magic = queue->magic;

        if (magic != 0) {
            // only drain magic packets if there are any
            __u64 res = __sync_val_compare_and_swap(&queue->magic, magic, 0);
            if (res == magic) {
                // race won, we get to decrement the occupancy
                __sync_fetch_and_sub(&queue->occupancy, magic);
                bpf_trace_printk(
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
    // see https://github.com/llvm/llvm-project/issues/35921 vs
    // https://docs.ebpf.io/linux/concepts/concurrency/
    // atomic add seems to be broken right now
    __u64 occupancy = queue->occupancy;
    __u64 capacity = queue->capacity;
    // always increment, we use it to estimate the current rate
    __sync_fetch_and_add(&queue->occupancy, packet_size);

    burst_control(key, queue);


    bpf_trace_printk(
        "Packet counters: queue: %u, occupancy: %lu, capacity: %lu", 58, key,
        occupancy, capacity
    );
    if (occupancy + packet_size <= capacity) {
        // we are allowed to continue, send the packages
        bpf_trace_printk("counter increment: success", 27);
        return 0;
    } else {
        // our package did not fit, so we drop it
        bpf_trace_printk("counter increment: failure", 27);
        return 1;
    }
}

static __u32 classify_packet(struct xdp_md* ctx) { return 0; }
static __u32 calculate_size(struct xdp_md* ctx) {
    return ctx->data_end - ctx->data;
}

static __u32 initialize(struct phantom_queue* queue) {
    // initialize timer
    __u32 res = bpf_timer_init(
        &queue->policer, &xdp_general_map, CLOCK_MONOTONIC
    );
    if (res) {
        bpf_trace_printk("error: could not initialize timer: %ld", 39, res);
        return 1;
    }

    // set the callback for the timer
    res = bpf_timer_set_callback(&queue->policer, policer_callback);
    if (res) {
        bpf_trace_printk("error: could not set timer callback: %ld", 41, res);
        return 1;
    }
    // start the timer
    res = bpf_timer_start(&queue->policer, ONE_SECOND, 0);
    if (res) {
        bpf_trace_printk("error: could not start timer: %ld", 34, res);
        return 1;
    }
    return 0;
}


SEC("xdp")
int bc_pqp_xdp(struct xdp_md* ctx) {
    bpf_trace_printk(
        "===== BC-PQP on rx-queue %u =====", 34, ctx->rx_queue_index
    );


    __u32 key = classify_packet(ctx);
    __u64 packet_size = calculate_size(ctx);
    struct phantom_queue* queue = (struct phantom_queue*)bpf_map_lookup_elem(
        &xdp_general_map, &key
    );
    if (queue == NULL) {
        bpf_trace_printk("Could not read element %u from map", 35, key);
        goto abort;
    } else {
        if (queue->capacity == 0) {
            // we are first, start timer and initialize capacity
            __u32 res = __sync_val_compare_and_swap(&queue->capacity, 0, RATE);
            if (!res) {
                // race won, we can initialize our queue
                res = initialize(queue);
                if (res) {
                    bpf_trace_printk("failed to initialize queue %u", 30, key);
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
    bpf_trace_printk("We are aborting", 16);
    return XDP_ABORTED;
drop:
    bpf_trace_printk("We are dropping the packet.", 28);
    return XDP_DROP;
pass:
    bpf_trace_printk("We are passing the packet to the kernel.", 41);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
