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

#define PARSING_ERROR -1

#define RX_QUEUES 4
#define PHANTOM_QUEUES 10

#define ONE_SECOND 1e9 // 1s = 1e9 ns
#define RATE 1e6       // 1 MB/s

struct phantom_queue {
    __u64 occupancy;
    __u64 capacity;
    struct bpf_timer policer;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct phantom_queue);
    __uint(max_entries, PHANTOM_QUEUES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_general_map SEC(".maps");

enum packet_classification {
    IPv4_UDP_0x00_TOS,
    IPv4_UDP_0x20_TOS,
    IPv4_UDP_0xb8_TOS,
    IPv4_TCP_0x00_TOS,
    IPv4_TCP_0x20_TOS,
    IPv4_TCP_0xa0_TOS,
    IPv4_TCP_0xb8_TOS,
    IPv4_ICMP,
    IPv6,

    // default value if packet cannot be classified
    // MUST(!) stay last value in enum
    UNCLASSIFIED,
};
_Static_assert(
    UNCLASSIFIED <= PHANTOM_QUEUES, "Number of different classifications must "
                                    "be less or equal to phantom queue count"
);


__u64 classification_counts[UNCLASSIFIED + 1] = {0};

const char* const classification_names[UNCLASSIFIED + 1] = {
    [IPv4_UDP_0x00_TOS] = "IPv4 UDP with TOS of 0x00",
    [IPv4_UDP_0x20_TOS] = "IPv4 UDP with TOS of 0x20",
    [IPv4_UDP_0xb8_TOS] = "IPv4 UDP with TOS of 0xb8",
    [IPv4_TCP_0x00_TOS] = "IPv4 TCP with TOS of 0x00",
    [IPv4_TCP_0x20_TOS] = "IPv4 TCP with TOS of 0x20",
    [IPv4_TCP_0xa0_TOS] = "IPv4 TCP with TOS of 0xa0",
    [IPv4_TCP_0xb8_TOS] = "IPv4 TCP with TOS of 0xb8",
    [IPv4_ICMP] = "IPv4 ICMP",
    [IPv6] = "IPv6",
    [UNCLASSIFIED] = "Unclassified",
};

/*
The policer (one per phantom queue) is responsible for draining the queue
at the desired rate (with the desired policy).
*/
static __u32 policer_callback(
    void* map, __u32* key, struct phantom_queue* queue
) {
    // reset occupancy
    queue->occupancy = 0;

    bpf_trace_printk("Packet classification counts:", 30);
    for (__u32 i = 0; i <= UNCLASSIFIED; i++) {
        bpf_trace_printk(
            "%07ld (%s)", 21, classification_counts[i], classification_names[i]
        );
    }

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

static __u64 try_increment_counter(
    __u32 key, struct phantom_queue* queue, __u64 packet_size
) {
    // see https://github.com/llvm/llvm-project/issues/35921 vs
    // https://docs.ebpf.io/linux/concepts/concurrency/
    // atomic add seems to be broken right now
    __u64 occupancy = queue->occupancy;
    bpf_trace_printk(
        "Packet counters: queu: %u, occupancy: %lu, capacity: %lu", 57, key,
        occupancy, queue->capacity
    );
    if (occupancy + packet_size <= queue->capacity) {
        // we are allowed to continue, send the packages
        bpf_trace_printk("counter increment: success", 27);
        __sync_fetch_and_add(&queue->occupancy, packet_size);
        return 0;
    } else {
        // our package did not fit, so we drop it
        bpf_trace_printk("counter increment: failure", 27);
        return 1;
    }
}

// classify packet using 8-bit DiffServ value from IP's TOS header field
static enum packet_classification classify_packet(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr* eth_header;
    int eth_type = parse_ethhdr(&nh, data_end, &eth_header);
    eth_type = bpf_ntohs(eth_type);

    if (eth_type != ETH_P_IP) {
        if (eth_type == ETH_P_IPV6) {
            return IPv6;
        }
        return UNCLASSIFIED;
    }

    struct iphdr* ipv4_header;
    int ipv4_type = parse_iphdr(&nh, data_end, &ipv4_header);

    switch (ipv4_type) {
        case IPPROTO_UDP: {
            switch (ipv4_header->tos) {
                case 0x00:
                    return IPv4_UDP_0x00_TOS;
                case 0x20:
                    return IPv4_UDP_0x20_TOS;
                case 0xb8:
                    return IPv4_UDP_0xb8_TOS;
                default:
                    bpf_trace_printk(
                        "UNEXPECTED UDP tos: %x", 23, ipv4_header->tos
                    );
                    return UNCLASSIFIED;
            }
        }
        case IPPROTO_TCP:
            switch (ipv4_header->tos) {
                case 0x00:
                    return IPv4_TCP_0x00_TOS;
                case 0x20:
                    return IPv4_TCP_0x20_TOS;
                case 0xa0:
                    return IPv4_TCP_0xa0_TOS;
                case 0xb8:
                    return IPv4_TCP_0xb8_TOS;
                default:
                    bpf_trace_printk(
                        "UNEXPECTED TCP tos: %x", 23, ipv4_header->tos
                    );
                    return UNCLASSIFIED;
            }
        case IPPROTO_ICMP:
            return IPv4_ICMP;
        case PARSING_ERROR:
        default:
            return UNCLASSIFIED;
    }
}

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

    enum packet_classification classification = classify_packet(ctx);
    __u32 key = UNCLASSIFIED;
    if (classification <= UNCLASSIFIED) {
        key = classification;
        __sync_fetch_and_add(&classification_counts[key], 1);
    }

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
