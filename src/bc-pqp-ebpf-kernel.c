// SPDX-License-Identifier: GPL-2.0-or-later
#include <limits.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define PARSING_ERROR -1

#define RX_QUEUES 4
#define PHANTOM_QUEUES 10

#define ONE_SECOND 1000000000L // 1s = 1e9 ns
#define RATE 1e6               // 1 MB/s

#ifdef DEBUG
#define log(...) bpf_trace_printk(__VA_ARGS__)
#else
#define log(...)                                                               \
    do {                                                                       \
    } while (0)
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

static __u64 try_increment_counter(
    __u32 key, struct phantom_queue* queue, __u64 packet_size
) {
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
    // capacity was already set
    queue->rate = RATE;
    queue->time = bpf_ktime_get_ns();
    return 0;
}


SEC("xdp")
int bc_pqp_xdp(struct xdp_md* ctx) {
    log("===== BC-PQP on rx-queue %u =====", 34, ctx->rx_queue_index);

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
