// SPDX-License-Identifier: GPL-2.0-or-later
#include <limits.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

#define PARSING_ERROR -1

#ifndef RX_QUEUES
#define RX_QUEUES 4
#endif

#ifndef PHANTOM_QUEUES
#define PHANTOM_QUEUES 4
#endif

#define MEBIBYTE (1 << 20)
#define GIBIBYTE (1 << 30)
#define TEBIBYTE (1 << 40)

#define ONE_SECOND 1000000000L // 1s = 1e9 ns

#ifndef BURST_TIME
#define BURST_TIME 100000000L
#endif

#ifndef RATE
#define RATE GIBIBYTE
#endif

#ifdef DEBUG
#define log(fmt, ...)                                                          \
    do {                                                                       \
        char ____fmt[] = fmt;                                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    } while (0)
#else
#define log(...)                                                               \
    do {                                                                       \
    } while (0)
#endif

#define EGRESS_INTERFACE 3

#ifdef CLASSIFY_BY_DESTINATION
#define CLASSIFY_BY dest
#elif defined(CLASSIFY_BY_SOURCE)
#define CLASSIFY_BY source
#else
#define CLASSIFY_BY source
#endif

enum mac_index {
    MAC_CLIENT,
    MAC_VM_INGRESS,
    MAC_VM_EGRESS,
    MAC_SERVER,
};

#define MAC_ADDRESS_COUNT 4
_Static_assert(
    MAC_SERVER < MAC_ADDRESS_COUNT, "Need enough space for MAC addresses"
);

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} mac_map SEC(".maps");

// bypass kernel networking stack by rewriting the MAC address to eth1
int bypass_kernel_if_possible(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr* eth_header;
    int eth_type = parse_ethhdr(&nh, data_end, &eth_header);
    eth_type = bpf_ntohs(eth_type);

    switch (eth_type) {
        case ETH_P_IP:
            break;
        default:
            log("We are passing the packet to the kernel.");
            return XDP_PASS;
    }

    __u32 server_key = MAC_SERVER;
    __u64* next_hop_mac_ptr = (__u64*)bpf_map_lookup_elem(
        &mac_map, &server_key
    );
    if (next_hop_mac_ptr == NULL) {
        log("Could not find next hop MAC address", 36);
        return XDP_PASS;
    }
    __u64 next_hop_mac = *next_hop_mac_ptr;
    __u8 new_dest[6] = {
        (__u8)((next_hop_mac >> 0) & 0xff),
        (__u8)((next_hop_mac >> 8) & 0xff),
        (__u8)((next_hop_mac >> 16) & 0xff),
        (__u8)((next_hop_mac >> 24) & 0xff),
        (__u8)((next_hop_mac >> 32) & 0xff),
        (__u8)((next_hop_mac >> 40) & 0xff),
    };

    __u32 egress_key = MAC_VM_EGRESS;
    __u64* egress_mac_ptr = (__u64*)bpf_map_lookup_elem(&mac_map, &egress_key);
    if (egress_mac_ptr == NULL) {
        log("Could not find egress MAC address", 34);
        return XDP_PASS;
    }
    __u64 egress_mac = *egress_mac_ptr;
    __u8 new_src[6] = {
        (__u8)((egress_mac >> 0) & 0xff),  (__u8)((egress_mac >> 8) & 0xff),
        (__u8)((egress_mac >> 16) & 0xff), (__u8)((egress_mac >> 24) & 0xff),
        (__u8)((egress_mac >> 32) & 0xff), (__u8)((egress_mac >> 40) & 0xff),
    };

    __builtin_memcpy(eth_header->h_dest, new_dest, ETH_ALEN);
    __builtin_memcpy(eth_header->h_source, new_src, ETH_ALEN);
    log("Kernel Bypass: Redirecting packet %lx -> %lx", 45, egress_mac,
        next_hop_mac);

    return bpf_redirect(EGRESS_INTERFACE, 0);
}

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
    __uint(max_entries, PHANTOM_QUEUES + 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_general_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, PHANTOM_QUEUES + 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} classification_counts SEC(".maps");

static __u64 calculate_drain(__u64 now, __u64 previous, __u64 rate) {
    // can be negative if we have a timing issue and someone who has started
    // after us already managed to write to the queue. In that case our drain
    // was already included in their drain, i.e. we don't have to do anything
    __s64 timespan = (__s64)(now - previous);
    if (timespan < (__s64)0) {
        return 0;
    }
    __s64 res = timespan * (__s64)rate;
    if (res < (__s64)0) {
        res = INT_MAX;
    }
    // res is now unsigned again since 0 <= res <= MAX_INT
    return (__u64)res / ONE_SECOND;
}

/**
    Uses the supplied occupancy and capacity to calculate whether magic needs to
   be added/removed. That amount if any is returned as a signed integer but is
   not yet added to the occupancy.
*/
static __s64 burst_control(
    __u32 key, struct phantom_queue* queue, __s64 occupancy, __u64 capacity
) {
    // unlike in the paper we assume that all queues are active
    // and that the queue size is proportional to the demand
    __u64 r_i = capacity;
    __u64 x_i = r_i * BURST_TIME / ONE_SECOND;
    // calculate thresholds (0.5, 1.5)
    __u64 x_i_half = x_i >> 1;
    __u64 x_i_plus = x_i, x_i_minus = x_i;
    x_i_plus += x_i_half;
    x_i_minus -= x_i_half;

    if (occupancy > (__s64)x_i_plus) {
        // fill queue with magic packets
        if (queue->magic == 0) {
            // because occupancy passed the (signed) comparison above, it must
            // now be >= 0 since capacity must be >= 0 and thus also x_i_plus
            __u64 magic = capacity - (__u64)occupancy;
            __u64 res = __sync_val_compare_and_swap(&queue->magic, 0, magic);
            if (res == 0) {
                log("should add %lu magic bytes to queue %d with occupancy %ld",
                    magic, key, occupancy);
                return (__s64)magic;
            }
        }

    } else if (occupancy < (__s64)x_i_minus) {
        // remove magic packets
        __u64 magic = queue->magic;

        if (magic != 0) {
            // only drain magic packets if there are any
            __u64 res = __sync_val_compare_and_swap(&queue->magic, magic, 0);
            if (res == magic) {
                log("should subtract %ld magic bytes from queue %d with "
                    "occupancy %ld",
                    magic, key, occupancy);
                return (__s64)-magic;
            }
        }
    }
    return 0;
}

static __u64 try_increment_counter(
    __u32 key, struct phantom_queue* queue, __u64 packet_size
) {
    __u64 now = bpf_ktime_get_ns();
    __u64 previous = queue->time;
    __u64 rate = queue->rate;
    __s64 occupancy = queue->occupancy;
    __u64 capacity = queue->capacity;
    __u64 drain = calculate_drain(now, previous, rate);

    __s64 diff = 0;
    __u64 prev = __sync_val_compare_and_swap(&queue->time, previous, now);

    if (prev == previous) {
        // race won, we get to add the drain + magic
        // todo we have already reat occupancy etc. but we change it in
        // burst_control
        __s64 magic = burst_control(key, queue, occupancy, capacity);
        diff += magic;
        diff -= drain;
    }

    __u64 rv;

    // check upper bound
    if (occupancy + diff + (__s64)packet_size <= (__s64)capacity) {
        diff += packet_size;
        rv = 0;
        log("counter increment: success");
    } else {
        rv = 1;
        log("counter increment: failure");
    }
    // check lower bound (we only want to deplete the queue until zero)
    if (occupancy + diff >= 0) {
        // we are positive, i.e. the normal case (add everything)
        __sync_fetch_and_add(&queue->occupancy, diff);
    } else {
        // we either
        // 1. don't have enough tokens left so instead of adding the whole large
        // (negative) diff we just deplete the queue to zero
        // 2. somehow ended up with a negative occupancy, most likely we
        // "overshot" at some point when multiple threads depleted the queue
        // simultaneously (or there was a bug)
        __sync_fetch_and_sub(&queue->occupancy, occupancy);
    }

    log("occ: %li, pkt: %lu", occupancy, packet_size);
    log("drain: %li, diff: %li", drain, diff);

    return rv;
}

/**
 * classify packet using destination port
 **/
static void classify_packet(
    struct xdp_md* ctx, __u32* phantom_queue, __u32* packet_size
) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    __u32 header_size = sizeof(struct ethhdr);
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr* eth;
    int eth_type = parse_ethhdr(&nh, data_end, &eth);
    eth_type = bpf_ntohs(eth_type);

    __u32 port = 0;
    switch (eth_type) {
        case ETH_P_IP: {
            header_size += sizeof(struct iphdr);
            struct iphdr* ip_header;
            __s32 ip_parse_result = parse_iphdr(&nh, data_end, &ip_header);
            if (ip_parse_result == -1) {
                log("Cannot classify packet because IP parsing failed");
                goto default_error;
            }
            __u32 ip_type = (__u32)ip_parse_result;
            switch (ip_type) {
                case IPPROTO_TCP: {
                    struct tcphdr* tcp_header;
                    __s32 tcp_header_size = parse_tcphdr(
                        &nh, data_end, &tcp_header
                    );
                    if (tcp_header_size == -1) {
                        log(
                            "Cannot classify packet because TCP parsing failed"
                        );
                        goto default_error;
                    }
                    header_size += sizeof(struct tcphdr);
                    port = bpf_ntohs(tcp_header->CLASSIFY_BY);
                    break;
                }
                case IPPROTO_UDP: {
                    struct udphdr* udp_header;
                    __s32 udp_header_size = parse_udphdr(
                        &nh, data_end, &udp_header
                    );
                    if (udp_header_size == -1) {
                        log(
                            "Cannot classify packet because UDP parsing failed"
                        );
                        goto default_error;
                    }
                    header_size += sizeof(struct udphdr);
                    port = bpf_ntohs(udp_header->CLASSIFY_BY);
                    break;
                }
                default: {
                    log("Cannot classify packet because of unknown packet "
                        "protocol: %u",
                        ip_type);
                    goto default_error;
                }
            }
        }
    }
    *phantom_queue = port % PHANTOM_QUEUES;
    *packet_size = data_end - data;
#ifdef STRIP_HEADERS
    if (header_size < *packet_size) {
        *packet_size -= header_size;
    } else {
        log("Cannot classify packet because parsed header is larger than parse "
            "packet");
        goto default_error;
    }
#else
    (void)header_size;
#endif
    return;
default_error:
    *phantom_queue = PHANTOM_QUEUES;
    *packet_size = data_end - data;
    return;
}

static __u32 initialize(struct phantom_queue* queue) {
    // capacity was already set
    queue->rate = RATE;
    queue->time = bpf_ktime_get_ns();
    return 0;
}

SEC("xdp")
int bc_pqp_xdp(struct xdp_md* ctx) {
    log("===== BC-PQP on rx-queue %u =====", ctx->rx_queue_index);

    __u32 classification, packet_size;
    classify_packet(ctx, &classification, &packet_size);
    // sanity check for the loader
    // todo this somehow only works with 8 as upper bound?
    if (classification >= 0 && classification <= PHANTOM_QUEUES) {
        __u64* value = (__u64*)bpf_map_lookup_elem(
            &classification_counts, &classification
        );
        if (value != NULL) {
            log("Classification successful: [%u] = %lu", classification,
                *value);
            __sync_fetch_and_add(value, 1);
        } else {
            log("Classification unsuccessful");
            goto abort;
        }
    } else {
        log("Aborting because classification is out of range");
        goto abort;
    }

    struct phantom_queue* queue = (struct phantom_queue*)bpf_map_lookup_elem(
        &xdp_general_map, &classification
    );
    if (queue == NULL) {
        log("Could not read element %u from map", classification);
        goto abort;
    } else {
        if (queue->capacity == 0) {
            // we are first, start timer and initialize capacity
            __u32 res = __sync_val_compare_and_swap(&queue->capacity, 0, RATE);
            if (!res) {
                // race won, we can initialize our queue
                res = initialize(queue);
                if (res) {
                    log("failed to initialize queue %u", classification);
                    goto abort;
                }
            }
        }

        __u64 result = try_increment_counter(
            classification, queue, packet_size
        );
        if (!result) {
            goto pass;
        } else {
            goto drop;
        }
    }
abort:
    log("We are aborting");
    return XDP_ABORTED;
drop:
    log("We are dropping the packet.");
    return XDP_DROP;
pass:
    return bypass_kernel_if_possible(ctx);
}

char _license[] SEC("license") = "GPL";
