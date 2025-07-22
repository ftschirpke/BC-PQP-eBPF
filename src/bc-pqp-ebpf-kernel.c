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

#define PHANTOM_QUEUES 10

#define MEBIBYTE (1 << 20)
#define GIBIBYTE (1 << 30)
#define TEBIBYTE (1 << 40)

#define ONE_SECOND 1000000000L // 1s = 1e9 ns
#define BURST_TIME 100000000L
#define RATE GIBIBYTE

#define STRIP_HEADERS

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

// todo increasing this doesn't help somehow?
__u64 classification_counts[PHANTOM_QUEUES + 1] = {0};

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

static void burst_control(__u32 key, struct phantom_queue* queue) {
    __s64 occupancy = queue->occupancy;
    __u64 capacity = queue->capacity;
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
                // race won, add magic
                __sync_fetch_and_add(&queue->occupancy, (__s64)magic);
                log("added %ld magic bytes to queue %d with occupancy %ld",
                    magic, key, occupancy);
            }
        }

    } else if (occupancy < (__s64)x_i_minus) {
        // remove magic packets
        __u64 magic = queue->magic;

        if (magic != 0) {
            // only drain magic packets if there are any
            __u64 res = __sync_val_compare_and_swap(&queue->magic, magic, 0);
            if (res == magic) {
                // race won, we get to decrement the occupancy
                __sync_fetch_and_sub(&queue->occupancy, (__s64)magic);
                log("subtracted %ld magic bytes from queue %d with occupancy "
                    "%ld",
                    magic, key, occupancy);
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
        diff = (__s64)-drain;
    }

    __u64 rv;

    // check upper bound
    if (occupancy + diff + ((__s64)packet_size) <= (__s64)queue->capacity) {
        diff += packet_size;
        rv = 0;
        log("counter increment: success");
    } else {
        rv = 1;
        log("counter increment: failure");
    }
    // check lower bound
    if (occupancy + diff > 0) {
        __sync_fetch_and_add(&queue->occupancy, diff);
    } else if (occupancy > 0) {
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
    __u32 header_size = 0;
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr* eth;
    int eth_type = parse_ethhdr(&nh, data_end, &eth);
    eth_type = bpf_ntohs(eth_type);

    if ((void*)(eth + 1) > data_end)
        goto default_error;
    void* ip_start = (void*)eth + 1;
    __u32 port;
    switch (eth_type) {
        case ETH_P_IP: {
            header_size += 20;
            struct iphdr* ip = (struct iphdr*)ip_start;
            if ((void*)(ip + 1) > data_end)
                goto default_error;
            __u64 ip_hdr_len = ip->ihl * 4;

            if ((void*)ip + ip_hdr_len > data_end) {
                goto default_error;
            }
            if (ip->frag_off != 0)
                goto default_error;
            void* transport_start = (void*)((__u8*)ip + ip_hdr_len);
            __u8 protocol = ip->protocol;
            switch (protocol) {
                case IPPROTO_TCP: {
                    header_size += 20;
                    struct tcphdr* tcp = (struct tcphdr*)transport_start;
                    if ((void*)(tcp + 1) > data_end)
                        goto default_error;
                    port = bpf_ntohs(tcp->source);
                    break;
                }
                case IPPROTO_UDP: {
                    header_size += 8;
                    struct udphdr* udp = (struct udphdr*)transport_start;
                    if ((void*)(udp + 1) > data_end)
                        goto default_error;
                    port = bpf_ntohs(udp->source);
                    break;
                }
                default:
                    goto default_error;
            }
            break;
        }
        default:
            goto default_error;
    }
    *phantom_queue = port % PHANTOM_QUEUES;
    *packet_size = data_end - data - header_size;
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
        classification_counts[classification]++;
    } else {
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
