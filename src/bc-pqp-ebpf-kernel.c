// SPDX-License-Identifier: GPL-2.0-or-later
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

struct phantom_queue {
    // how many bytes are currently in this queue
    __s64 occupancy;
    // how many bytes fit in this queue
    __u64 capacity;
    // timestamp of the packet that was sent last
    __u64 last_packet;
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

static __s64 calculate_drain(__u64 now, __u64 previous, __u64 rate) {
    // todo is this always positive?
    __s64 timespan = now - previous;
    return (timespan * rate) / ONE_SECOND;
}

static __u64 try_increment_counter(
    __u32 key, struct phantom_queue* queue, __u64 packet_size
) {
    __u64 now = bpf_ktime_get_ns();
    __u64 last_packet = queue->last_packet;
    __u64 rate = queue->rate;
    __s64 drain = calculate_drain(now, last_packet, rate);
    __u64 prev = __sync_val_compare_and_swap(
        &queue->last_packet, last_packet, now
    );
    __s64 diff;
    if (prev == last_packet) {
        // we won the race, so we will add the drain and our packet to the
        // occupancy
        diff = packet_size - drain;
    } else {
        // we lost the race, meaning someone whose timestamp is very close to
        // ours wrote their results at the same time because of this, the drain
        // between our two timestamps should be negligible
        diff = packet_size;
    }
    // now we are can write to the occupancy, but we still need to check whether
    // it fits into our capacity
    if (queue->occupancy + diff <= queue->capacity) {
        __sync_fetch_and_add(&queue->occupancy, diff);
        bpf_trace_printk("counter increment: success", 27);
        return 0;
    }
    bpf_trace_printk("counter increment: failure", 27);
    return 1;
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
