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

// flags allowed in bpf_timer_init, see also
// - https://github.com/tpapagian/go-ebpf-timer/blob/main/fentry.c
// - https://docs.ebpf.io/linux/concepts/timers/
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 7

#ifndef RX_QUEUES
#define RX_QUEUES 4
#endif

#ifndef PHANTOM_QUEUES
// MUST be a power of two
#define PHANTOM_QUEUES 4
#endif

#define MEBIBYTE (1 << 20)
#define GIBIBYTE (1 << 30)
#define TEBIBYTE (1 << 40)

#define MEBIBIT (MEBIBYTE >> 3)
#define GIBIBIT (GIBIBYTE >> 3)
#define TEBIBIT (TEBIBYTE >> 3)

#define ONE_SECOND 1000000000L // 1s = 1e9 ns

#ifndef BURST_TIME
#define BURST_TIME 100000000L
#endif

#ifndef CALLBACK_TIME
#define CALLBACK_TIME 100000000L
#endif

#ifndef RATE
#define RATE GIBIBIT
#endif

#ifdef DEBUG
#define log(fmt, ...)                                                          \
    do {                                                                       \
        bpf_printk(fmt, ##__VA_ARGS__);                                        \
    } while (0)
#else
#define log(...)                                                               \
    do {                                                                       \
    } while (0)
#endif

// likely/unlikely macros have been added in bpf_helpers v1.6.0
// https://github.com/libbpf/libbpf/commit/7a1388d55faa47d80be19a4b050ca58d2343cc0a
// (we don't have that version yet)
#ifndef likely
#define likely(x) (__builtin_expect(!!(x), 1))
#endif

#ifndef unlikely
#define unlikely(x) (__builtin_expect(!!(x), 0))
#endif

#define EGRESS_INTERFACE 3

#ifdef CLASSIFY_BY_DESTINATION
#define CLASSIFY_BY dest
#elif defined(CLASSIFY_BY_SOURCE)
#define CLASSIFY_BY source
#else
#define CLASSIFY_BY source
#endif
// a poor-mans log_2, calculated by looking at the MSB
#define ld(x) (64 - (__u32)__builtin_clzll((__u64)x))

#define INIT_NOT_STARTED 0
#define INIT_STARTED 1
#define INIT_DONE 2

#define UPDATE_NOT_STARTED 0
#define UPDATE_THROUGHPUT 1
#define UPDATE_CAPACITY_DOWN 2
#define UPDATE_CAPACITY_UP 3


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
static __u32 bypass_kernel_if_possible(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr* eth_header;
    __s32 eth_type = parse_ethhdr(&nh, data_end, &eth_header);
    eth_type = bpf_ntohs(eth_type);

    if (unlikely(eth_type != ETH_P_IP)) {
        log("We are passing the packet to the kernel.");
        return XDP_PASS;
    }

    __u32 server_key = MAC_SERVER;
    __u64* next_hop_mac_ptr = (__u64*)bpf_map_lookup_elem(
        &mac_map, &server_key
    );
    if (unlikely(next_hop_mac_ptr == NULL)) {
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
    if (unlikely(egress_mac_ptr == NULL)) {
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

struct local_phantom_queue {
    // how many bytes are currently in this queue
    __s64 occupancy;
    // how many bytes fit in this queue
    __u64 capacity;
    // timestamp of the packet that was sent last
    __u64 time;
    // how much of the occupancy is actually magic
    __u64 magic;
    // counter for burst control
    __u64 burst_occupancy;
    // how much bytes wanted to get through this queue (passed & aborted)
    __u64 throughput;
    // diff of rate to capacity
    __s32 rate_diff;
    // reset flag (set from global timer)
    __u32 reset;
};

struct global_phantom_queue {
    __u64 capacity;
    __u64 rate;
    __u64 rx_queue_throughput[RX_QUEUES];
};

struct global_queues {
    __u64 initialized;
    struct bpf_timer timer;
    struct global_phantom_queue queues[PHANTOM_QUEUES];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct local_phantom_queue);
    __uint(max_entries, PHANTOM_QUEUES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_general_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_queues);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} global_queues_map SEC(".maps");

static __u32 timer_callback(
    void* map, __u32* key, struct global_queues* globals
) {
    __u64 aggregate_throughput[PHANTOM_QUEUES] = {0};
    __u32 rx_queue, ph_queue_key, ph_queue, res;
    // get all current throughput measurements and aggregate them

    bpf_for(rx_queue, 0, RX_QUEUES) {
        bpf_for(ph_queue, 0, PHANTOM_QUEUES) {
            // this is a small trick to make the verifier happy
            // we need to pass a reference of rx_queue to bpf_map_lookup_elem,
            // which will reset all assertions the verifier has about this
            // variable (i.e. bounds). We use a single-use copy to circumvent
            // problems.
            ph_queue_key = ph_queue;
            struct local_phantom_queue* lq = (struct local_phantom_queue*)
                bpf_map_lookup_percpu_elem(
                    &xdp_general_map, &ph_queue_key, rx_queue
                );
            if (unlikely(lq == NULL)) {
                log("failed to read from local_queues index %u, core %u",
                    ph_queue_key, rx_queue);
                goto reset_timer;
            }
            // checkt that the local queue has reset the field,
            // otherwise assume that it it inactive
            __u64 curr_tp;
            if (lq->reset == UPDATE_NOT_STARTED) {
                curr_tp = lq->throughput;
            } else {
                curr_tp = 1;
            }

            __u64 prev_tp = globals->queues[ph_queue]
                                .rx_queue_throughput[rx_queue];
            // update global moving average
            __u64 avg = (prev_tp + curr_tp) / 2;
            log("throughput in queue (ph: %u, rx: %u) is (curr: %lu, prev: "
                "%lu, new: %lu)",
                ph_queue, rx_queue, curr_tp, prev_tp, avg);
            globals->queues[ph_queue].rx_queue_throughput[rx_queue] = avg;
            // save per-phantom-queue average
            aggregate_throughput[ph_queue] += avg;
        }
    }

    // calculate updated capacity & rate values and set them in the local queues

    bpf_for(rx_queue, 0, RX_QUEUES) {
        bpf_for(ph_queue, 0, PHANTOM_QUEUES) {
            ph_queue_key = ph_queue;
            struct local_phantom_queue* lpq = (struct local_phantom_queue*)
                bpf_map_lookup_percpu_elem(
                    &xdp_general_map, &ph_queue_key, rx_queue
                );
            if (unlikely(lpq == NULL)) {
                log("failed to read from local_queues index %u, core %u",
                    ph_queue_key, rx_queue);
                goto reset_timer;
            }
            __u64 local_throughput = globals->queues[ph_queue]
                                         .rx_queue_throughput[rx_queue];
            __u64 agg_throughput = aggregate_throughput[ph_queue];
            __u64 global_capacity = globals->queues[ph_queue].capacity;
            __u64 local_capacity = (local_throughput * global_capacity)
                                   / agg_throughput;
            __u64 old_local_capacity = lpq->capacity;
            log("update queue: agg: %lu, local tp: %lu, global cap: %lu",
                agg_throughput, local_throughput, global_capacity);
            log("update queue (ph: %u, rx: %u) capacity (old: %lu, new: %lu)",
                ph_queue, rx_queue, old_local_capacity, local_capacity);
            if (old_local_capacity != local_capacity) {
                __sync_lock_test_and_set(&lpq->capacity, local_capacity);
                // signal to the local queue that it should reset it's
                // throughput counter, and that we have changed the capacity
                __sync_lock_test_and_set(
                    &lpq->reset, old_local_capacity > local_capacity
                                     ? UPDATE_CAPACITY_DOWN
                                     : UPDATE_CAPACITY_UP
                );
            } else {
                // signal to the local queue that it should reset it's
                // throughput counter
                __sync_lock_test_and_set(&lpq->reset, UPDATE_THROUGHPUT);
            }
        }
    }

// reset the timer
reset_timer:
    res = bpf_timer_start(&globals->timer, CALLBACK_TIME, 0);
    log("resetting timer");
    if (unlikely(res)) {
        log("error: could not reset timer in callback %ld", res);
    }
    return 0;
}

static __u64 calculate_drain(__u64 now, __u64 previous, __u64 rate) {
    // can be negative if we have a timing issue and someone who has started
    // after us already managed to write to the queue. In that case our
    // drain was already included in their drain, i.e. we don't have to do
    // anything
    __s64 timespan = (__s64)(now - previous);
    if (unlikely(timespan < (__s64)0)) {
        return 0;
    }

    // we try detect overflows (in a performant fashion)
    if (unlikely(ld(rate) + ld(timespan) <= sizeof(__u64) * 8)) {
        return (rate * (__u64)timespan) / ONE_SECOND;
    } else {
        log("overflowing drain detected (timespan: %ld, rate: %lu)", timespan,
            rate);
        return (((__u64)timespan) / ONE_SECOND) * rate;
    }
}

/**
    Uses the supplied occupancy and capacity to calculate whether magic needs to
   be added/removed. That amount if any is returned as a signed integer but is
   not yet added to the occupancy.
*/
static __s64 burst_control(
    __u32 key, struct local_phantom_queue* queue, __u64 previous, __u64 now,
    __u64 packet_size
) {
    // unlike in the paper we assume that all queues are active
    // and that the queue size is proportional to the demand
    __u8 rolled_over, reset;
    __u64 burst_occupancy;

    reset = queue->reset;
    if (reset != UPDATE_NOT_STARTED) {
        // the global timer has asked us to reset the throughput counter
        queue->reset = UPDATE_NOT_STARTED;
        queue->throughput = packet_size;
        if (reset == UPDATE_CAPACITY_DOWN) {
            // the queue size was decreased by the timer
            if (queue->occupancy > (__s64)queue->capacity) {
                __u64 removed = (__u64)queue->occupancy - queue->capacity;
                queue->occupancy -= (__s64)removed;
                queue->magic = queue->magic > removed ? queue->magic - removed
                                                      : 0;
            }
        } else if (reset == UPDATE_CAPACITY_UP) {
            if (queue->magic != 0 && queue->occupancy > 0) {
                // the queue size was increased and since there was magic in it
                // we assume that it was (almost) full. We want to stay close to
                // that state, so we fill up the queue and adjust the saved
                // magic accordingly
                __u64 added = queue->capacity - (__u64)queue->occupancy;
                queue->magic += added;
                queue->occupancy += (__s64)added;
            }
        }
    }

    __u64 burst_window_offset = (previous % BURST_TIME) + (now - previous);
    // the following is equivalent to
    // 'previous / BURST_TIME == now / BURST_TIME'
    // in the below version we only need one modulo calculation (instead of 2
    // divisions) which should be faster
    if (likely(burst_window_offset < BURST_TIME)) {
        rolled_over = 0;
        queue->burst_occupancy += packet_size;
        burst_occupancy = queue->burst_occupancy;
    } else {
        // we have rolled over to a new BURST_TIME slot
        // we can be sure that nobody else tries to reset burst_occupancy
        // because we have won the compare_and_swap on the timestamp, and we can
        // guarantee that there is always just one pair of previous / now
        // timestamps that "crosses a BURST_TIME border" because our time is
        // monotonic
        rolled_over = 1;
        burst_occupancy = queue->burst_occupancy;
        queue->burst_occupancy = packet_size;
        if (unlikely(burst_window_offset >= 2 * BURST_TIME)) {
            // we missed at least one BURST_TIME slot (no packet arrived)
            // therefore the last burst occupancy was actually 0
            // (and not the previous value as usual)
            burst_occupancy = 0;
        }
    }


    __u64 r_i = (__u64)((__s64)queue->capacity + queue->rate_diff);
    __u64 x_i = r_i * BURST_TIME / ONE_SECOND;
    // calculate thresholds (0.5, 1.5)
    __u64 x_i_half = x_i >> 1;
    __u64 x_i_plus = x_i, x_i_minus = x_i;
    x_i_plus += x_i_half;
    x_i_minus -= x_i_half;

    if (burst_occupancy > x_i_plus) {
        // fill queue with magic packets
        if (queue->magic == 0) {
            __u64 magic = queue->capacity - (__u64)queue->occupancy;
            queue->magic = magic;
            log("should add %lu magic bytes to queue %d with burst "
                "occupancy %lu",
                magic, key, burst_occupancy);
            return (__s64)magic;
        }

    } else if (rolled_over == 1 && burst_occupancy < x_i_minus) {
        // we only check for "underflow" once a BURST_TIME period is complete
        // remove magic packets
        __u64 magic = queue->magic;

        if (magic != 0) {
            // only drain magic packets if there are any
            queue->magic = 0;
            log("should subtract %ld magic bytes from queue %d with burst "
                "occupancy %lu",
                magic, key, burst_occupancy);
            return (__s64)-magic;
        }
    }
    return 0;
}

static __u64 try_increment_counter(
    __u32 key, struct local_phantom_queue* queue, __u64 packet_size
) {
    // always count throughput, no matter whether we pass/drop this packet
    queue->throughput += packet_size;

    __u64 now = bpf_ktime_get_ns();
    __u64 previous = queue->time;
    __u64 capacity = queue->capacity;
    __u64 rate = (__u64)((__s64)capacity + queue->rate_diff);
    __u64 drain = calculate_drain(now, previous, rate);

    __s64 diff = 0;

    queue->time = now;
    __s64 magic = burst_control(key, queue, previous, now, packet_size);
    // burst control might change the occupancy, so we should read it only after
    // that's done
    __s64 occupancy = queue->occupancy;

    diff += magic;
    diff -= drain;


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
        queue->occupancy += diff;
    } else {
        // we either
        // 1. don't have enough tokens left so instead of adding the whole large
        // (negative) diff we just deplete the queue to zero
        // 2. somehow ended up with a negative occupancy, most likely we
        // "overshot" at some point when multiple threads depleted the queue
        // simultaneously (or there was a bug)
        queue->occupancy -= occupancy;
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
    __s32 eth_type = parse_ethhdr(&nh, data_end, &eth);
    eth_type = bpf_ntohs(eth_type);

    __u32 port = 0;
    switch (eth_type) {
        case ETH_P_IP: {
            header_size += sizeof(struct iphdr);
            struct iphdr* ip_header;
            __s32 ip_parse_result = parse_iphdr(&nh, data_end, &ip_header);
            if (unlikely(ip_parse_result == -1)) {
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
                    if (unlikely(tcp_header_size == -1)) {
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
                    if (unlikely(udp_header_size == -1)) {
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
                    log("Cannot classify packet because of unknown transport "
                        "protocol: %u",
                        ip_type);
                    goto default_error;
                }
            }
            break;
        }
        default: {
            log("Cannot classify packet because of unknown internet "
                "protocol: %u",
                eth_type);
            goto default_error;
        }
    }
    *phantom_queue = port % PHANTOM_QUEUES;
    *packet_size = data_end - data;
#ifdef STRIP_HEADERS
    if (likely(header_size < *packet_size)) {
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

static __u32 initialize(struct global_queues* globals) {
    // initialize global structures
    // we use __sync_lock_test_and_set to make sure those changes are immediatly
    // written to main memory and not cached. Since we wait for initialization
    // to complete before accessing the maps, other threads should never see the
    // uninitialized structures.

    __u32 rx_queue, ph_queue, ph_queue_key;
    bpf_for(ph_queue, 0, PHANTOM_QUEUES) {
        __sync_lock_test_and_set(&(globals->queues[ph_queue].capacity), RATE);
        __sync_lock_test_and_set(&(globals->queues[ph_queue].rate), RATE);
        bpf_for(rx_queue, 0, RX_QUEUES) {
            __sync_lock_test_and_set(
                &(globals->queues[ph_queue].rx_queue_throughput[rx_queue]), 1
            );
        }
    }

    // initialize local structures
    __u64 time = bpf_ktime_get_ns();
    bpf_for(rx_queue, 0, RX_QUEUES) {
        bpf_for(ph_queue, 0, PHANTOM_QUEUES) {
            ph_queue_key = ph_queue;
            struct local_phantom_queue* lpq = (struct local_phantom_queue*)
                bpf_map_lookup_percpu_elem(
                    &xdp_general_map, &ph_queue_key, rx_queue
                );
            if (unlikely(lpq == NULL)) {
                log("failed to read from local_queues index %u, core %u",
                    ph_queue_key, rx_queue);
                return 1;
            }
            __sync_lock_test_and_set(&(lpq->capacity), RATE / RX_QUEUES);
            __sync_lock_test_and_set(&(lpq->rate_diff), 0);
            __sync_lock_test_and_set(&(lpq->time), time);
            __sync_lock_test_and_set(&(lpq->throughput), 1);
        }
    }

    // initialize timer
    __u32 res = bpf_timer_init(
        &globals->timer, &global_queues_map, CLOCK_MONOTONIC
    );
    if (unlikely(res)) {
        log("error: could not initialize timer: %ld", res);
        return 1;
    }
    res = bpf_timer_set_callback(&globals->timer, timer_callback);
    if (unlikely(res)) {
        log("error: could not set timer callback: %ld", res);
        return 1;
    }
    res = bpf_timer_start(&globals->timer, CALLBACK_TIME, 0);
    if (unlikely(res)) {
        log("error: could not start timer: %ld", res);
        return 1;
    }
    __sync_lock_test_and_set(&globals->initialized, INIT_DONE);
    log("global initialization done (data initialized and timer scheduled)");
    return 0;
}

SEC("xdp")
__u32 bc_pqp_xdp(struct xdp_md* ctx) {
    log("===== BC-PQP on rx-queue %u =====", ctx->rx_queue_index);

    __u32 zero = 0;
    struct global_queues* globals = (struct global_queues*)bpf_map_lookup_elem(
        &global_queues_map, &zero
    );
    if (likely(globals != NULL)) {
        if (likely(globals->initialized == INIT_DONE)) {
            // everything is already initialized
        } else {
            // try to initialize
            if (!__sync_val_compare_and_swap(
                    &globals->initialized, INIT_NOT_STARTED, INIT_STARTED
                )) {
                initialize(globals);
            } else {
                // someone else is initializing, just pass in the meantime
                goto pass;
            }
        }
    } else {
        log("failed to get global timer");
        goto abort;
    }


    __u32 classification, packet_size;
    classify_packet(ctx, &classification, &packet_size);

    if (likely(classification < PHANTOM_QUEUES)) {
        struct local_phantom_queue* queue = (struct local_phantom_queue*)
            bpf_map_lookup_elem(&xdp_general_map, &classification);
        if (likely(queue != NULL)) {
            __u64 result = try_increment_counter(
                classification, queue, packet_size
            );
            if (!result) {
                goto pass;
            } else {
                goto drop;
            }
        } else {
            // something went wrong
            goto abort;
        }
    } else {
        // unknown classification, let the kernel deal with it
        goto kernel;
    }


abort:
    log("We are aborting");
    return XDP_ABORTED;
drop:
    log("We are dropping the packet.");
    return XDP_DROP;
pass:
    return bypass_kernel_if_possible(ctx);
kernel:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
