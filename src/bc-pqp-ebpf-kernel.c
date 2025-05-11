// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/parsing_helpers.h>

#define RX_QUEUES 4

struct stats {
    struct bpf_spin_lock semaphore;
    __u32 counter;
} __attribute__((aligned(8)));

__u32 global_counter = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct stats);
	__uint(max_entries, RX_QUEUES + 1);
} xdp_general_map SEC(".maps");

SEC("xdp")
int bc_pqp_xdp(struct xdp_md* ctx) {
    bpf_trace_printk("===== BC-PQP on queue %u =====", 31, ctx->rx_queue_index);

    if (ctx->rx_queue_index >= RX_QUEUES) {
        bpf_trace_printk("Unexpected rx queue index: %u >= %u", 36, ctx->rx_queue_index, RX_QUEUES);
        goto pass;
    }

    __u32 queue_counter_value = 0;
    __u32 key = ctx->rx_queue_index;
    struct stats *queue_read = (struct stats *)bpf_map_lookup_elem(&xdp_general_map, &key);
    if (queue_read == NULL) {
        bpf_trace_printk("Could not read queue-specific element from map", 47);
    } else {
        bpf_spin_lock(&queue_read->semaphore);
        queue_counter_value = queue_read->counter++;
        bpf_spin_unlock(&queue_read->semaphore);
    }

    __u32 total_counter_value = 0;
    key = RX_QUEUES;
    struct stats *total_read = (struct stats *)bpf_map_lookup_elem(&xdp_general_map, &key);
    if (total_read == NULL) {
        bpf_trace_printk("Could not read total element from map", 38);
    } else {
        bpf_spin_lock(&total_read->semaphore);
        total_counter_value = total_read->counter++;
        bpf_spin_unlock(&total_read->semaphore);
    }

    bpf_trace_printk("Packet counters: QUEUE: %u, TOTAL: %u == %u",
        44,
        queue_counter_value,
        total_counter_value,
        global_counter
    );
    __sync_fetch_and_add(&global_counter, 1);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr *eth_header;
	int eth_type = parse_ethhdr(&nh, data_end, &eth_header);
    eth_type = bpf_ntohs(eth_type);
    bpf_trace_printk("ETH type: 0x%04x (0x%04x is IPv4, 0x%04x is IPv6)", 50, eth_type, ETH_P_IP, ETH_P_IPV6);

	struct iphdr *ipv4_header;
	struct ipv6hdr *ipv6_header;
	if (eth_type == ETH_P_IP) {
		int ipv4_type = parse_iphdr(&nh, data_end, &ipv4_header);
        bpf_trace_printk("IPv4 type: 0x%04x (0x%04x is the expected ICMP, 0x%04x is TCP)", 63, ipv4_type, IPPROTO_ICMP, IPPROTO_TCP);
		if (ipv4_type != IPPROTO_ICMP) {
			goto pass;
        }
	} else if (eth_type == ETH_P_IPV6) {
		int ipv6_type = parse_ip6hdr(&nh, data_end, &ipv6_header);
        bpf_trace_printk("IPv6 type: 0x%04x (0x%04x is the expected ICMPv6, 0x%04x is TCP)", 65, ipv6_type, IPPROTO_ICMPV6, IPPROTO_TCP);
		if (ipv6_type != IPPROTO_ICMPV6) {
			goto pass;
        }
	} else {
		goto pass;
	}

    // swap source and destination IP address
    __u16 echo_reply_type;
	struct icmphdr_common *icmp_header;
	int icmp_type = parse_icmphdr_common(&nh, data_end, &icmp_header);
	if (eth_type == ETH_P_IP && icmp_type == ICMP_ECHO) {
        __be32 tmp_saddr = ipv4_header->saddr;
        ipv4_header->saddr = ipv4_header->daddr;
        ipv4_header->daddr = tmp_saddr;
		echo_reply_type = ICMP_ECHOREPLY;
	} else if (eth_type == ETH_P_IPV6 && icmp_type == ICMPV6_ECHO_REQUEST) {
        struct in6_addr tmp_saddr = ipv6_header->saddr;
        ipv6_header->saddr = ipv6_header->daddr;
        ipv6_header->daddr = tmp_saddr;
		echo_reply_type = ICMPV6_ECHO_REPLY;
	} else {
		goto pass;
	}

    // swap source and destination MAC address
	__u8 tmp_source[ETH_ALEN];
	__builtin_memcpy(tmp_source, eth_header->h_source, ETH_ALEN);
	__builtin_memcpy(eth_header->h_source, eth_header->h_dest, ETH_ALEN);
	__builtin_memcpy(eth_header->h_dest, tmp_source, ETH_ALEN);

    // compute new checksum
    // (see https://github.com/xdp-project/xdp-tutorial/blob/6d3aa8191da499fae8bd4fd5aa89fefa3184274f/packet-solutions/xdp_prog_kern_03.c#L34)
	__u16 old_checksum = icmp_header->cksum;
	icmp_header->cksum = 0;
	struct icmphdr_common old_icmp_header = *icmp_header;
	icmp_header->type = echo_reply_type;
    __u32 size = sizeof(struct icmphdr_common);
	__u32 csum = bpf_csum_diff((__be32 *)&old_icmp_header, size, (__be32 *)icmp_header, size, ~old_checksum);
	__u32 sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	icmp_header->cksum = ~sum;
    bpf_trace_printk("Rewritten checksum 0x%04x -> 0x%04x", 36, old_checksum, icmp_header->cksum);

    bpf_trace_printk("We are actually replying in XDP!", 33);
	return XDP_TX;

pass:
    bpf_trace_printk("We are passing the packet to the kernel.", 41);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
