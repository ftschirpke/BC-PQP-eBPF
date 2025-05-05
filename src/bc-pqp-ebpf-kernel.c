// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

// the original function from <xdp/parsing_helpers.h> copied for debugging purposes
static __always_inline int parse_ethhdr_own(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	struct vlan_hdr *vlh;
	__u16 h_proto;

	if (eth + 1 > data_end)
		return -1;

	nh->pos = eth + 1;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
    // BUG: loop causes errors on loading
	/* #pragma unroll */
	/* for (int i = 0; i < VLAN_MAX_DEPTH; i++) { */
	/* 	if (!proto_is_vlan(h_proto)) */
	/* 		break; */

	/* 	if (vlh + 1 > data_end) */
	/* 		break; */

	/* 	h_proto = vlh->h_vlan_encapsulated_proto; */
	/* 	vlh++; */
	/* } */

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

// the original function from <xdp/parsing_helpers.h> copied for debugging purposes
static __always_inline int parse_iphdr_own(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	/* if (nh->pos + hdrsize > data_end) */ // BUG: causes errors on loading
	/* 	return -1; */

    (void) hdrsize;
	/* nh->pos += hdrsize; */ // BUG: causes errors on loading
	*iphdr = iph;

	return iph->protocol;
}

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx) {
    bpf_trace_printk("BC-PQP program called", 22);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh;
    nh.pos = data;

    bpf_trace_printk("Set data pointers", 18);

	struct ethhdr *eth_header;
	struct iphdr *ip_header;
	/* struct ipv6hdr *ipv6_header; */
	/* struct icmphdr_common *icmp_header; */

    bpf_trace_printk("Parsing ETH...", 15);
    int eth_type = parse_ethhdr_own(&nh, data_end, &eth_header);
    eth_type = bpf_ntohs(eth_type);
    bpf_trace_printk("Parsed ETH... 0x%04x", 21, eth_type);
    int ip_type;
    if (eth_type == ETH_P_IP) {
        ip_type = parse_iphdr_own(&nh, data_end, &ip_header);
        if (ip_type != IPPROTO_ICMP) {
            bpf_trace_printk("Passing IP packet with non-ICMP protocol", 41);
            return XDP_PASS;
        }
    } else {
        bpf_trace_printk("Passing non-IP packet", 22);
        return XDP_PASS;
    }
    
    // TODO: swap source and destination values
    // TODO: fix checksums

    bpf_trace_printk("Reached end of function", 24);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
