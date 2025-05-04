// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <xdp/parsing_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx) {
    bpf_trace_printk("BC-PQP program called", 22);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
	struct hdr_cursor nh;
    nh.pos = data;

    bpf_trace_printk("Set data pointers", 18);

	struct ethhdr *eth_header;
	/* struct iphdr *ip_header; */
	/* struct ipv6hdr *ipv6_header; */
	/* struct icmphdr_common *icmp_header; */

    bpf_trace_printk("Parsing ETH...", 15);
    int eth_type = parse_ethhdr(&nh, data_end, &eth_header);
    /* bpf_trace_printk("Parsed ETH... %d", 17, eth_type); */

    (void) eth_type;
    (void) data_end;
    (void) eth_header;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
