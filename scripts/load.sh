#!/bin/sh

# timers need a userspace reference to work (thats why we use --pin-path)
# see https://docs.ebpf.io/linux/helper-function/bpf_timer_init/
xdp-loader load --pin-path /sys/fs/bpf/bc-pqp -m skb eth0 bc-pqp-ebpf-kernel.o
