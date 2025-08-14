#!/bin/bash

if [ $# -eq 0 ]; then
    f=bc-pqp-ebpf-kernel.o
else
    f=$1
fi

echo "Loading eBPF program $f"
# timers need a userspace reference to work (thats why we use --pin-path)
# see https://docs.ebpf.io/linux/helper-function/bpf_timer_init/
xdp-loader load -vv --pin-path /sys/fs/bpf/bc-pqp -m skb eth0 $f || exit 1
