#!/bin/bash

if [ $# -eq 0 ]; then
    f=bc-pqp-ebpf-kernel.o
else
    f=$1
fi

echo "Resolving MAC addresses and writing them to eBPF map:"
echo "If routes are not established, the MAC resolution might take a few seconds..."

ping -c1 192.168.101.10 &> /dev/null
ping -c1 192.168.102.10 &> /dev/null

VM_INGRESS_MAC=$(ip link show eth0 | awk '/ether/ {print $2}')
VM_EGRESS_MAC=$(ip link show eth1 | awk '/ether/ {print $2}')

CLIENT_MAC=$(ip neigh show 192.168.101.10 | awk '{print $5}')
SERVER_MAC=$(ip neigh show 192.168.102.10 | awk '{print $5}')

echo "VM_INGRESS_MAC = $VM_INGRESS_MAC"
echo "VM_EGRESS_MAC = $VM_EGRESS_MAC"
echo "CLIENT_MAC = $CLIENT_MAC"
echo "SERVER_MAC = $SERVER_MAC"

mac2hex() {
    IFS=":" read -ra octets <<< "$1"
    printf "%02x %02x %02x %02x %02x %02x 00 00" "0x${octets[0]}" "0x${octets[1]}" "0x${octets[2]}" \
        "0x${octets[3]}" "0x${octets[4]}" "0x${octets[5]}"
}

HEX_VM_INGRESS_MAC=$(mac2hex $VM_INGRESS_MAC)
HEX_VM_EGRESS_MAC=$(mac2hex $VM_EGRESS_MAC)
HEX_CLIENT_MAC=$(mac2hex $CLIENT_MAC)
HEX_SERVER_MAC=$(mac2hex $SERVER_MAC)

echo "Loading eBPF program $f"
# timers need a userspace reference to work (thats why we use --pin-path)
# see https://docs.ebpf.io/linux/helper-function/bpf_timer_init/
xdp-loader load --pin-path /sys/fs/bpf/bc-pqp -m skb eth0 $f || exit 1

echo "Writing mac addresses to map"

MAP_PATH="/sys/fs/bpf/bc-pqp/mac_map"

bpftool map update pinned $MAP_PATH key 0 0 0 0 value hex $HEX_CLIENT_MAC
bpftool map update pinned $MAP_PATH key 1 0 0 0 value hex $HEX_VM_INGRESS_MAC
bpftool map update pinned $MAP_PATH key 2 0 0 0 value hex $HEX_VM_EGRESS_MAC
bpftool map update pinned $MAP_PATH key 3 0 0 0 value hex $HEX_SERVER_MAC
