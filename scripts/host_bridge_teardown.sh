#!/bin/sh

sudo virsh net-destroy default
sudo virsh net-undefine default

sudo ip addr flush dev virbr0
sudo ip link set virbr0 down
sudo ip link delete virbr0 type bridge

echo "=== SANITY CHECK: ==="
sh $(dirname $0)/host_bridge_status.sh
