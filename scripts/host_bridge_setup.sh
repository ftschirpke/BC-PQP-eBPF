#!/bin/sh

sudo ip link add name br0 type bridge
sudo ip addr add 192.168.100.1/24 dev br0
sudo ip link set br0 up

echo "allow br0" | sudo tee -a /etc/qemu/bridge.conf

echo "=== SANITY CHECK: ==="
sh $(dirname $0)/host_bridge_status.sh
