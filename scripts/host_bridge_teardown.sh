#!/bin/sh

sudo ip addr flush dev br0
sudo ip link set br0 down
sudo ip link delete br0 type bridge

sudo sed -i "/^allow br0$/d" /etc/qemu/bridge.conf

echo "=== SANITY CHECK: ==="
ip link show br0
echo "--- /etc/qemu/bridge.conf ---"
cat -n /etc/qemu/bridge.conf
