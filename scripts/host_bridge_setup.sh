#!/bin/sh

# usually this should already exist, but just in case
sudo virsh net-define "$(dirname "$0")/default-bridge.xml"
sudo virsh net-start default

sudo ip link add name virbr0 type bridge
sudo ip addr add 192.168.100.1/24 dev virbr0
sudo ip link set virbr0 up

echo "=== SANITY CHECK: ==="
sh $(dirname $0)/host_bridge_status.sh
