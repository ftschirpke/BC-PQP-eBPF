#!/bin/sh

ip link show br0
echo "--- /etc/qemu/bridge.conf ---"
cat -n /etc/qemu/bridge.conf
