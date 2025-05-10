#!/bin/sh

ip link show virbr0
virsh net-info default 
echo "--- /etc/qemu/bridge.conf ---"
cat -n /etc/qemu/bridge.conf
