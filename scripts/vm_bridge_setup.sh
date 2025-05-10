#!/bin/sh

ip addr add 192.168.100.2/24 dev eth0
ip link set eth0 up

echo "=== SANITY CHECK: ==="
ip a
