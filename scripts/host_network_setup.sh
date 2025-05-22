#!/bin/sh

### NETWORK SETUP
#
# This script sets up a list of network devices to allow for
# network testing only on the host but still running traffic
# through the VM.
#
# The setup allows to ping from one host network namespace
# the other with all trafiic passing through the VM.
# i.e.
#   sudo ip netns exec ns1 ping 192.168.102.10
#   sudo ip netns exec ns2 ping 192.168.101.10
#
# The diagram below shows a high-level (not perfectly accurate)
# overview of the resulting network.
#
# TODO: currently, echos 1 through 9 are dropped, probably due to ARP
# INFO: There may be easier solutions to achieve the same goal.
#
#   +--------- ns1 ----------+     +--------- ns2 ----------+
#   |  +------------------+  |     |  +------------------+  |
#   |  |     veth1_ns     |  |     |  |     veth2_ns     |  |
#   |  |  192.168.101.10  |  |     |  |  192.168.102.10  |  |
#   |  +--------+---------+  |     |  +--------+---------+  |
#   |           ^            |     |           ^            |
#   +-----------|------------+     +-----------|------------+
#               | (veth1)                      | (veth2)
#               v                              v
#      +--------+---------+           +--------+---------+   
#      |    veth1_host    |           |    veth2_host    |   
#      | (192.168.101.20) |           | (192.168.102.20) |   
#      +--------+---------+           +--------+---------+   
#               |                              |
#      +--------+---------+           +--------+---------+
#      |       br1        |           |       br2        |
#      |  192.168.101.30  |           |  192.168.102.30  |
#      +--------+---------+           +--------+---------+
#               ^                              ^
#               |                              |
#      +--------+---------+           +--------+---------+
# HOST |    Tap device    |           |    Tap device    |
# -----|    created by    |-----------|    created by    |-----
# VM   |   virt-install   |           |   virt-install   |
#      +--------+---------+           +--------+---------+
#               |                              |
#               v                              v
#      +--------+---------+           +--------+---------+
#      |       eth0       |           |       eth1       |
#      |  192.168.101.100 |           |  192.168.102.100 |
#      +--------+---------+           +--------+---------+
#               |                              |
#      +--------+------------------------------+---------+
#      |            Our XDP Program (BC-PQP)             |
#      + - - - - - - - - - - - - - - - - - - - - - - - - +
#      |           VM Kernel Networking Stack            |
#      +-------------------------------------------------+
#


sudo ip link add br1 type bridge
sudo ip link add br2 type bridge

sudo ip link set br1 up
sudo ip link set br2 up

sudo ip netns add ns1
sudo ip netns add ns2

sudo ip link add veth1_host type veth peer name veth1_ns
sudo ip link add veth2_host type veth peer name veth2_ns

sudo ip link set veth1_ns netns ns1
sudo ip link set veth2_ns netns ns2

sudo ip netns exec ns1 ip link set veth1_ns up
sudo ip netns exec ns2 ip link set veth2_ns up

sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up

sudo ip netns exec ns1 ip addr add 192.168.101.10/24 dev veth1_ns
sudo ip netns exec ns2 ip addr add 192.168.102.10/24 dev veth2_ns

sudo ip link set veth1_host master br1
sudo ip link set veth2_host master br2

sudo ip link set veth1_host up
sudo ip link set veth2_host up

# sudo ip addr add 192.168.101.20/24 dev veth1_host
# sudo ip addr add 192.168.102.20/24 dev veth2_host

sudo ip addr add 192.168.101.30/24 dev br1
sudo ip addr add 192.168.102.30/24 dev br2

sudo ip netns exec ns1 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec ns2 sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec ns1 ip route add default via 192.168.101.100 dev veth1_ns
sudo ip netns exec ns2 ip route add default via 192.168.102.100 dev veth2_ns

