#!/bin/sh

### NETWORK TEARDOWN
#
# This script deletes all the network devices created
# in the host_network_setup.sh script.

sudo ip addr flush dev br1
sudo ip addr flush dev br2

sudo ip link set br1 down
sudo ip link set br2 down

sudo ip link del veth1_host
sudo ip link del veth2_host

sudo ip link delete br1 type bridge
sudo ip link delete br2 type bridge

sudo ip netns del ns1
sudo ip netns del ns2

