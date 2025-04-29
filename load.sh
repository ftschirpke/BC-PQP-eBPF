#!/bin/sh

ip link set dev lo xdpgeneric obj bc-pqp-ebpf-kernel.o sec xdp
