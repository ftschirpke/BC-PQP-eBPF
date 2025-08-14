#!/usr/bin/env bash

# === Configuration: ===

# TODO

INGRESS_IF_NAME="eno1"
EGRESS_IF_INDEX="2"
EGRESS_IF_MAC_ADDRESS="aa:bb:cc:dd:ee:ff"
NEXT_HOP_MAC_ADDRESS="aa:bb:cc:dd:ee:ff"

RX_QUEUES="4"
FLOWS="4"
BITRATE="1000000000"

CLANG="clang"

SUDO="sudo" # leave empty if sudo not required

# =====================

BITRATE="${BITRATE}L"

mac2hex() {
    IFS=":" read -ra octets <<< "$1"
    printf "0x%02x%02x%02x%02x%02x%02x" "0x${octets[0]}" "0x${octets[1]}" "0x${octets[2]}" \
        "0x${octets[3]}" "0x${octets[4]}" "0x${octets[5]}"
}

HEX_EGRESS_IF_MAC=$(mac2hex $EGRESS_IF_MAC_ADDRESS)
HEX_NEXT_HOP_MAC=$(mac2hex $NEXT_HOP_MAC_ADDRESS)

WARN_FLAGS="-Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wsign-compare -Wimplicit-fallthrough -Wsign-conversion -Werror"

PROGRAM_NAME="bc-pqp-ebpf-kernel"

echo "Compiling with command:"
echo $CLANG -target bpf \
    -D __BPF_TRACING__ \
    -D CLASSIFY_BY_DESTINATION \
    -DRX_QUEUES="$RX_QUEUES" \
    -DPHANTOM_QUEUES="$FLOWS" \
    -DBITRATE="$BITRATE" \
    -DEGRESS_INTERFACE="$EGRESS_IF_INDEX" \
    -DEGRESS_MAC="$HEX_EGRESS_IF_MAC" \
    -DNEXT_HOP_MAC="$HEX_NEXT_HOP_MAC" \
    -O2 -g \
    $WARN_FLAGS \
    -c "$PROGRAM_NAME.c" \
    -o "$PROGRAM_NAME.o"

$CLANG -target bpf \
    -D __BPF_TRACING__ \
    -D CLASSIFY_BY_DESTINATION \
    -DRX_QUEUES="$RX_QUEUES" \
    -DPHANTOM_QUEUES="$FLOWS" \
    -DBITRATE="$BITRATE" \
    -DEGRESS_INTERFACE="$EGRESS_IF_INDEX" \
    -DEGRESS_MAC="$HEX_EGRESS_IF_MAC" \
    -DNEXT_HOP_MAC="$HEX_NEXT_HOP_MAC" \
    -O2 -g \
    $WARN_FLAGS \
    -c "$PROGRAM_NAME.c" \
    -o "$PROGRAM_NAME.o"
    
echo "Loading program..."
$SUDO ip link set dev "$INGRESS_IF_NAME" xdpgeneric obj "$PROGRAM_NAME.o" sec xdp

