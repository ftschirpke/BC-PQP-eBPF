#!/usr/bin/env bash

# === Konfiguration: ===

# TODO

INGRESS_IF_NAME="eno1"

SUDO="sudo" # leave empty if sudo not required

# =====================

$SUDO ip link set "$INGRESS_IF_NAME" xdpgeneric off

