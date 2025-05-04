#!/bin/sh

usage="$0 <id> // where id is the optional id of your XDP program - otherwise all will be unloaded"

if [ $# -eq 0 ]; then
    if="-a"
elif [ $# -eq 1 ]; then
    if [ $1 == "-h" -o $1 == "--help" ]; then
        echo "${usage}"
        exit 0
    else
        if="-i $1"
    fi
else
    echo "${usage}"
    exit 1
fi

xdp-loader unload eth0 $if
