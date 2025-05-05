#!/bin/sh

# copy our program build in https://github.com/ftschirpke/xdp-tutorial
# to scripts directory for debugging

cd $(dirname $0)
cp ../../xdp-tutorial/bc-pqp/xdp_prog_kern.o .
