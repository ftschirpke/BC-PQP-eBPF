#!/bin/sh
bpftrace -e 'tracepoint:xdp:* { @cnt[probe] = count(); }'
