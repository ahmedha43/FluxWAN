#!/bin/sh
strace -f -o /tmp/pppd_strace.log pppd file /tmp/fluxwan_ppp0.opts &
PID=$!
sleep 4
kill $PID 2>/dev/null || true
tail -30 /tmp/pppd_strace.log
