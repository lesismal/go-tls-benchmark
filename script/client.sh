#!/bin/bash

. ./script/env.sh || { return 1 2>/dev/null || exit 1; }

# The client BENCH_CLIENT built, bench.client - but for a framework pinned to
# TLS 1.1 under benchcli-rustls, which rustls does not implement: that one
# goes to benchcli-go, which script/build.sh always builds, as bench.report.
client_bin=./output/bin/bench.client
if [ "$BENCH_CLIENT" = benchcli-rustls ]; then
    for arg in "$@"; do
        case "$arg" in
            -f=*-tls11)
                echo "${arg#-f=}: rustls does not implement TLS 1.1, measured with benchcli-go"
                client_bin=./output/bin/bench.report
                ;;
        esac
    done
fi

$limit_cpu_client "$client_bin" "$@"
