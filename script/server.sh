#!/bin/bash

. ./script/env.sh

framework=$1
shift

# fib alone takes this flag; see BENCH_FIB_SOCKET_SYSCALLS in script/config.sh.
case "$framework" in
    fib|fib-tls*) set -- "-socketsyscalls=${BENCH_FIB_SOCKET_SYSCALLS}" "$@" ;;
esac

echo "run ${framework} server on cpu ${server_cpu_list:-unbound}"
# -f first: it is what makes the server binary this variant of it.
nohup $limit_cpu_server "./output/bin/${framework}.server" -f="${framework}" "$@" \
    >"./output/log/${preffix}${framework}${suffix}.log" 2>&1 &
