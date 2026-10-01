#!/bin/bash

# A million TLS connections per framework. Needs the system settings in
# the README's "before running the test", on both nodes of a two-node run.

# -socketsyscalls[=BOOL] is the drivers' own flag, for BENCH_FIB_SOCKET_SYSCALLS
# in script/config.sh: taken out here, before env.sh checks the value, so that
# neither the clients nor the report step is handed a flag it does not define.
driver_args=()
for arg in "$@"; do
    case "$arg" in
        -socketsyscalls|--socketsyscalls) BENCH_FIB_SOCKET_SYSCALLS=true ;;
        -socketsyscalls=*|--socketsyscalls=*) BENCH_FIB_SOCKET_SYSCALLS=${arg#*=} ;;
        *) driver_args+=("$arg") ;;
    esac
done
set -- ${driver_args[@]+"${driver_args[@]}"}

. ./script/env.sh || { return 1 2>/dev/null || exit 1; }

echo $line

. ./script/killall.sh

echo $line

. ./script/clean.sh

echo $line

# The subset this script measures, in framework-name order like every other
# framework list; see script/config.sh. BENCH_FRAMEWORKS narrows it the same
# way it narrows the full list.
if [ -z "${BENCH_FRAMEWORKS:-}" ]; then
    frameworks=(
        "fib-tls13"
        "rustls-tls13"
        "stdtls-tls13"
        "usockets-tls13"
    )
fi

print_env

echo $line

. ./script/build.sh || { return 1 2>/dev/null || exit 1; }

echo $line

# The servers and the benchmark client take different flags, and this script
# takes the client's. Forward only what a server actually defines.
server_flags=$(server_flags_of "$@")

# A server node starts every server now and leaves them up for the client
# node. On a single node, clients.sh starts each one for its own turn only.
if bench_runs_servers && ! bench_owns_servers; then
    . ./script/servers.sh

    echo $line
fi

if ! bench_runs_clients; then
    echo "servers are up and left running. On the client node:"
    echo "  BENCH_ROLE=client BENCH_SERVER_HOST=<this host> bash script/1m_conns_benchmark.sh"
    echo "Stop them here afterwards with: bash script/killall.sh"
    echo $line
    return 0 2>/dev/null || exit 0
fi

. ./script/clients.sh -c=1000000 -en=2000000 -b=1024 -rr=1 -preffix=1m_connections_ "$@" || { return 1 2>/dev/null || exit 1; }

# The report step reads BENCH_REPORT_SORT for the row order of its tables; see
# script/config.sh.
. ./script/report.sh -preffix=1m_connections_ "$@"

echo $line
