#!/bin/bash

# Benchmark client: benchcli-usockets (default), on uSockets and BoringSSL,
# benchcli-rustls, on rustls and tokio, or benchcli-go, on crypto/tls. All
# three run the same three benchmarks with the same flags and write the same
# JSON report files; the report step turns them into tables with the Go client
# whichever measured.
#
# benchcli-usockets is the default because it is the one that holds a server
# back least: given fewer CPUs than the server, so that the client is the
# bottleneck, it reaches on average 94% of the best of the three across every
# framework and phase, against 88% for benchcli-rustls and 75% for
# benchcli-go, and with the runner's own split it is within 1% of the best on
# more rows than either. See "Clients" in the README for the measurements.
#
# rustls does not implement TLS 1.1, so under benchcli-rustls the *-tls11
# frameworks are measured by benchcli-go (script/client.sh); the other two
# measure every framework. benchcli-usockets needs git, cmake and a C/C++
# compiler, as the usockets server does; benchcli-rustls needs cargo.
# Override for one run with: BENCH_CLIENT=benchcli-go bash script/benchmark.sh
BENCH_CLIENT=${BENCH_CLIENT:-benchcli-usockets}
case "$BENCH_CLIENT" in
    benchcli-go|benchcli-rustls|benchcli-usockets) ;;
    *) echo "Unsupported BENCH_CLIENT: $BENCH_CLIENT (want benchcli-go, benchcli-rustls or benchcli-usockets)" >&2; return 1 ;;
esac

# Where the servers are, as the clients should reach them: an address or a
# hostname, IPv6 included. The default keeps a single-node run on loopback.
# The servers always bind every interface, so a two-node run configures only
# this side.
# Override for one run with: BENCH_SERVER_HOST=10.0.0.2 bash script/benchmark.sh
BENCH_SERVER_HOST=${BENCH_SERVER_HOST:-127.0.0.1}

# Which half of the benchmark this machine runs:
#
#   both    (default) build everything, start the servers, run the clients
#           against them and write the report - one machine
#   server  build and start the servers, then leave them running. Nothing is
#           measured here; the client node does that
#   client  build the client only, run it against BENCH_SERVER_HOST and write
#           the report. Nothing is started or stopped here
#
# A two-node run is BENCH_ROLE=server on one machine and, once it reports the
# servers are up, BENCH_ROLE=client BENCH_SERVER_HOST=<that machine> on the
# other. "client" against a loopback host is also the way to run the clients
# again without restarting servers that are already up on this machine.
#
# Two things differ from a single-node run. The client cannot stop a server it
# did not start, so every framework's server stays up for the whole run rather
# than being started right before its turn and stopped right after it, as on
# one node: stop them on the server node afterwards
# with script/killall.sh, and use BENCH_FRAMEWORKS below if the idle ones
# holding memory would disturb the framework being measured. And each node
# gives the whole machine to its own half, since there is no longer anything
# to divide it with; BENCH_SERVER_CPU_LIST and BENCH_CLIENT_CPU_LIST still
# pin it where a node shares its CPUs with something else.
BENCH_ROLE=${BENCH_ROLE:-both}
case "$BENCH_ROLE" in
    both|server|client) ;;
    *) echo "Unsupported BENCH_ROLE: $BENCH_ROLE (want both, server or client)" >&2; return 1 ;;
esac

# The order the report tables put their rows in. Both orders carry the same
# rows and the same numbers; only the order differs:
#
#   result     (default) best first, ranked by the number each benchmark
#              answers with: TPS in all three - full handshakes per second in
#              Connections, round trips in BenchEcho, and in BenchPipeline the
#              echoes the clients read back off the server per second - with
#              CPU EER, then MEM EER, breaking a tie. The rate test pipelines
#              messages at a rate the clients set rather than to completion,
#              so what came back under that load is its result there the way
#              TPS is in the other two; Msg Sent is the load rather than the
#              answer
#   framework  the order FrameworkList in config/config.go lists them in,
#              which is by framework name. It is what puts a framework on the
#              same row in every table and across runs, whatever it scored, so
#              two reports can be diffed. Only the Go list reaches a report;
#              the frameworks array below decides what is built and run, and is
#              kept in the same order so that the two read alike
#
# In either order every ranked column - TPS, CPU EER and MEM EER - shows each
# row's share of the best in that column after it, the best being 100%, and
# carries [↓1], [↓2] or [↓3] after its title for which key it is. Rows that tie keep the
# framework order between them, so two frameworks that scored the same - or a
# whole table from a benchmark that did not run, which leaves every row at
# zero - come out the same way on every run.
#
# Override for one run with: BENCH_REPORT_SORT=framework bash script/benchmark.sh
# or, without re-running the benchmark, by passing the client flag straight to
# the report step: bash script/report.sh -sort=framework
BENCH_REPORT_SORT=${BENCH_REPORT_SORT:-result}
case "$BENCH_REPORT_SORT" in
    result|framework) ;;
    *) echo "Unsupported BENCH_REPORT_SORT: $BENCH_REPORT_SORT (want result or framework)" >&2; return 1 ;;
esac

# fib only: the calls its server reads and writes its sockets with, which is
# fib.Config.SocketSyscalls:
#
#   true   (default, as in fib) recvfrom, sendto and sendmsg
#   false  read, write and writev, which reach the same socket code through
#          the VFS, and with it the security module's file permission hook on
#          every call (AppArmor's, in a Docker container)
#
# Linux only: elsewhere fib ignores it.
# script/server.sh gives it to the fib server as -socketsyscalls,
# and to no other, which would exit on a flag it does not define. Exported,
# since script/server.sh runs as a process of its own.
#
# Override for one run with: BENCH_FIB_SOCKET_SYSCALLS=false bash script/benchmark.sh
# or with the drivers' own flag, which they take out of their arguments before
# the clients see them: bash script/benchmark.sh -socketsyscalls=false
BENCH_FIB_SOCKET_SYSCALLS=${BENCH_FIB_SOCKET_SYSCALLS:-true}
case "$BENCH_FIB_SOCKET_SYSCALLS" in
    true|false) ;;
    *) echo "Unsupported BENCH_FIB_SOCKET_SYSCALLS: $BENCH_FIB_SOCKET_SYSCALLS (want true or false)" >&2; return 1 ;;
esac
export BENCH_FIB_SOCKET_SYSCALLS

# The matrix script/benchmarkN.sh runs every framework through.
Connections=(5000 50000)
BodySize=(1024 4096)
BenchTime=(2000000)
# Seconds between two runs, once the last one's server has exited: none after
# the last run. A server is up when it listens on all its ports, and its client
# starts one second after that.
SleepTime=5

# Which frameworks a run measures, and the order the servers are started and
# the clients run in. A framework is a server pinned to one TLS version,
# "<server>-tls<version>", with its own ports: config.Variants in
# config/config.go, in whose order this list is kept.
#
#   fib     github.com/lesismal/fib: its event loop, with fib/tls running
#           crypto/tls in front of an echo handler
#   rustls  rustls on tokio (tokio-rustls, aws-lc-rs), a task per connection;
#           building it needs cargo (see frameworks/rustls/build.sh). TLS 1.2
#           and 1.3 only: rustls does not implement 1.1
#   stdtls  the standard library: crypto/tls over net, a goroutine per
#           connection
#   usockets  uSockets (under uWebSockets and Bun) with BoringSSL, in C: an
#           event loop per CPU; building it needs git, cmake and a C/C++
#           compiler (see frameworks/usockets/build.sh)
frameworks=(
    "fib-tls11"
    "fib-tls12"
    "fib-tls13"
    "rustls-tls12"
    "rustls-tls13"
    "stdtls-tls11"
    "stdtls-tls12"
    "stdtls-tls13"
    "usockets-tls11"
    "usockets-tls12"
    "usockets-tls13"
)

# The server a framework is a variant of, whose binary it runs: "fib" for
# "fib-tls13".
framework_base() {
    printf '%s' "${1%-tls*}"
}

# The TLS version a framework is pinned to, "1.3" for "fib-tls13".
framework_version() {
    local v=${1##*-tls}
    printf '%s.%s' "${v:0:1}" "${v:1}"
}

# Optional comma-separated subset, used by the Docker smoke test and useful for
# focused local runs: frameworks by name, "fib-tls13", or servers, "fib" for
# every variant of it. Unknown names are rejected before they reach build
# paths.
if [ -n "${BENCH_FRAMEWORKS:-}" ]; then
    all_frameworks=("${frameworks[@]}")
    IFS=',' read -r -a requested_frameworks <<< "$BENCH_FRAMEWORKS"
    frameworks=()
    for requested_framework in "${requested_frameworks[@]}"; do
        framework_found=false
        for available_framework in "${all_frameworks[@]}"; do
            if [ "$requested_framework" = "$available_framework" ] ||
                [ "$requested_framework" = "$(framework_base "$available_framework")" ]; then
                framework_found=true
                frameworks+=("$available_framework")
            fi
        done
        if [ "$framework_found" != true ]; then
            echo "Unsupported framework in BENCH_FRAMEWORKS: $requested_framework" >&2
            return 1
        fi
    done
fi

# Optional comma-separated TLS versions, "1.2,1.3" (or "12,13"), narrowing the
# frameworks to the ones pinned to those.
if [ -n "${BENCH_TLS_VERSIONS:-}" ]; then
    IFS=',' read -r -a requested_versions <<< "$BENCH_TLS_VERSIONS"
    selected_frameworks=()
    for f in "${frameworks[@]}"; do
        for requested_version in "${requested_versions[@]}"; do
            requested_version=${requested_version#tls}
            case "$requested_version" in
                1.1|11|1.2|12|1.3|13) ;;
                *) echo "Unsupported version in BENCH_TLS_VERSIONS: $requested_version (want 1.1, 1.2 or 1.3)" >&2; return 1 ;;
            esac
            if [ "${requested_version/./}" = "${f##*-tls}" ]; then
                selected_frameworks+=("$f")
            fi
        done
    done
    frameworks=("${selected_frameworks[@]}")
fi

if [ "${#frameworks[@]}" -eq 0 ]; then
    echo "BENCH_FRAMEWORKS and BENCH_TLS_VERSIONS must leave at least one framework" >&2
    return 1
fi

# The first and last benchmark port of framework $1, "12001 12050", read from
# config.Variants in config/config.go rather than copied here.
# TestScriptServerPorts holds this to config.Ports. Here, with
# server_port_range below, rather than in env.sh: docker_benchmark.sh reads
# only this file.
server_ports() {
    sed -n "s/^[[:space:]]*{\"$1\",[^\"]*\"\([0-9]*\):\([0-9]*\)\"},[[:space:]]*\$/\1 \2/p" ./config/config.go | head -n 1
}

# Every port a server listens on, of every framework in config.Variants - its
# benchmark ports and the control port after them - as the one range
# "12001-12751" that covers them all.
#
# A single-node run starts each server only for its own turn, after other
# frameworks' clients have already dialed tens of thousands of connections.
# With an ephemeral port range that takes these in, as the "1024 65535" the
# README and docker_benchmark.sh set does, those connections' local ports -
# and the TIME_WAIT sockets they leave for a minute after them - sit on ports
# a later server needs, and it exits with "address already in use". Reserving
# the range, with net.ipv4.ip_local_reserved_ports, keeps the kernel from
# handing them out as ephemeral ports.
server_port_range() {
    sed -n '/^var Variants = \[\]Variant{/,/^}/p' ./config/config.go |
        sed -n 's/^[[:space:]]*{"[^"]*",[^"]*"\([0-9]*\):\([0-9]*\)"},[[:space:]]*$/\1 \2/p' |
        awk 'NR == 1 || $1 < min { min = $1 } NR == 1 || $2 > max { max = $2 } END { if (NR) print min "-" max + 1 }'
}

# The flags the servers define, out of a command line that is the client's:
# script/benchmark.sh and the rest take one command line for both, and pass a
# server only what it defines, since anything else would stop it with "flag
# provided but not defined". -key reaches the servers only, and the client
# reports the key it was served. The TLS version is not a flag: it is the
# framework's, e.g. fib-tls13's, which both sides read from its name.
server_flags_of() {
    local arg flags=""
    for arg in "$@"; do
        case "$arg" in
            -nodelay=*|-reuseport=*|-b=*|-m=*|-key=*) flags="${flags} ${arg}" ;;
        esac
    done
    printf '%s' "$flags"
}
