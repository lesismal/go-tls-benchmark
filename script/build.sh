#!/bin/bash

# Also support invoking this script directly from the repository root.
if ! declare -p frameworks >/dev/null 2>&1 || ! declare -F bench_runs_servers >/dev/null 2>&1; then
    . ./script/env.sh || { return 1 2>/dev/null || exit 1; }
fi

build_benchmark() {
    . ./script/clean.sh
    mkdir -p ./output/bin ./output/log ./output/report || return 1

    # Each half only builds what it runs.
    if bench_runs_servers; then
        # Each server once, into output/bin/base, and each framework as a
        # hard link to its server's binary under its own name: the name is
        # what killone.sh stops it by and what the client finds it by to
        # sample it, and it runs as the variant its -f names.
        mkdir -p ./output/bin/base || return 1
        local built=" " base
        for f in "${frameworks[@]}"; do
            base=$(framework_base "$f")
            if [[ "$built" != *" ${base} "* ]]; then
                echo "build ${base} ..."
                case "$base" in
                    rustls) bash ./frameworks/rustls/build.sh "$(pwd)/output/bin/base/${base}" || return 1 ;;
                    usockets) bash ./frameworks/usockets/build.sh "$(pwd)/output/bin/base/${base}" || return 1 ;;
                    *) go build -o "./output/bin/base/${base}" "./frameworks/${base}" || return 1 ;;
                esac
                echo "build ${base} done"
                echo
                built="${built}${base} "
            fi
            ln -f "./output/bin/base/${base}" "./output/bin/${f}.server" || return 1
        done
    else
        echo "skip building the servers: they run on ${BENCH_SERVER_HOST}"
        echo
    fi

    if bench_runs_clients; then
        # The Go client is also the report step, whichever client measures:
        # script/report.sh runs it as bench.report.
        echo "build report: benchcli-go ..."
        go build -o ./output/bin/bench.report ./benchcli-go || return 1
        echo "build client: ${BENCH_CLIENT} ..."
        case "$BENCH_CLIENT" in
            benchcli-go) cp ./output/bin/bench.report ./output/bin/bench.client || return 1 ;;
            benchcli-rustls) bash ./benchcli-rustls/build.sh "$(pwd)/output/bin/bench.client" || return 1 ;;
        esac
        echo "build client done"
    else
        echo "skip building the client: it runs elsewhere"
    fi
}

build_benchmark || { return 1 2>/dev/null || exit 1; }
