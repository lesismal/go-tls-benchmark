#!/bin/bash

. ./script/env.sh

framework=$1
shift

echo "run ${framework} server on cpu ${server_cpu_list:-unbound}"
# -f first: it is what makes the server binary this variant of it.
nohup $limit_cpu_server "./output/bin/${framework}.server" -f="${framework}" "$@" \
    >"./output/log/${preffix}${framework}${suffix}.log" 2>&1 &
