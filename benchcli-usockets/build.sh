#!/usr/bin/env bash
# Builds benchcli-usockets to $1 (default ../output/bin/bench.client), on the
# uSockets and BoringSSL frameworks/usockets/deps.sh pins - the same sources
# the usockets server builds from. Needs git, cmake and a C11/C++17 compiler.
set -euo pipefail
cd "$(dirname "$0")"
. ../frameworks/usockets/deps.sh
usockets_deps

# uSockets' own TLS layer is not used - see main.cpp - so its sockets are
# built plain.
build_dir=${BENCHCLI_USOCKETS_BUILD_DIR:-"$USOCKETS_DEPS/build-client"}
usockets_objects "$build_dir" -DLIBUS_NO_SSL

output=${1:-../output/bin/bench.client}
mkdir -p "$(dirname "$output")"
"${CXX:-c++}" -std=c++17 -O3 -DNDEBUG -Wall -Wextra -DLIBUS_NO_SSL -I"$USOCKETS_SRC" -I"$BORINGSSL_DIR/include" \
    ${CXXFLAGS:-} main.cpp "${USOCKETS_OBJECTS[@]}" \
    "$BORINGSSL_DIR/build/libssl.a" "$BORINGSSL_DIR/build/libcrypto.a" -pthread ${LDFLAGS:-} -o "$output"
