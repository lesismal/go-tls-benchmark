#!/usr/bin/env bash
# Builds the uSockets server to $1 (default ../../output/bin/base/usockets),
# on the uSockets and BoringSSL deps.sh pins.
set -euo pipefail
cd "$(dirname "$0")"
. ./deps.sh
usockets_deps

build_dir=${USOCKETS_BUILD_DIR:-"$USOCKETS_DEPS/build-server"}
usockets_objects "$build_dir" -DLIBUS_USE_OPENSSL

output=${1:-../../output/bin/base/usockets}
mkdir -p "$(dirname "$output")"
"${CC:-cc}" -std=c11 -O3 -DNDEBUG -Wall -Wextra -DLIBUS_USE_OPENSSL -I"$USOCKETS_SRC" -I"$BORINGSSL_DIR/include" \
    ${CFLAGS:-} -c server.c -o "$build_dir/server.o"
"${CXX:-c++}" "$build_dir/server.o" "${USOCKETS_OBJECTS[@]}" \
    "$BORINGSSL_DIR/build/libssl.a" "$BORINGSSL_DIR/build/libcrypto.a" -pthread ${LDFLAGS:-} -o "$output"
