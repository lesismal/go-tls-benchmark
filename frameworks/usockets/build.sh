#!/usr/bin/env bash
# Builds the uSockets server to $1 (default ../../output/bin/base/usockets).
#
# uSockets comes from the uWebSockets release go-websocket-benchmark pins,
# and BoringSSL from a pinned release; both are cloned into USOCKETS_DEPS_DIR
# (default .deps) on the first build and reused after, which is how
# script/Dockerfile.benchmark has them in the image so that a build in the
# container needs no network. Needs git, cmake, a C11 and a C++17 compiler.
set -euo pipefail
cd "$(dirname "$0")"

UWEBSOCKETS_VERSION=v20.74.0
BORINGSSL_VERSION=0.20260903.0

deps=${USOCKETS_DEPS_DIR:-"$PWD/.deps"}
uws="$deps/uWebSockets"
boringssl="$deps/boringssl"
mkdir -p "$deps"
if [ ! -f "$uws/uSockets/src/libusockets.h" ]; then
    rm -rf "$uws"
    git clone -q --depth 1 --branch "$UWEBSOCKETS_VERSION" https://github.com/uNetworking/uWebSockets.git "$uws"
    # Only uSockets: a recursive checkout would fetch fuzzers and TLS
    # libraries too.
    git -C "$uws" submodule update -q --init --depth 1 uSockets
fi
if [ ! -f "$boringssl/build/libssl.a" ]; then
    if [ ! -f "$boringssl/CMakeLists.txt" ]; then
        rm -rf "$boringssl"
        git clone -q --depth 1 --branch "$BORINGSSL_VERSION" https://github.com/google/boringssl.git "$boringssl"
    fi
    cmake -S "$boringssl" -B "$boringssl/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF >/dev/null
    cmake --build "$boringssl/build" --target ssl crypto -j "$(getconf _NPROCESSORS_ONLN)" >/dev/null
fi

usockets="$uws/uSockets/src"
build_dir=${USOCKETS_BUILD_DIR:-"$deps/build"}
mkdir -p "$build_dir"
cflags=(-O3 -DNDEBUG -DLIBUS_USE_OPENSSL -I"$usockets" -I"$boringssl/include")
objects=()
for source in "$usockets"/*.c "$usockets"/eventing/*.c "$usockets"/crypto/*.c "$usockets"/io_uring/*.c; do
    object="$build_dir/$(basename "${source%.c}").o"
    "${CC:-cc}" -std=c11 "${cflags[@]}" ${CFLAGS:-} -c "$source" -o "$object"
    objects+=("$object")
done
for source in "$usockets"/crypto/*.cpp; do
    object="$build_dir/$(basename "${source%.cpp}").o"
    "${CXX:-c++}" -std=c++17 "${cflags[@]}" ${CXXFLAGS:-} -c "$source" -o "$object"
    objects+=("$object")
done

output=${1:-../../output/bin/base/usockets}
mkdir -p "$(dirname "$output")"
"${CC:-cc}" -std=c11 -Wall -Wextra "${cflags[@]}" ${CFLAGS:-} -c server.c -o "$build_dir/server.o"
"${CXX:-c++}" "$build_dir/server.o" "${objects[@]}" \
    "$boringssl/build/libssl.a" "$boringssl/build/libcrypto.a" -pthread ${LDFLAGS:-} -o "$output"
