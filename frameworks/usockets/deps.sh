#!/usr/bin/env bash
# Sourced by frameworks/usockets/build.sh and benchcli-usockets/build.sh: the
# pinned uSockets and BoringSSL sources, cloned into USOCKETS_DEPS_DIR
# (default frameworks/usockets/.deps) on the first build and reused after,
# with BoringSSL built. Sets USOCKETS_SRC to uSockets' src directory and
# BORINGSSL_DIR to BoringSSL's tree, whose build/ holds libssl.a and
# libcrypto.a. script/Dockerfile.benchmark runs it when the image is built, so
# that a build in the container needs no network. Needs git, cmake and a C/C++
# compiler.

UWEBSOCKETS_VERSION=v20.74.0
BORINGSSL_VERSION=0.20260903.0

usockets_deps() {
    local here deps uws
    here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    deps=${USOCKETS_DEPS_DIR:-"$here/.deps"}
    uws="$deps/uWebSockets"
    BORINGSSL_DIR="$deps/boringssl"
    mkdir -p "$deps" || return 1
    if [ ! -f "$uws/uSockets/src/libusockets.h" ]; then
        rm -rf "$uws"
        git clone -q --depth 1 --branch "$UWEBSOCKETS_VERSION" https://github.com/uNetworking/uWebSockets.git "$uws" || return 1
        # Only uSockets: a recursive checkout would fetch fuzzers and TLS
        # libraries too.
        git -C "$uws" submodule update -q --init --depth 1 uSockets || return 1
    fi
    if [ ! -f "$BORINGSSL_DIR/build/libssl.a" ]; then
        if [ ! -f "$BORINGSSL_DIR/CMakeLists.txt" ]; then
            rm -rf "$BORINGSSL_DIR"
            git clone -q --depth 1 --branch "$BORINGSSL_VERSION" https://github.com/google/boringssl.git "$BORINGSSL_DIR" || return 1
        fi
        cmake -S "$BORINGSSL_DIR" -B "$BORINGSSL_DIR/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF >/dev/null || return 1
        cmake --build "$BORINGSSL_DIR/build" --target ssl crypto -j "$(getconf _NPROCESSORS_ONLN)" >/dev/null || return 1
    fi
    USOCKETS_SRC="$uws/uSockets/src"
    USOCKETS_DEPS="$deps"
}

# Compiles uSockets into $1 with the extra flags that follow, and sets
# USOCKETS_OBJECTS to the object files.
usockets_objects() {
    local out=$1 source object
    shift
    mkdir -p "$out" || return 1
    USOCKETS_OBJECTS=()
    for source in "$USOCKETS_SRC"/*.c "$USOCKETS_SRC"/eventing/*.c "$USOCKETS_SRC"/crypto/*.c "$USOCKETS_SRC"/io_uring/*.c; do
        object="$out/$(basename "${source%.c}").o"
        "${CC:-cc}" -std=c11 -O3 -DNDEBUG -I"$USOCKETS_SRC" -I"$BORINGSSL_DIR/include" "$@" ${CFLAGS:-} -c "$source" -o "$object" || return 1
        USOCKETS_OBJECTS+=("$object")
    done
    for source in "$USOCKETS_SRC"/crypto/*.cpp; do
        object="$out/$(basename "${source%.cpp}").o"
        "${CXX:-c++}" -std=c++17 -O3 -DNDEBUG -I"$USOCKETS_SRC" -I"$BORINGSSL_DIR/include" "$@" ${CXXFLAGS:-} -c "$source" -o "$object" || return 1
        USOCKETS_OBJECTS+=("$object")
    done
}
