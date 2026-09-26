#!/usr/bin/env bash
# Builds the rustls server to $1 (default ../../output/bin/base/rustls).
#
# Needs cargo 1.85 or newer on PATH; the dependencies are pinned by Cargo.lock
# (--locked). The first build downloads them from crates.io; set
# CARGO_NET_OFFLINE=true to build from what is already in CARGO_HOME, which is
# how script/Dockerfile.benchmark builds it. CARGO_TARGET_DIR, when set, is
# where the build keeps its objects.
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v cargo >/dev/null 2>&1; then
    echo "rustls: cargo not found; install a Rust toolchain (https://rustup.rs), 1.85 or newer" >&2
    exit 1
fi
cargo build --release --locked
target_dir=${CARGO_TARGET_DIR:-"$PWD/target"}
output=${1:-../../output/bin/base/rustls}
mkdir -p "$(dirname "$output")"
cp "$target_dir/release/rustls_server" "$output"
