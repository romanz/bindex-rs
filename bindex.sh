#!/bin/bash
cd `dirname $0`
set -eux
export RUST_LOG=${RUST_LOG:-info}
cargo +stable build --release --all --locked

ARGS="--db-path ./__db_sptweaks"
ulimit -n 8192
target/release/bindex-cli $ARGS $*
