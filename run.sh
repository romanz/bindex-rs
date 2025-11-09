#!/bin/bash
cd `dirname $0`
set -eux
export RUST_LOG=${RUST_LOG:-info}
cargo +stable build --release --all --locked

ARGS="--db-path ./db"
target/release/bindex-cli $ARGS $*
