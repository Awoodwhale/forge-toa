#!/bin/sh
cargo xtask build-ebpf --release && \
cargo build --release