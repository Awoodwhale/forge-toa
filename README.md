# faketoa

## Introduce

An eBPF program using [aya-rs/aya](https://github.com/aya-rs/aya) that can forge socket toa

## Prerequisites

1. `rustup toolchain install nightly --component rust-src`
2. `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
