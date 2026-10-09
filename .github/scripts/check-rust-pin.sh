#!/usr/bin/env bash
# Fails if any tracked file other than rust-toolchain.toml hard-codes the project's Rust
# version. rust-toolchain.toml's `channel` is the only place it appears: the workflows read
# it and install exactly that toolchain. (Cargo.toml's `rust-version` is the MSRV, kept in
# lockstep with it by hand. The toolchain cargo-semver-checks needs is a tool requirement,
# not the project's toolchain: checks.yml names it once, in SEMVER_TOOLCHAIN.)
# Usage: check-rust-pin.sh   (from the repo root)
set -euo pipefail

# rust:1.x image tags, dtolnay/rust-toolchain@1.x, RUST_VERSION=1.x defaults, and a
# `toolchain: 1.x` action input.
pattern='rust:1\.[0-9]|rust-toolchain@1\.[0-9]|RUST_VERSION[:=] *"?1\.[0-9]|toolchain: *"?1\.[0-9]'

hits=$(git ls-files -z | grep -zv '^rust-toolchain\.toml$' | xargs -0 grep -nE "$pattern" -- || true)
if [[ -n "$hits" ]]; then
  echo "::error::a Rust version is hard-coded outside rust-toolchain.toml:"
  echo "$hits"
  exit 1
fi
echo "ok: the Rust version appears only in rust-toolchain.toml"
