#!/usr/bin/env bash
# Prints the crate's name, version and release tag from Cargo.toml's [package] table,
# and the toolchain channel from rust-toolchain.toml, without needing a Rust toolchain.
#
# `canonical` is false when the run is not in the repository Cargo.toml's `repository`
# names (a fork's push runs): master.yml then proves nothing and release.yml refuses.
#
# Outputs (stdout, and $GITHUB_OUTPUT when set): crate, version, tag, rust_version,
# canonical.
set -euo pipefail

pkg_field() {
  awk -v key="$1" '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && $0 ~ "^" key " *=" { sub(/^[^=]*= *"/, ""); sub(/".*$/, ""); print; exit }
  ' Cargo.toml
}

crate=$(pkg_field name)
version=$(pkg_field version)
repository=$(pkg_field repository)
rust_version=$(sed -nE 's/^channel *= *"([^"]+)".*/\1/p' rust-toolchain.toml | head -n1)

if [[ ! "$crate" =~ ^[a-z0-9_-]+$ ]]; then
  echo "::error::could not read a valid [package] name from Cargo.toml (got '${crate}')"
  exit 1
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::error::Cargo.toml's [package] version '${version}' is not <major>.<minor>.<patch>"
  exit 1
fi
if [[ -z "$rust_version" ]]; then
  echo "::error::could not read channel from rust-toolchain.toml"
  exit 1
fi

canonical=true
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  here_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}"
  if [[ "${repository,,}" != "${here_url,,}" ]]; then
    canonical=false
    echo "::warning::Cargo.toml's repository '${repository}' is not ${here_url}: not the canonical repository; nothing is proven or published here." >&2
  fi
fi

{
  echo "crate=${crate}"
  echo "version=${version}"
  echo "tag=v${version}"
  echo "rust_version=${rust_version}"
  echo "canonical=${canonical}"
} | tee -a "${GITHUB_OUTPUT:-/dev/null}"
