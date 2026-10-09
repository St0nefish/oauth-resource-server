#!/usr/bin/env bash
# Prints `true` when the change from <from> to <to> touches a code path, `false` when it
# does not. The ONE definition of "code path": ci-fast.yml (whether to run the cargo
# checks), slow.yml (whether to run the slow tier) and master.yml (whether a merge needs
# its own test proof) all call it.
#
# Code paths — anything compiled into, tested against, or checking the crate:
#   src/**  tests/**  examples/**  Cargo.toml  Cargo.lock  rust-toolchain.toml
#   deny.toml  .cargo/**  README.md  .github/workflows/**  .github/scripts/**
# README.md is the crate-level rustdoc (`src/lib.rs` include_str!s it), so its examples
# are doctests. No other Markdown file counts. fuzz/ is not built by these checks
# (fuzz.yml runs it after a merge), so it is not a code path here.
#
# One exception: a Cargo.toml / Cargo.lock change that ONLY moves this crate's own
# version (the [package] version and Cargo.lock's own entry — the post-release roll PR, a
# hand-made minor/major bump) is not a code change: it lands with no build, and the next
# code change builds with the new version compiled in.
#
# Usage: code-paths.sh <from> <to>   (commit-ishes present in the local clone)
set -euo pipefail
shopt -s inherit_errexit

from=${1:?usage: code-paths.sh <from> <to>}
to=${2:?usage: code-paths.sh <from> <to>}

code_re='^(src/|tests/|examples/|\.cargo/|\.github/workflows/|\.github/scripts/)|^(Cargo\.toml|Cargo\.lock|rust-toolchain\.toml|deny\.toml|README\.md)$'

show() { git show "${1}:${2}" 2>/dev/null || true; }

crate=$(show "$to" Cargo.toml | awk '
  /^\[/ { in_package = ($0 == "[package]") }
  in_package && /^name *=/ { sub(/^name *= *"/, ""); sub(/".*$/, ""); print; exit }
')

# Cargo.toml with the [package] version value blanked.
normalize_manifest() {
  awk '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version *=/ { print "version = \"<own version>\""; next }
    { print }
  '
}

# Cargo.lock with this crate's own version blanked (the line after its name line).
normalize_lock() {
  awk -v crate="$crate" '
    own && /^version = / { print "version = \"<own version>\""; own = 0; next }
    { own = ($0 == "name = \"" crate "\""); print }
  '
}

version_only() {
  local path=$1 norm=$2
  [[ "$(show "$from" "$path" | "$norm")" == "$(show "$to" "$path" | "$norm")" ]]
}

changed=$(git diff --no-renames --name-only "$from" "$to")
code=false
while IFS= read -r path; do
  [[ -n "$path" && (! "$path" =~ \.md$ || "$path" == README.md) && "$path" =~ $code_re ]] || continue
  case "$path" in
    Cargo.toml) version_only Cargo.toml normalize_manifest && continue ;;
    Cargo.lock) version_only Cargo.lock normalize_lock && continue ;;
  esac
  echo "code path changed: ${path}" >&2
  code=true
  break
done <<<"$changed"

echo "$code"
