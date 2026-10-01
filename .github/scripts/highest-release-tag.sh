#!/usr/bin/env bash
# Prints the highest stable release tag, v<x.y.z> with no pre-release suffix, compared as
# versions (so v0.10.0 > v0.9.0).
#
# Input (stdin): tag names or refs, one per line — `refs/tags/` prefixes, `git ls-remote`
#   columns and `^{}` peel lines are accepted. Every line is read; nothing is paginated.
# Output: the tag; nothing (and exit 1) when there is none, so a caller fails closed or
#   handles "no release yet" explicitly.
#
# Usage:
#   git ls-remote --tags --refs origin 'refs/tags/v*' | highest-release-tag.sh
set -euo pipefail
shopt -s inherit_errexit

if (($# > 0)); then
  echo "usage: highest-release-tag.sh < tags" >&2
  exit 2
fi

result=$(sed -E 's/^[0-9a-f]+[[:space:]]+//; s#^refs/tags/##' |
  { grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true; } |
  sort -u -t. -k1.2,1n -k2,2n -k3,3n |
  tail -n 1)
if [[ -z "$result" ]]; then
  exit 1
fi
printf '%s\n' "$result"
