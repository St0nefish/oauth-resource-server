#!/usr/bin/env bash
# Prints CHANGELOG.md's `## [<version>]` section: every line after that heading up to the
# next `## [` heading or the link-reference block at the end of the file. Fails (exit 1,
# with an `::error::`) when the section is missing or holds nothing but whitespace.
#
# The one extraction every release step uses — ci.yml's `release-on-bump` (which must
# never create a release `check` will refuse), and release.yml's `check` and
# `release-notes` — so the three cannot disagree about what counts as a section.
#
# Usage: changelog-section.sh <version> [<changelog path, default CHANGELOG.md>]
set -euo pipefail
shopt -s inherit_errexit

version=${1:?usage: changelog-section.sh <version> [CHANGELOG.md]}
file=${2:-CHANGELOG.md}

section=$(awk -v heading="## [${version}]" '
  index($0, heading) == 1 { in_section = 1; next }
  in_section && (/^## \[/ || /^\[[^]]+\]: /) { exit }
  in_section { print }
' "$file")
if ! grep -q '[^[:space:]]' <<<"$section"; then
  echo "::error::${file}'s '## [${version}]' section is missing or empty; the release notes are taken from it." >&2
  exit 1
fi
printf '%s\n' "$section"
