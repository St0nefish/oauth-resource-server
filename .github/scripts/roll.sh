#!/usr/bin/env bash
# Opens and arms the roll PR after release <released> shipped: master's version moves
# to the next patch, so it again names the NEXT release. Run by release.yml's `roll` job
# in a checkout of master whose persisted token is the GitHub App's, with GH_TOKEN the
# same App token — the PR and the arming must be the App's, or no workflow runs on them.
#
#   - master's version is not <released> (a hand minor/major bump already moved it):
#     nothing to roll, exit 0;
#   - an open PR from release/roll-v<next> exists: reused (re-armed);
#   - otherwise `cargo release version patch` on branch release/roll-v<next> (Cargo.toml +
#     Cargo.lock), and CHANGELOG.md's `## [Unreleased]` entries are dated
#     `## [<released>] - <date>` under a fresh `## [Unreleased]`, with the link
#     references at the bottom moved along (`[Unreleased]: .../compare/v<released>...HEAD`
#     and a new `[<released>]: .../compare/<previous>...v<released>`); committed as the
#     App's bot user, pushed, PR opened and armed.
#
# A version-only PR: ci-fast lints, ci-slow passes without a build, it auto-merges. If a
# hand bump lands first, master.yml's `rolls` job closes this PR with a comment.
#
# Usage: roll.sh <released x.y.z>   Env: GH_TOKEN, APP_SLUG, GITHUB_REPOSITORY.
set -euo pipefail
shopt -s inherit_errexit

released=${1:?usage: roll.sh <released x.y.z>}
: "${GH_TOKEN:?}" "${APP_SLUG:?}" "${GITHUB_REPOSITORY:?}"
[[ "$released" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || {
  echo "::error::'${released}' is not x.y.z"
  exit 1
}
next="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"
branch="release/roll-v${next}"
title="release: roll version to ${next}"

version() {
  awk '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version *=/ { sub(/^version *= *"/, ""); sub(/".*$/, ""); print; exit }
  ' Cargo.toml
}

current=$(version)
if [[ "$current" != "$released" ]]; then
  echo "master's version is ${current}, not the released ${released}: it already moved; no roll."
  exit 0
fi

pr=$(gh pr list --repo "$GITHUB_REPOSITORY" --head "$branch" --base master --state open \
  --json number --jq '.[0].number // empty')
if [[ -n "$pr" ]]; then
  echo "#${pr} already rolls to ${next}; reusing it."
else
  if git ls-remote --exit-code --heads origin "$branch" >/dev/null; then
    echo "${branch} exists (a previous run died before opening the PR); reusing it."
  else
    git checkout --quiet -B "$branch" origin/master
    cargo release version patch --execute --no-confirm
    [[ "$(version)" == "$next" ]] || {
      echo "::error::Cargo.toml is at $(version) after the roll, expected ${next}"
      exit 1
    }
    if [[ -f CHANGELOG.md ]] && grep -qx '## \[Unreleased\]' CHANGELOG.md; then
      out=$(awk -v rel="$released" -v date="$(date -u +%F)" '
        $0 == "## [Unreleased]" { print; print ""; print "## [" rel "] - " date; next }
        { print }' CHANGELOG.md)
      printf '%s\n' "$out" >CHANGELOG.md
      # [Unreleased]: <repo>/compare/<previous>...HEAD -> compare/v<released>...HEAD, plus
      # the released version's own compare link under it.
      out=$(awk -v rel="$released" '
        match($0, /^\[Unreleased\]: .*\/compare\//) && $0 ~ /\.\.\.HEAD$/ {
          base = substr($0, 15, RLENGTH - 14)
          prev = substr($0, RLENGTH + 1); sub(/\.\.\.HEAD$/, "", prev)
          print "[Unreleased]: " base "v" rel "...HEAD"
          print "[" rel "]: " base prev "...v" rel
          next
        }
        { print }' CHANGELOG.md)
      printf '%s\n' "$out" >CHANGELOG.md
    fi
    uid=$(gh api "users/${APP_SLUG}%5Bbot%5D" --jq .id)
    git -c user.name="${APP_SLUG}[bot]" -c user.email="${uid}+${APP_SLUG}[bot]@users.noreply.github.com" \
      -c commit.gpgsign=false commit --quiet -am "$title"
    git push --quiet origin "HEAD:refs/heads/${branch}"
  fi
  body="Rolls master to the next patch version after releasing v${released}: ${released} -> ${next}. Version-only, so it runs no build. Opened by release.yml."
  url=$(gh pr create --repo "$GITHUB_REPOSITORY" --base master --head "$branch" --title "$title" --body "$body")
  pr=${url##*/}
  echo "opened #${pr}"
fi

gh pr merge "$pr" --auto --merge --repo "$GITHUB_REPOSITORY"
echo "#${pr} armed for auto-merge"
