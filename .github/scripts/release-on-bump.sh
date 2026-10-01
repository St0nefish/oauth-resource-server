#!/usr/bin/env bash
# Creates the GitHub release v<x.y.z> for a master commit that changed Cargo.toml's
# [package] version. Run by ci.yml's `release-on-bump` job, after every heavy job of that
# commit's post-merge run succeeded; the published release is what starts release.yml.
#
# A release is created only when all of these hold; otherwise the script says why and
# exits 0 ("no release" is a normal outcome for almost every commit):
#   - COMMIT has a first parent (a root commit is never a release);
#   - the [package] version at COMMIT differs from its first parent's (a parent with no
#     Cargo.toml counts as different; the remaining rules then decide);
#   - the version is stable, <major>.<minor>.<patch>. A pre-release (0.4.0-rc.1) is
#     logged and skipped: those stay owner-published by hand;
#   - no tag v<version> exists on origin;
#   - v<version> would be the highest stable v* tag, so a re-run of an older bump
#     commit's CI after a newer release never creates a release below it.
# And it FAILS (exit 1), creating nothing, when:
#   - the version at COMMIT is not a semver version at all (a malformed version on
#     master is an error, not "no release");
#   - CHANGELOG.md at COMMIT has no non-empty `## [<version>]` section — release.yml's
#     `check` refuses such a release, so creating it would only leave a tag behind that
#     publishes nothing;
#   - it would create a release but has no token (outside DRY_RUN).
# The tag name is derived from the manifest, so it cannot disagree with it.
#
# No `repository`-field guard (the template this is adapted from has one, to skip an
# uninitialised template copy): this repository is not a template, and ci.yml runs the
# job only when `github.repository` is this repository, which keeps a fork's own CI from
# trying to release.
#
# The release is created with `gh release create` at COMMIT's full sha: not a draft, not
# a prerelease, placeholder notes (release.yml's `release-notes` replaces them with the
# CHANGELOG section once the crate is on crates.io). GH_TOKEN must be a GitHub App
# installation token (the auto-merge App, contents: write), never GITHUB_TOKEN: GitHub
# starts no workflow run for a release GITHUB_TOKEN creates, and the `v*` tag ruleset
# refuses it the tag. The App is a bypass actor on that ruleset and in release.yml's
# RELEASE_SENDERS.
#
# Inputs (env):
#   COMMIT              full sha of the commit to release; its first parent must be
#                       present (fetch-depth: 2) and `origin` readable (`git ls-remote`)
#   GH_TOKEN            the App token (not needed with DRY_RUN=1)
#   GITHUB_REPOSITORY   owner/repo
#   DRY_RUN             1 -> run every check, then print the command instead of running it
set -euo pipefail
shopt -s inherit_errexit

: "${COMMIT:?COMMIT is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
GH_TOKEN="${GH_TOKEN:-}"
DRY_RUN="${DRY_RUN:-}"
here=$(dirname "$0")

# The `version` key of the `[package]` table of a Cargo.toml on stdin; nothing if absent.
# The same parse release.yml's `check` uses.
pkg_version() {
  awk '
    /^\[/ { in_package = ($0 == "[package]") }
    in_package && /^version *=/ { sub(/^version *= *"/, ""); sub(/".*$/, ""); print; exit }
  '
}

if [[ ! "${COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::COMMIT '${COMMIT}' is not a full commit sha."
  exit 1
fi

version=$(git show "${COMMIT}:Cargo.toml" | pkg_version)
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "::error::The [package] version '${version}' at ${COMMIT} is not <major>.<minor>.<patch>[-pre]."
  exit 1
fi
tag="v${version}"

if ! parent=$(git rev-parse --verify --quiet "${COMMIT}^1"); then
  echo "${COMMIT} has no parent (a root commit); no release."
  exit 0
fi
parent_version=""
if parent_manifest=$(git show "${parent}:Cargo.toml" 2>/dev/null); then
  parent_version=$(pkg_version <<<"${parent_manifest}")
fi
if [[ -n "${parent_version}" && "${parent_version}" == "${version}" ]]; then
  echo "Version ${version} is unchanged from the parent commit ${parent}; no release."
  exit 0
fi
echo "Version at ${COMMIT}: ${version} (parent ${parent}: ${parent_version:-none})."

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "::notice::${version} is a pre-release; release-on-bump creates stable releases only. The owner publishes a pre-release by hand: gh release create ${tag} --target ${COMMIT} --title ${tag} --prerelease --generate-notes"
  exit 0
fi

# Every tag, unpaginated; a failed listing fails the job rather than guessing.
refs=$(git ls-remote --tags --refs origin 'refs/tags/v*')
if grep -qE "[[:space:]]refs/tags/${tag//./\\.}\$" <<<"${refs}"; then
  echo "${tag} already exists; no release."
  exit 0
fi
highest=$({
  printf '%s\n' "${refs}"
  printf '%s\n' "${tag}"
} | "${here}/highest-release-tag.sh")
if [[ "${highest}" != "${tag}" ]]; then
  echo "::notice::${tag} is below the highest stable release ${highest}; no release."
  exit 0
fi

# release.yml's `check` refuses a release without this section; fail here instead of
# creating a release (and a tag) that can never publish.
changelog=$(mktemp)
trap 'rm -f "${changelog}"' EXIT
if ! git show "${COMMIT}:CHANGELOG.md" >"${changelog}"; then
  echo "::error::${COMMIT} has no CHANGELOG.md; not creating ${tag}."
  exit 1
fi
if ! "${here}/changelog-section.sh" "${version}" "${changelog}" >/dev/null 2>&1; then
  echo "::error::CHANGELOG.md at ${COMMIT} has no non-empty '## [${version}]' section, so release.yml's check would refuse ${tag}; not creating it. Merge a fix that adds the '## [${version}]' section (a commit whose version is unchanged releases nothing), then create the release by hand at the commit that has it."
  exit 1
fi

cmd=(gh release create "${tag}" --repo "${GITHUB_REPOSITORY}" --target "${COMMIT}" --title "${tag}" --generate-notes)
if [[ "${DRY_RUN}" == "1" ]]; then
  echo "Dry run: every check passed; would run: ${cmd[*]}"
  exit 0
fi
if [[ -z "${GH_TOKEN}" ]]; then
  echo "::error::${COMMIT} bumps the version to ${version}, but no App token was provided; ${tag} was not created. Fix the token (vars.APP_CLIENT_ID, secrets.APP_PRIVATE_KEY) and re-run this job, or as the owner: ${cmd[*]}"
  exit 1
fi

if ! url=$("${cmd[@]}"); then
  echo "::error::Creating release ${tag} at ${COMMIT} failed. A ruleset rejection means the App is not a bypass actor on the v* tag ruleset."
  exit 1
fi
echo "Created release ${tag} at ${COMMIT} (${url}); release.yml runs from here."
