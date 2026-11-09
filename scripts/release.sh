#!/usr/bin/env bash

set -euo pipefail

offline=0
if [[ "${1:-}" == "--offline" ]]; then
  offline=1
  shift
fi

if [[ "$#" -ne 1 ]]; then
  echo "Usage: scripts/release.sh [--offline] <LEVEL|VERSION>" >&2
  exit 2
fi

release_target="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${workspace_root}"

for command in cargo git git-cliff; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Required command not found: ${command}" >&2
    exit 1
  fi
done
if ! cargo release --version >/dev/null 2>&1; then
  echo "cargo-release is required; install it with 'cargo install cargo-release'." >&2
  exit 1
fi

workspace_version() {
  local package_id
  package_id="$(cargo pkgid --offline --package boring-sys)"
  package_id="${package_id##*#}"
  printf '%s\n' "${package_id##*@}"
}

current_branch="$(git symbolic-ref --quiet --short HEAD)"
if [[ "${current_branch}" != "master" ]]; then
  echo "Run this script from master, not ${current_branch}." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1)" ]]; then
  echo "The worktree must be clean before preparing a release." >&2
  exit 1
fi

if ! previous_version="$(workspace_version)" || [[ -z "${previous_version}" ]]; then
  echo "Could not read the current workspace version." >&2
  exit 1
fi
previous_tag="v${previous_version}"

base_commit="$(git rev-parse HEAD)"
repository_url=""
if (( ! offline )); then
  repository_url="$(sed -n '/^\[workspace\.package\]$/,/^\[/ {
    s/^repository = "\([^"]*\)"$/\1/p
  }' Cargo.toml)"
  if [[ -z "${repository_url}" ]]; then
    echo "Could not read the canonical repository URL from Cargo.toml." >&2
    exit 1
  fi
  if ! git fetch --no-tags "${repository_url}" refs/heads/master; then
    echo "Could not fetch canonical master from ${repository_url}." >&2
    exit 1
  fi
  base_commit="$(git rev-parse FETCH_HEAD)"
  if [[ "$(git rev-parse HEAD)" != "${base_commit}" ]]; then
    echo "Local master must match canonical master at ${repository_url}." >&2
    exit 1
  fi
  if ! git fetch --no-tags "${repository_url}" \
    "refs/tags/${previous_tag}:refs/tags/${previous_tag}"; then
    echo "Could not fetch previous release tag ${previous_tag} from ${repository_url}." >&2
    exit 1
  fi
fi

if ! previous_tag_commit="$(git rev-parse --verify --quiet "${previous_tag}^{commit}")"; then
  echo "Previous release tag ${previous_tag} is unavailable." >&2
  exit 1
fi
if ! git merge-base --is-ancestor "${previous_tag_commit}" "${base_commit}"; then
  echo "Previous release tag ${previous_tag} is not an ancestor of the release base." >&2
  exit 1
fi

temporary_branch="release-preparation-$$"
git switch -c "${temporary_branch}"

# Keep every Cargo invocation offline. Calling the individual cargo-release
# steps also avoids the top-level command's crates.io publication checks.
export CARGO_NET_OFFLINE=true
release_args=(
  --workspace
  --execute
  --no-confirm
  --allow-branch "${temporary_branch}"
)

if ! cargo release version "${release_target}" "${release_args[@]}" \
  || ! cargo release replace "${release_args[@]}"; then
  echo "Release preparation failed on ${temporary_branch}; inspect the worktree before retrying." >&2
  exit 1
fi

# Refresh only workspace package versions in the lockfile, using cached data.
cargo metadata --offline --format-version 1 >/dev/null
cargo metadata --locked --offline --format-version 1 >/dev/null

if ! version="$(workspace_version)" || [[ -z "${version}" ]]; then
  echo "Could not read the released workspace version." >&2
  exit 1
fi

release_branch="release/${version}"
if (( ! offline )); then
  if ! remote_refs="$(git ls-remote --refs \
    "${repository_url}" \
    "refs/heads/${release_branch}" \
    "refs/tags/v${version}")"; then
    echo "Could not check canonical release refs at ${repository_url}." >&2
    exit 1
  fi
  if grep -Fq $'\t'"refs/heads/${release_branch}" <<<"${remote_refs}"; then
    echo "Canonical branch ${release_branch} already exists." >&2
    exit 1
  fi
  if grep -Fq $'\t'"refs/tags/v${version}" <<<"${remote_refs}"; then
    echo "Canonical tag v${version} already exists." >&2
    exit 1
  fi
fi

release_range="${previous_tag}..HEAD"
if ! changes="$(git cliff --offline "${release_range}")" \
  || ! git cliff --offline --tag "v${version}" --prepend RELEASE_NOTES "${release_range}"; then
  echo "Release preparation failed on ${temporary_branch}; inspect the worktree before retrying." >&2
  exit 1
fi

if [[ -z "${changes}" ]]; then
  echo "git-cliff generated an empty release change list." >&2
  exit 1
fi

git add --update
if ! git commit -m "Release ${version}" -m "${changes}"; then
  echo "Release preparation failed on ${temporary_branch}; inspect the worktree before retrying." >&2
  exit 1
fi

git branch -m "${release_branch}"

if [[ -n "$(git status --porcelain=v1)" ]]; then
  echo "Release preparation left uncommitted changes behind." >&2
  exit 1
fi
for path in Cargo.toml Cargo.lock RELEASE_NOTES tokio-boring/README.md; do
  if ! git diff --name-only "${base_commit}..HEAD" | grep -Fxq "${path}"; then
    echo "The release commit did not update ${path}." >&2
    exit 1
  fi
done

if (( offline )); then
  preparation_summary="without network access"
else
  preparation_summary="from canonical master"
fi

cat <<EOF
Prepared ${release_branch} ${preparation_summary}. Inspect the release commit,
then publish the branch and open its PR manually:

  git push --set-upstream origin ${release_branch}
  gh pr create --base master --head ${release_branch} --title "Release ${version}" --body ""
EOF
