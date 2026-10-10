#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Publish a release that CI built: run it where the release key is.
#   website/publish-ci-release.sh v<version> [--publish]
# 1. finds the CI run of the tag and downloads its download set (every
#    platform's package, manifest.json, an unsigned SHA256SUMS) into
#    website/public/downloads, checking every file against SHA256SUMS;
# 2. signs SHA256SUMS with the release key (scripts/sign-release.sh);
# 3. uploads SHA256SUMS and SHA256SUMS.sig to the GitHub release (the
#    updater's second channel) and, with --publish, takes it out of draft;
# 4. puts the run's screenshots on the website (scripts/screenshots/update-site.sh),
#    rebuilds and deploys the site (DEPLOY_HOST, default dedibox; DEPLOY_PATH,
#    default sites/varsto/public).
# Needs gh (logged in), the release key (VARSTO_RELEASE_KEY), OpenSSL 3,
# pandoc, rsync and SSH access to the site host.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tag="${1:?usage: publish-ci-release.sh v<version> [--publish]}"
publish="${2:-}"
repo="${GITHUB_REPO:-janttsu/varsto}"
version="${tag#v}"
cv="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
[ "$cv" = "$version" ] || { echo "Cargo.toml says $cv, the tag $tag" >&2; exit 2; }
run="$(gh run list -R "$repo" --workflow CI --branch "$tag" --limit 1 --json databaseId,status,conclusion -q '.[0] | "\(.databaseId) \(.status) \(.conclusion)"')"
read -r id status conclusion <<<"$run"
[ -n "${id:-}" ] || { echo "no CI run for $tag" >&2; exit 1; }
[ "$status" = completed ] || { echo "CI run $id for $tag is $status; wait for it" >&2; exit 1; }
echo "== CI run $id ($conclusion)"
out="$root/website/public/downloads"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gh run download "$id" -R "$repo" -n downloads -D "$tmp/dl"
(cd "$tmp/dl" && sha256sum -c SHA256SUMS)
mkdir -p "$out"
# The new set replaces the previous version's files.
find "$out" -maxdepth 1 -type f \( -name 'varsto-*' -o -name 'Varsto-*' -o -name SHA256SUMS -o -name SHA256SUMS.sig -o -name manifest.json \) -delete
cp "$tmp/dl"/* "$out/"
"$root/scripts/sign-release.sh" "$out/SHA256SUMS"
"$root/scripts/sign-release.sh" --verify "$out/SHA256SUMS"
gh release upload "$tag" -R "$repo" "$out/SHA256SUMS" "$out/SHA256SUMS.sig" --clobber
if [ "$publish" = "--publish" ]; then
  gh release edit "$tag" -R "$repo" --draft=false
  echo "GitHub release $tag published"
fi
"$root/scripts/screenshots/update-site.sh" "$id" || echo "!! screenshots not updated (see above)"
DEPLOY_HOST="${DEPLOY_HOST:-dedibox}" DEPLOY_PATH="${DEPLOY_PATH:-sites/varsto/public}" "$root/website/deploy.sh" >/dev/null
echo "== published $version: https://varsto.net/downloads/"
