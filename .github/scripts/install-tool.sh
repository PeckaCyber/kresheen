#!/usr/bin/env bash
# Install a pinned release binary (Linux x86_64) after verifying its SHA256, and put it on PATH for later steps.
# Usage: .github/scripts/install-tool.sh <grype|syft|cosign>
# To update a tool, change the version and the checksum together (checksum from the project's release checksums file).
set -euo pipefail

tool=${1:?usage: install-tool.sh <grype|syft|cosign>}
case "$tool" in
  grype)
    version=0.121.0
    sha256=64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519
    url="https://github.com/anchore/grype/releases/download/v${version}/grype_${version}_linux_amd64.tar.gz"
    kind=tar ;;
  syft)
    version=1.55.0
    sha256=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
    url="https://github.com/anchore/syft/releases/download/v${version}/syft_${version}_linux_amd64.tar.gz"
    kind=tar ;;
  cosign)
    version=3.1.4
    sha256=424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa
    url="https://github.com/sigstore/cosign/releases/download/v${version}/cosign-linux-amd64"
    kind=bin ;;
  *) echo "unknown tool: $tool" >&2; exit 2 ;;
esac

dest="${RUNNER_TEMP:-/tmp}/tools/bin"
work=$(mktemp -d)
mkdir -p "$dest"
curl -sSfL --retry 3 -o "$work/download" "$url"
echo "${sha256}  ${work}/download" | sha256sum -c -
if [ "$kind" = tar ]; then
  tar -xzf "$work/download" -C "$work" "$tool"
  install -m 0755 "$work/$tool" "$dest/$tool"
else
  install -m 0755 "$work/download" "$dest/$tool"
fi
rm -rf "$work"
if [ -n "${GITHUB_PATH:-}" ]; then echo "$dest" >> "$GITHUB_PATH"; fi
echo "installed $tool $version"
