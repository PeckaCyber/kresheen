#!/usr/bin/env bash
# Install a pinned release binary (Linux x86_64) after verifying its SHA256, and put it on PATH for later steps.
# Usage: .github/scripts/install-tool.sh <grype|syft|cosign|actionlint|zizmor|hadolint|kube-linter>
# To update a tool, change the version and the checksum together (checksum from the project's release checksums file).
set -euo pipefail

tool=${1:?usage: install-tool.sh <grype|syft|cosign|actionlint|zizmor|hadolint|kube-linter>}
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
  actionlint)
    version=1.7.12
    sha256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    url="https://github.com/rhysd/actionlint/releases/download/v${version}/actionlint_${version}_linux_amd64.tar.gz"
    kind=tar ;;
  zizmor)
    version=1.30.1
    sha256=e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a
    url="https://github.com/zizmorcore/zizmor/releases/download/v${version}/zizmor-x86_64-unknown-linux-gnu.tar.gz"
    kind=tar ;;
  hadolint)
    version=2.15.1
    sha256=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
    url="https://github.com/hadolint/hadolint/releases/download/v${version}/hadolint-linux-x86_64"
    kind=bin ;;
  kube-linter)
    version=0.8.3
    sha256=618d299a3e2839c8ca9d86fce0db617be0fba41f0fecbbbfb7fbf1c04299fae1
    url="https://github.com/stackrox/kube-linter/releases/download/v${version}/kube-linter-linux"
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
