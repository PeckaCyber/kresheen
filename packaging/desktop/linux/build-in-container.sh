#!/usr/bin/env bash
# Runs packaging/desktop/build.py inside the glibc 2.28 build image (Dockerfile.build next to this script), so the
# Linux packages run on older distributions too. Arguments go to build.py.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
docker build -q -t kresheen-desktop-build -f "$root/packaging/desktop/linux/Dockerfile.build" "$root/packaging/desktop/linux"
docker run --rm --user "$(id -u):$(id -g)" -v "$root:/src" -w /src kresheen-desktop-build \
  bash -c 'exec "$(uv python find 3.13)" packaging/desktop/build.py "$@"' build.py "$@"
