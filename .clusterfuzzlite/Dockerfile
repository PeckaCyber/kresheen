# ClusterFuzzLite build image for the Atheris harnesses in fuzz/ (see .clusterfuzzlite/build.sh). The OSS-Fuzz
# Python builder ships Atheris, PyInstaller and its own Python; both images are pinned by digest.
FROM ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 AS uv

FROM gcr.io/oss-fuzz-base/base-builder-python:latest@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY --from=uv /uv /usr/local/bin/uv
COPY . $SRC/kresheen
WORKDIR $SRC/kresheen
COPY .clusterfuzzlite/build.sh $SRC/
