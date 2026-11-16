# ClusterFuzzLite build image for the Atheris harnesses in fuzz/ (see .clusterfuzzlite/build.sh). The OSS-Fuzz
# Python builder ships Atheris, PyInstaller and its own Python; both images are pinned by digest.
FROM ghcr.io/astral-sh/uv:0.13.8@sha256:5cc1805e2426484abca4ad46ea783bab281fdb225fd82d8ce6d66a81254bac85 AS uv

FROM gcr.io/oss-fuzz-base/base-builder-python:latest@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY --from=uv /uv /usr/local/bin/uv
COPY . $SRC/kresheen
WORKDIR $SRC/kresheen
COPY .clusterfuzzlite/build.sh $SRC/
