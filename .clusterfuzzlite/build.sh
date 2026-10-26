#!/bin/bash -eu
# Builds one fuzzer binary per fuzz/fuzz_*.py, each with a seed corpus. Runs inside the image from
# .clusterfuzzlite/Dockerfile ($SRC, $OUT and compile_python_fuzzer come from the OSS-Fuzz builder).

# Same install as the release image: the lock file exported to a hashed list, then the project without deps.
uv export --frozen --no-dev --no-emit-project --format requirements-txt --no-header -o /tmp/requirements.txt
pip3 install --no-cache-dir --require-hashes -r /tmp/requirements.txt
pip3 install --no-cache-dir --no-deps .

for fuzzer in fuzz/fuzz_*.py; do
  # --collect-data: the engine reads rule and sample files that ship inside the package.
  compile_python_fuzzer "$fuzzer" --collect-data kresheen
done

zip -qj "$OUT/fuzz_diagram_seed_corpus.zip" fuzz/seeds/fuzz_diagram/*
zip -qj "$OUT/fuzz_manifest_seed_corpus.zip" src/kresheen/engine/samples/kubernetes_app.yaml \
  src/kresheen/engine/samples/aws_app_plan.json
python3 - <<'PY'
import io, os, tarfile, zipfile

def tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = payload.decode()
                archive.addfile(info)
    return buffer.getvalue()

seeds = {
    "repo": [("repo-abc/package.json", tarfile.REGTYPE, b"{}"), ("repo-abc/main.tf", tarfile.REGTYPE, b"x")],
    "links": [("repo-abc/a", tarfile.REGTYPE, b"a"), ("repo-abc/s", tarfile.SYMTYPE, b"a"),
              ("repo-abc/h", tarfile.LNKTYPE, b"repo-abc/a"), ("repo-abc/d", tarfile.DIRTYPE, b"")],
    # A link over a directory made tarfile recurse until RecursionError (fuzz-nightly, 2026-10-26).
    "link-over-dir": [("repo-abc/a", tarfile.REGTYPE, b"a"), ("repo-abc/", tarfile.SYMTYPE, b"")],
}
with zipfile.ZipFile(os.path.join(os.environ["OUT"], "fuzz_tarball_seed_corpus.zip"), "w") as corpus:
    for name, members in seeds.items():
        corpus.writestr(name, tar(members))
PY
