"""Builds the desktop installers for the platform it runs on.

    python packaging/desktop/build.py [--out dist-desktop]

Expects the built web interface in src/kresheen/web (as the release workflow puts it there before `uv build`).
Steps: a clean virtual environment from the hashed uv.lock export plus the project, PyInstaller from its hashed
requirements, the Grype binary for this platform (checksum verified), a one-folder PyInstaller build, then the
platform's packages:

    Linux    kresheen-<version>-linux-x86_64.tar.gz, .deb and .rpm (nfpm)
    Windows  kresheen-<version>-windows-x86_64-setup.exe (Inno Setup, per-user, no admin) and a .zip
    macOS    kresheen-<version>-macos-arm64.dmg (Kresheen.app, opens Terminal to run the server)

The builds are not code-signed yet: Windows SmartScreen and macOS Gatekeeper warn on first start.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / "build" / "desktop"

# Keep in step with the Grype version in .github/scripts/install-tool.sh and the Dockerfile.
GRYPE_VERSION = "0.121.0"
GRYPE = {
    ("linux", "x86_64"): ("linux_amd64.tar.gz", "64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519"),
    ("darwin", "arm64"): ("darwin_arm64.tar.gz", "7be39d3a0428c664ce0183e4aba31ed9accffce9eda7e7f6fa84e9c512285f27"),
    ("win32", "AMD64"): ("windows_amd64.zip", "f867bbdc14bd8b0d99b3fc47d839af07480a540072b16896373a8ba32b76f588"),
}
NFPM_VERSION = "2.48.0"
NFPM_SHA256 = "6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750"


def run(*args: str | Path, **kwargs) -> None:
    print("+", " ".join(str(a) for a in args), flush=True)
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def tar_member(data: bytes, name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.extractfile(name)
        if member is None:
            raise SystemExit(f"{name} missing from the download")
        return member.read()


def download(url: str, sha256: str) -> bytes:
    if not url.startswith("https://github.com/"):
        raise ValueError(f"unexpected download URL: {url}")
    # The URL is one of the fixed https://github.com/ URLs above and the bytes are checked against a pinned SHA256.
    with urllib.request.urlopen(url, timeout=120) as response:  # nosemgrep: dynamic-urllib-use-detected
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise SystemExit(f"checksum mismatch for {url}: {digest}")
    return data


def project_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def prepare_venv() -> Path:
    if not (ROOT / "src" / "kresheen" / "web" / "index.html").exists():
        raise SystemExit("src/kresheen/web is missing: build the frontend and copy frontend/dist there first")
    venv = BUILD / "venv"
    shutil.rmtree(venv, ignore_errors=True)
    run(sys.executable, "-m", "venv", venv)
    python = venv_python(venv)
    requirements = BUILD / "requirements.txt"
    run("uv", "export", "--frozen", "--no-dev", "--no-emit-project", "--format", "requirements-txt", "--no-header",
        "-o", requirements, cwd=ROOT)
    run(python, "-m", "pip", "install", "--no-cache-dir", "--require-hashes", "-r", requirements)
    run(python, "-m", "pip", "install", "--no-cache-dir", "--require-hashes", "-r",
        ROOT / ".github" / "requirements" / "pyinstaller.txt")
    run(python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", ROOT)
    return python


def fetch_grype(dest: Path) -> None:
    key = (sys.platform, platform.machine())
    if key not in GRYPE:
        raise SystemExit(f"no Grype build pinned for {key}")
    suffix, sha256 = GRYPE[key]
    url = f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/grype_{GRYPE_VERSION}_{suffix}"
    data = download(url, sha256)
    name = "grype.exe" if sys.platform == "win32" else "grype"
    if suffix.endswith(".zip"):
        payload = zipfile.ZipFile(io.BytesIO(data)).read(name)
    else:
        payload = tar_member(data, name)
    (dest / name).write_bytes(payload)
    (dest / name).chmod(0o755)


def bundle(python: Path) -> Path:
    dist, work = BUILD / "dist", BUILD / "work"
    shutil.rmtree(dist, ignore_errors=True)
    run(python, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", dist, "--workpath", work,
        HERE / "kresheen.spec", cwd=HERE)
    app = dist / "kresheen"
    fetch_grype(app)
    for name in ("LICENSE", "NOTICE"):
        shutil.copy(ROOT / name, app / name)
    # Smoke test: the frozen app starts its CLI and finds its own metadata.
    run(app / ("kresheen.exe" if sys.platform == "win32" else "kresheen"), "--version")
    return app


def package_linux(app: Path, version: str, out: Path) -> None:
    stem = f"kresheen-{version}-linux-x86_64"
    with tarfile.open(out / f"{stem}.tar.gz", "w:gz") as archive:
        archive.add(app, arcname=f"kresheen-{version}")
    tools = BUILD / "tools"
    tools.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/goreleaser/nfpm/releases/download/v{NFPM_VERSION}/nfpm_{NFPM_VERSION}_Linux_x86_64.tar.gz"
    nfpm = tools / "nfpm"
    nfpm.write_bytes(tar_member(download(url, NFPM_SHA256), "nfpm"))
    nfpm.chmod(0o755)
    config = BUILD / "nfpm.yaml"
    template = (HERE / "linux" / "nfpm.yaml").read_text()
    config.write_text(template.replace("@VERSION@", version).replace("@APP_DIR@", app.as_posix())
                      .replace("@HERE@", (HERE / "linux").as_posix()))
    for packager, name in (("deb", f"kresheen_{version}_amd64.deb"), ("rpm", f"kresheen-{version}.x86_64.rpm")):
        run(nfpm, "package", "--config", config, "--packager", packager, "--target", out / name)


def package_windows(app: Path, version: str, out: Path) -> None:
    stem = f"kresheen-{version}-windows-x86_64"
    shutil.make_archive(str(out / stem), "zip", app.parent, app.name)
    # On PATH, or where the machine-wide (GitHub's image) or per-user (winget) install puts it.
    candidates = [Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
                  Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe"]
    iscc = shutil.which("iscc") or next((str(c) for c in candidates if c.exists()), None)
    if iscc is None:
        raise SystemExit("Inno Setup (ISCC.exe) not found")
    run(iscc, f"/DAppVersion={version}", f"/DAppDir={app}", f"/DOutDir={out}", f"/DOutName={stem}-setup",
        HERE / "windows" / "kresheen.iss")


def package_macos(app: Path, version: str, out: Path) -> None:
    bundle_dir = BUILD / "Kresheen.app"
    shutil.rmtree(bundle_dir, ignore_errors=True)
    contents = bundle_dir / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    shutil.copytree(app, contents / "Resources" / "kresheen", symlinks=True)
    plist = (HERE / "macos" / "Info.plist").read_text().replace("@VERSION@", version)
    (contents / "Info.plist").write_text(plist)
    launcher = contents / "MacOS" / "Kresheen"
    shutil.copy(HERE / "macos" / "launch.sh", launcher)
    launcher.chmod(0o755)
    staging = BUILD / "dmg"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir()
    shutil.copytree(bundle_dir, staging / "Kresheen.app", symlinks=True)
    (staging / "Applications").symlink_to("/Applications")
    run("hdiutil", "create", "-volname", "Kresheen", "-srcfolder", staging, "-ov", "-format", "UDZO",
        out / f"kresheen-{version}-macos-arm64.dmg")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="dist-desktop", help="Folder for the finished packages.")
    args = parser.parse_args()
    out = (ROOT / args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    version = project_version()
    app = bundle(prepare_venv())
    {"linux": package_linux, "win32": package_windows, "darwin": package_macos}[sys.platform](app, version, out)
    for path in sorted(out.iterdir()):
        print(f"{path.name}  {path.stat().st_size // (1024 * 1024)} MB")


if __name__ == "__main__":
    main()
