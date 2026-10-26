"""Builds the desktop installers for the platform it runs on.

    python packaging/desktop/build.py [--out dist-desktop]

Expects the built web interface in src/kresheen/web (as the release workflow puts it there before `uv build`).
Steps: a clean virtual environment from the hashed uv.lock export plus the project, PyInstaller from its hashed
requirements, the Grype binary for this platform (checksum verified), a one-folder PyInstaller build, then the
platform's packages:

    Linux    kresheen-<version>-linux-x86_64.tar.gz, .deb and .rpm (nfpm)
    Windows  kresheen-<version>-windows-x86_64-setup.exe (Inno Setup, per-user, no admin) and a .zip
    macOS    kresheen-<version>-macos-<arm64|x86_64>.dmg (Kresheen.app, opens Terminal to run the server)

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
    ("darwin", "x86_64"): ("darwin_amd64.tar.gz", "27eef17e42f0340af6582cdbc33ad18faf9f601c613ab81d2e1658a94cbc357f"),
    ("win32", "AMD64"): ("windows_amd64.zip", "f867bbdc14bd8b0d99b3fc47d839af07480a540072b16896373a8ba32b76f588"),
}
# Intel macOS: cryptography and argon2-cffi-bindings publish no Intel macOS wheels, so they are built from their
# hash-checked sdists, cryptography against a static OpenSSL built here. Keep OpenSSL on a supported 3.5 LTS release.
MACOS_INTEL_FROM_SOURCE = ("cryptography", "argon2-cffi-bindings")
MACOS_DEPLOYMENT_TARGET = "12.0"  # LSMinimumSystemVersion in macos/Info.plist
OPENSSL_VERSION = "3.5.9"
OPENSSL_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
RUST_TOOLCHAIN = "1.90.0"  # cryptography needs 1.83 or newer
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
    run(
        "uv",
        "export",
        "--frozen",
        "--no-dev",
        "--no-emit-project",
        "--format",
        "requirements-txt",
        "--no-header",
        "-o",
        requirements,
        cwd=ROOT,
    )
    if (sys.platform, platform.machine()) == ("darwin", "x86_64"):
        install_intel_macos_from_source(python, requirements)
    # Packages installed above count as satisfied here, so pip does not look for their (missing) wheels.
    run(python, "-m", "pip", "install", "--no-cache-dir", "--require-hashes", "-r", requirements)
    run(
        python,
        "-m",
        "pip",
        "install",
        "--no-cache-dir",
        "--require-hashes",
        "-r",
        ROOT / ".github" / "requirements" / "pyinstaller.txt",
    )
    run(python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", ROOT)
    return python


def requirement_block(requirements: Path, name: str) -> str:
    """The pinned line of `name` with its hashes, from a `uv export` file."""
    block: list[str] = []
    for line in requirements.read_text().splitlines():
        if block and not line.startswith(" "):
            break
        if block or line.lower().replace("_", "-").startswith(f"{name}=="):
            block.append(line)
    if not block:
        raise SystemExit(f"{name} is not in {requirements}")
    return "\n".join(line for line in block if not line.lstrip().startswith("#")) + "\n"


def build_static_openssl() -> Path:
    prefix, src = BUILD / "openssl", BUILD / "openssl-src"
    shutil.rmtree(prefix, ignore_errors=True)
    shutil.rmtree(src, ignore_errors=True)
    data = download(
        f"https://github.com/openssl/openssl/releases/download/openssl-{OPENSSL_VERSION}/openssl-{OPENSSL_VERSION}.tar.gz",
        OPENSSL_SHA256,
    )
    archive = BUILD / f"openssl-{OPENSSL_VERSION}.tar.gz"
    archive.write_bytes(data)
    shutil.unpack_archive(archive, src, filter="data")
    tree = src / f"openssl-{OPENSSL_VERSION}"
    env = {**os.environ, "MACOSX_DEPLOYMENT_TARGET": MACOS_DEPLOYMENT_TARGET}
    run(
        "perl",
        "./Configure",
        "darwin64-x86_64-cc",
        "no-shared",
        "no-tests",
        "no-docs",
        f"--prefix={prefix}",
        "--libdir=lib",
        cwd=tree,
        env=env,
    )
    run("make", f"-j{os.cpu_count() or 2}", cwd=tree, env=env)
    run("make", "install_sw", cwd=tree, env=env)
    return prefix


def install_intel_macos_from_source(python: Path, requirements: Path) -> None:
    openssl = build_static_openssl()
    run(
        python,
        "-m",
        "pip",
        "install",
        "--no-cache-dir",
        "--require-hashes",
        "--only-binary",
        ":all:",
        "-r",
        ROOT / ".github" / "requirements" / "macos-intel-build.txt",
    )
    run("rustup", "toolchain", "install", RUST_TOOLCHAIN, "--profile", "minimal")
    sdists, wheels = BUILD / "sdists", BUILD / "wheels"
    for folder in (sdists, wheels):
        shutil.rmtree(folder, ignore_errors=True)
        folder.mkdir(parents=True)
    pinned = BUILD / "from-source.txt"
    pinned.write_text("".join(requirement_block(requirements, name) for name in MACOS_INTEL_FROM_SOURCE))
    # The sdists are checked against the hashes in uv.lock; the build tools are hash-pinned above and used in place.
    run(
        python,
        "-m",
        "pip",
        "download",
        "--no-cache-dir",
        "--require-hashes",
        "--no-deps",
        "--no-binary",
        ":all:",
        "-r",
        pinned,
        "-d",
        sdists,
    )
    env = {
        **os.environ,
        # The build backends run their tools (maturin, cmake helpers) by name from the venv.
        "PATH": f"{python.parent}{os.pathsep}{os.environ.get('PATH', '')}",
        "MACOSX_DEPLOYMENT_TARGET": MACOS_DEPLOYMENT_TARGET,
        "OPENSSL_DIR": str(openssl),
        "OPENSSL_STATIC": "1",
        "RUSTUP_TOOLCHAIN": RUST_TOOLCHAIN,
    }
    for sdist in sorted(sdists.iterdir()):
        run(
            python,
            "-m",
            "pip",
            "wheel",
            "--no-cache-dir",
            "--no-build-isolation",
            "--no-deps",
            "-w",
            wheels,
            sdist,
            env=env,
        )
    run(python, "-m", "pip", "install", "--no-cache-dir", "--no-deps", *sorted(wheels.iterdir()))
    # The wheels must link the static OpenSSL above, not a system one, and load on the oldest supported macOS.
    run(
        python,
        "-c",
        "from cryptography.hazmat.backends.openssl.backend import backend; "
        f"v = backend.openssl_version_text(); print(v); assert v.startswith('OpenSSL {OPENSSL_VERSION} '), v; "
        "import _argon2_cffi_bindings",
    )
    built = [
        library
        for library in BUILD.joinpath("venv").rglob("*.so")
        if {"cryptography", "_argon2_cffi_bindings"} & set(library.parts)
    ]
    if len(built) < 2:
        raise SystemExit(f"expected the compiled cryptography and argon2 modules, found {built}")
    for library in built:
        load_commands = subprocess.run(["otool", "-l", library], check=True, capture_output=True, text=True).stdout
        if f"minos {MACOS_DEPLOYMENT_TARGET}" not in load_commands:
            raise SystemExit(f"{library} does not target macOS {MACOS_DEPLOYMENT_TARGET}")
        linked = subprocess.run(["otool", "-L", library], check=True, capture_output=True, text=True).stdout
        if "libssl" in linked or "libcrypto" in linked:
            raise SystemExit(f"{library} links a shared OpenSSL")


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
    run(
        python,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath",
        dist,
        "--workpath",
        work,
        HERE / "kresheen.spec",
        cwd=HERE,
    )
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
    url = (
        f"https://github.com/goreleaser/nfpm/releases/download/v{NFPM_VERSION}/nfpm_{NFPM_VERSION}_Linux_x86_64.tar.gz"
    )
    nfpm = tools / "nfpm"
    nfpm.write_bytes(tar_member(download(url, NFPM_SHA256), "nfpm"))
    nfpm.chmod(0o755)
    config = BUILD / "nfpm.yaml"
    template = (HERE / "linux" / "nfpm.yaml").read_text()
    config.write_text(
        template.replace("@VERSION@", version)
        .replace("@APP_DIR@", app.as_posix())
        .replace("@HERE@", (HERE / "linux").as_posix())
    )
    for packager, name in (("deb", f"kresheen_{version}_amd64.deb"), ("rpm", f"kresheen-{version}.x86_64.rpm")):
        run(nfpm, "package", "--config", config, "--packager", packager, "--target", out / name)


def package_windows(app: Path, version: str, out: Path) -> None:
    stem = f"kresheen-{version}-windows-x86_64"
    shutil.make_archive(str(out / stem), "zip", app.parent, app.name)
    # On PATH, or where the machine-wide (GitHub's image) or per-user (winget) install puts it.
    candidates = [
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
    ]
    iscc = shutil.which("iscc") or next((str(c) for c in candidates if c.exists()), None)
    if iscc is None:
        raise SystemExit("Inno Setup (ISCC.exe) not found")
    run(
        iscc,
        f"/DAppVersion={version}",
        f"/DAppDir={app}",
        f"/DOutDir={out}",
        f"/DOutName={stem}-setup",
        HERE / "windows" / "kresheen.iss",
    )


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
    run(
        "hdiutil",
        "create",
        "-volname",
        "Kresheen",
        "-srcfolder",
        staging,
        "-ov",
        "-format",
        "UDZO",
        out / f"kresheen-{version}-macos-{platform.machine()}.dmg",
    )


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
