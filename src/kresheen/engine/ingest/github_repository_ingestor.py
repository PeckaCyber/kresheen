"""Ingests a *whole* GitHub repository via GitHub's tarball endpoint --
plain `requests` (already a dependency), no `git` binary, no new SDK
dependency.

The scan downloads the whole tree rather than only the repo root, so nested
files (a monorepo's `frontend/package.json`, a `deploy/k8s/` directory, etc.)
are seen and Grype can be pointed at the real, complete repository.

This is a light, best-effort scan: notable files/directories
(container build files, IaC files, dependency manifests/lockfiles) become
`code_artifact` facts, and Grype is run against the whole extracted tree
for a genuine SBOM + vulnerability signal (see `_run_grype_scan`). Grype is
an optional external CLI -- this degrades gracefully (falls back to
filename-only facts) if it isn't installed. It needs a reasonably current
vulnerability DB (`grype db update`) to find real matches; that's an
operational prerequisite, not something this
ingestor tries to refresh inline on every scan (too slow/network-heavy to
do per-run).

Downloading and extracting an archive from a user-supplied GitHub URL is
new attack surface for this codebase (the Contents-API version only ever
read small JSON/text responses) -- `_extract_tarball_safely` treats that
extraction as untrusted input: it rejects path-traversal members, absolute
paths, symlinks escaping the extraction root, and device files *before*
extracting anything (checked over `tar.getmembers()` up front, not
discovered mid-extraction), on top of Python's own `filter="data"`
extraction filter (PEP 706) where the running interpreter supports it. A
download-size cap and an extracted-size cap (checked from member sizes
before extracting) guard against an oversized or bomb-like archive.

Two behaviours worth knowing:

1. Grype's `dir:` scan also catalogs GitHub Actions usage
   (`.github/workflows/*.yml`, `purl` starting with `pkg:github...`) and a
   `type: "file"` pseudo-component for the scanned directory itself --
   neither is a real application dependency. A repo with no lockfile
   committed would otherwise report a plausible-looking non-zero component
   count that implies a real dependency inventory. `_facts_from_cyclonedx`
   filters to real application-dependency `purl` ecosystems only (see
   `_is_application_dependency`) and separately flags `no_lockfile_detected`
   when only bare manifests (no lockfiles) were found, so the SBOM view can
   say so honestly instead of showing a misleading zero.
2. This scan has no way to know real data-flow/call relationships between
   components (that needs call-graph analysis). `normalize()` connects every
   code artifact and real vulnerability fact to one synthetic hub node
   representing the scanned repository itself, via a `discovered_in` edge
   -- an honest "this was found while scanning this repo" grouping, not a
   claim about how the application's components actually interact.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import ClassVar

import requests
import yaml

from kresheen.engine.ingest.base import SourceIngestor
from kresheen.engine.ingest.k8s_facts import build_k8s_facts, is_manifest_record
from kresheen.models.facts import FactEdge, FactNode, new_fact_edge_id, new_fact_node_id

logger = logging.getLogger(__name__)

_NOTABLE_FILES: dict[str, dict[str, str]] = {
    "Dockerfile": {"kind": "container_build"},
    "docker-compose.yml": {"kind": "container_compose"},
    "docker-compose.yaml": {"kind": "container_compose"},
    "package.json": {"kind": "dependency_manifest", "language": "node"},
    "requirements.txt": {"kind": "dependency_manifest", "language": "python"},
    "pyproject.toml": {"kind": "dependency_manifest", "language": "python"},
    "go.mod": {"kind": "dependency_manifest", "language": "go"},
    "pom.xml": {"kind": "dependency_manifest", "language": "java"},
    "build.gradle": {"kind": "dependency_manifest", "language": "java"},
    # Lockfiles: notable in their own right (they show real resolved
    # dependency versions), and also why Grype now gets pointed at the real
    # extracted tree rather than a hand-picked file allowlist -- confirmed
    # live that a bare manifest with no lockfile produces ZERO vulnerability
    # matches even for known-vulnerable exact versions.
    "package-lock.json": {"kind": "dependency_lockfile", "language": "node"},
    "yarn.lock": {"kind": "dependency_lockfile", "language": "node"},
    "pnpm-lock.yaml": {"kind": "dependency_lockfile", "language": "node"},
    "Pipfile.lock": {"kind": "dependency_lockfile", "language": "python"},
    "poetry.lock": {"kind": "dependency_lockfile", "language": "python"},
    "Gemfile.lock": {"kind": "dependency_lockfile", "language": "ruby"},
    "go.sum": {"kind": "dependency_lockfile", "language": "go"},
    "composer.lock": {"kind": "dependency_lockfile", "language": "php"},
}
_NOTABLE_DIRS: dict[str, dict[str, str]] = {
    "k8s": {"kind": "kubernetes_manifests"},
    "kubernetes": {"kind": "kubernetes_manifests"},
}

_MANIFEST_SUFFIXES = (".yaml", ".yml")
_MANIFEST_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "testdata"})
_MAX_MANIFEST_FILES = 300
_MAX_MANIFEST_FILE_BYTES = 1024 * 1024
_MAX_MANIFEST_RECORDS = 2000
_MAX_YAML_ALIASES = 20
_YAML_ALIAS_RE = re.compile(r"(?m)(?:^|[\s:\[,{-])\*[A-Za-z0-9_-]+")

_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024  # 200 MB compressed archive
_MAX_EXTRACTED_BYTES = 500 * 1024 * 1024  # 500 MB uncompressed, decompression-bomb guard
# Entries, not bytes: a few-MB archive of empty files stays under the byte caps but took 300 s and 1.1 GB to
# extract and walk at 1M files. Real repositories sit far below this.
_MAX_ARCHIVE_MEMBERS = 50_000
_DOWNLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB
_TARBALL_DOWNLOAD_TIMEOUT_SECONDS = 120
_GRYPE_TIMEOUT_SECONDS = 120


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    cleaned = repo_url.strip().rstrip("/")
    cleaned = re.sub(r"\.git$", "", cleaned)
    cleaned = re.sub(r"^(https?://)?(www\.)?github\.com/", "", cleaned)
    cleaned = re.sub(r"^git@github\.com:", "", cleaned)
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"Could not parse a GitHub owner/repo from: {repo_url}")
    return parts[0], parts[1]


_GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_GIT_REF_RE = re.compile(r"^[A-Za-z0-9._/@-]{1,200}$")


def validate_github_details(details: dict) -> None:
    """Refuse a repo URL or ref that could re-aim the request at another api.github.com path: owner/repo must be plain
    GitHub names, and the ref a plain ref with no `..` segment, no leading dash and no query or fragment
    characters. The host is already fixed to api.github.com. Raises ValueError."""
    owner, repo = _parse_owner_repo(details.get("repo_url", ""))
    for part in (owner, repo):
        if not _GITHUB_NAME_RE.fullmatch(part) or part in (".", ".."):
            raise ValueError(f"Not a valid GitHub owner/repository name: {part!r}")
    ref = details.get("ref")
    if ref and (
        not isinstance(ref, str) or not _GIT_REF_RE.fullmatch(ref) or ".." in ref.split("/") or ref.startswith(("-", "/"))
    ):
        raise ValueError("Not a valid git ref (use a branch, tag or commit SHA)")


_APPLICATION_DEPENDENCY_PURL_PREFIXES = (
    "pkg:npm/",
    "pkg:pypi/",
    "pkg:golang/",
    "pkg:maven/",
    "pkg:gem/",
    "pkg:composer/",
    "pkg:cargo/",
    "pkg:nuget/",
    "pkg:hex/",
    "pkg:conan/",
    "pkg:cocoapods/",
    "pkg:pub/",
    "pkg:swift/",
)


def _is_application_dependency(component: dict) -> bool:
    """Grype's `dir:` scan catalogs more than application dependencies --
    confirmed live against a real juice-shop scan: it also reports GitHub
    Actions referenced in `.github/workflows/*.yml` (`purl` starting with
    `pkg:github...`) and a `type: "file"` pseudo-component for the scanned
    directory itself (no `purl` at all). Neither is a real application
    dependency, and juice-shop's real repo has no lockfile committed, so
    every one of its 68 "components" turned out to be a CI action
    reference -- a misleading, plausible-looking non-zero count that
    implied a real dependency inventory when there wasn't one. A component
    only counts as a real application dependency if its `purl` matches a
    known package-ecosystem prefix."""
    purl = component.get("purl")
    return isinstance(purl, str) and purl.startswith(_APPLICATION_DEPENDENCY_PURL_PREFIXES)


def _severity_from_ratings(ratings: list) -> str:
    """A CycloneDX vulnerability can carry multiple `ratings[]` entries
    (e.g. a CVSS-based one alongside a severity-less EPSS score) -- take
    the first entry that actually has a `severity` field rather than
    assuming index 0 does. Confirmed live against a real Grype run."""
    for rating in ratings:
        if isinstance(rating, dict) and rating.get("severity"):
            return str(rating["severity"])
    return "unknown"


def _member_target_path(extract_root: Path, member_name: str) -> Path:
    """Resolve a tar member's on-disk target path, rejecting anything that
    would land outside `extract_root`. Absolute paths are rejected *before*
    joining -- `Path(root) / "/etc/passwd"` silently discards `root` and
    returns `/etc/passwd` (a pathlib gotcha, not a safe no-op), so an
    absolute-looking member name must never reach the join at all."""
    if PurePosixPath(member_name).is_absolute() or member_name.startswith("~"):
        raise ValueError(f"Refusing to extract archive member with an absolute path: {member_name}")
    target = (extract_root / member_name).resolve()
    try:
        target.relative_to(extract_root)
    except ValueError:
        raise ValueError(f"Refusing to extract path-traversal archive member: {member_name}") from None
    return target


def _extract_tarball_safely(tarball_path: str, extract_dir: str) -> None:
    """Validates every member of the archive *before* extracting anything
    (path traversal, absolute paths, symlinks escaping the extraction root,
    device files, total extracted size), then extracts using Python's own
    `filter="data"` security filter (PEP 706) as a second, independent
    layer wherever the running interpreter supports it
    (`hasattr(tarfile, "data_filter")` is the interpreter's own recommended
    feature-detection check, not a version-number guess)."""
    extract_root = Path(extract_dir).resolve()
    with tarfile.open(tarball_path, mode="r:gz") as tar:
        members: list[tarfile.TarInfo] = []
        total_size = 0
        for member in tar:  # lazily: stop at the cap instead of loading every entry first
            members.append(member)
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                raise ValueError(
                    f"Repository archive has more than {_MAX_ARCHIVE_MEMBERS} files -- aborting "
                    "(too many files to analyse)."
                )
            total_size += max(member.size, 0)
            if total_size > _MAX_EXTRACTED_BYTES:
                raise ValueError(
                    f"Repository archive extracts to more than {_MAX_EXTRACTED_BYTES} bytes -- "
                    "aborting (possible decompression bomb)."
                )
            if member.isdev():
                raise ValueError(f"Refusing to extract device file from archive: {member.name}")
            target = _member_target_path(extract_root, member.name)
            if member.issym() or member.islnk():
                link_name = member.linkname
                if PurePosixPath(link_name).is_absolute():
                    raise ValueError(
                        f"Refusing to extract symlink with an absolute target: {member.name} -> {link_name}"
                    )
                link_target = (target.parent / link_name).resolve()
                try:
                    link_target.relative_to(extract_root)
                except ValueError:
                    raise ValueError(
                        f"Refusing to extract symlink escaping the archive root: {member.name} -> {link_name}"
                    ) from None

        extract_kwargs: dict = {}
        if hasattr(tarfile, "data_filter"):
            extract_kwargs["filter"] = "data"
        tar.extractall(path=extract_dir, members=members, **extract_kwargs)


def _find_extracted_root(extract_dir: str) -> Path:
    """GitHub's tarball wraps the whole repository in one top-level
    `{owner}-{repo}-{sha}/` directory -- descend into it so callers see
    repo-relative paths, not that synthetic wrapper. Falls back to the
    extraction directory itself if the archive didn't have that shape
    (unexpected, but not fatal)."""
    children = list(Path(extract_dir).iterdir())
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return Path(extract_dir)


def _walk_notable_files(root: Path) -> list[dict]:
    """Recursively finds every notable file/directory anywhere in the tree
    (not just the top level) and records each match's real repo-relative
    path -- a monorepo's `frontend/package.json` and `backend/go.mod` are
    now distinguishable, which a top-level-only scan could never see."""
    matches: list[dict] = []
    for path in sorted(root.rglob("*")):
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if path.is_file():
            info = _NOTABLE_FILES.get(path.name)
            if info is not None:
                matches.append({"path": rel, "name": path.name, **info})
            elif path.name.endswith(".tf"):
                matches.append({"path": rel, "name": path.name, "kind": "terraform"})
        elif path.is_dir():
            info = _NOTABLE_DIRS.get(path.name.lower())
            if info is not None:
                matches.append({"path": rel, "name": path.name, **info})
    return matches


def _collect_k8s_records(root: Path) -> tuple[list[dict], dict[str, int]]:
    """Kubernetes objects found in the extracted tree, so a repository that
    ships its own manifests yields real components (and design-level threats)
    instead of only a file list. The content is untrusted, so this is bounded
    (file count, file size, record count), never follows symlinks, and skips
    what cannot be a plain manifest: Helm/Go templates (`{{ }}` is not YAML
    until rendered, and rendering means running code from the repo), and files
    with many YAML aliases (manifests do not use them; a nested-alias document
    can expand exponentially once walked). Skips are counted, not silent."""
    records: list[dict] = []
    stats = {"files_parsed": 0, "templated_skipped": 0, "unparseable_skipped": 0, "truncated": 0}
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if (
            path.suffix.lower() not in _MANIFEST_SUFFIXES
            or any(part in _MANIFEST_SKIP_DIRS for part in rel_parts[:-1])
            or path.is_symlink()
            or not path.is_file()
        ):
            continue
        if stats["files_parsed"] >= _MAX_MANIFEST_FILES or len(records) >= _MAX_MANIFEST_RECORDS:
            stats["truncated"] = 1
            break
        try:
            if path.stat().st_size > _MAX_MANIFEST_FILE_BYTES:
                stats["unparseable_skipped"] += 1
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            stats["unparseable_skipped"] += 1
            continue
        if "{{" in text:
            stats["templated_skipped"] += 1
            continue
        if len(_YAML_ALIAS_RE.findall(text)) > _MAX_YAML_ALIASES:
            stats["unparseable_skipped"] += 1
            continue
        try:
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            stats["unparseable_skipped"] += 1
            continue
        stats["files_parsed"] += 1
        records.extend(doc for doc in documents if is_manifest_record(doc))
    return records[:_MAX_MANIFEST_RECORDS], stats


def _run_grype_scan(directory: Path, notes: list[str] | None = None) -> tuple[dict, dict] | None:
    """Shells out to `grype dir:<root>` against the real extracted repository
    tree, requesting **two** simultaneous outputs: `cyclonedx-json` (the full
    SBOM document this ingestor has always used) and native `json`, which
    carries per-match `vulnerability.fix`/`.epss`/`.knownExploited` that
    cyclonedx-json does not (confirmed live during development: neither the
    fixed-version nor the EPSS/KEV data survives Grype's CycloneDX
    presenter). `-o format=path` accepts more than one `-o` in a single
    invocation and writes each to its own file (confirmed live against
    Grype 0.109), so this costs one scan, not two -- Grype embeds Syft's
    cataloger internally, so a single call already produces both a full
    component inventory and cross-referenced vulnerability matches, same as
    before this change. Pointing Grype at the whole tree (rather than a
    synthetic directory of hand-picked files) also lets its own ecosystem
    catalogers find manifests/lockfiles anywhere in the tree, not just the
    ones this ingestor's `_NOTABLE_FILES` allowlist happens to know about.

    Degrades gracefully: returns `None` (never raises) if Grype isn't
    installed, the scan times out, or it fails for any other reason -- a
    missing/failed SBOM scan must never break the rest of this ingestor's
    scan. Returns `(cyclonedx_document, native_matches_document)`.

    A skipped scan must never read as "no vulnerabilities": the reason is appended to `notes`, which the
    caller turns into a warning on the source's result.
    """
    def skipped(reason: str) -> None:
        if notes is not None:
            notes.append(reason)

    with tempfile.TemporaryDirectory() as tmp_dir:
        cyclonedx_path = Path(tmp_dir) / "cyclonedx.json"
        native_path = Path(tmp_dir) / "matches.json"
        try:
            subprocess.run(
                [
                    "grype",
                    f"dir:{directory}",
                    "-o",
                    f"cyclonedx-json={cyclonedx_path}",
                    "-o",
                    f"json={native_path}",
                ],
                check=True,
                capture_output=True,
                timeout=_GRYPE_TIMEOUT_SECONDS,
            )
            return json.loads(cyclonedx_path.read_text()), json.loads(native_path.read_text())
        except FileNotFoundError:
            logger.warning("grype is not installed -- skipping SBOM/vulnerability scan for this GitHub source")
            skipped("Grype is not installed on the server, so dependencies were not checked for known vulnerabilities.")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("grype scan timed out, skipping SBOM/vulnerability scan for this GitHub source")
            skipped("The vulnerability scan timed out, so dependencies were not checked for known vulnerabilities.")
            return None
        except (subprocess.CalledProcessError, json.JSONDecodeError, OSError) as exc:
            logger.warning("grype scan failed, skipping SBOM/vulnerability scan for this GitHub source: %s", exc)
            skipped("The vulnerability scan failed, so dependencies were not checked for known vulnerabilities.")
            return None


def _grype_match_lookup(native_matches: dict | None) -> dict[tuple[str, str, str], dict]:
    """(vulnerability id, package name, package version) -> fix/EPSS/KEV info
    from Grype's native `json` output (see `_run_grype_scan`). Keyed on the
    same three fields `_facts_from_cyclonedx` already extracts from the
    CycloneDX document for each vulnerability, since the two documents don't
    share a common id (CycloneDX's `affects[].ref` is a bom-ref, not the
    native output's package name+version)."""
    lookup: dict[tuple[str, str, str], dict] = {}
    for match in (native_matches or {}).get("matches", []):
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        key = (str(vuln.get("id", "")), str(artifact.get("name", "")), str(artifact.get("version") or ""))
        fix = vuln.get("fix") or {}
        epss_entries = vuln.get("epss") or []
        epss = epss_entries[0] if epss_entries and isinstance(epss_entries[0], dict) else {}
        lookup[key] = {
            "fixed_versions": list(fix.get("versions") or []),
            "fix_state": fix.get("state"),
            "epss_score": epss.get("epss"),
            "epss_percentile": epss.get("percentile"),
            "known_exploited": bool(vuln.get("knownExploited")),
        }
    return lookup


def _facts_from_cyclonedx(
    document: dict,
    *,
    run_id: str,
    application_id: str,
    repo: str,
    now: datetime,
    no_lockfile_detected: bool = False,
    manifest_files_found: list[str] | None = None,
    native_matches: dict | None = None,
) -> list[FactNode]:
    """One `FactNode` per real vulnerability match, plus one summary
    `sbom_document` node carrying the full raw CycloneDX document (same
    "store the full raw payload verbatim" precedent as `Evidence.raw`
    elsewhere in this codebase) -- the summary node is what backs the
    Application-run detail page's SBOM view.

    `document` is stored verbatim, unfiltered, for provenance -- but the
    `components`/`vulnerabilities`/`component_count`/`vulnerability_count`
    attributes actually surfaced to the SBOM view are filtered to real
    application dependencies only (see `_is_application_dependency`), and
    a vulnerability only produces a fact/counts toward the total if the
    component it affects survived that same filter. `native_matches`, when
    given, is Grype's native-json scan of the same tree (see
    `_run_grype_scan`/`_grype_match_lookup`) -- absent (`None`) for a caller
    that only has a CycloneDX document (e.g. a unit test fixture predating
    this), in which case fix/EPSS/KEV attributes are simply blank rather
    than raising."""
    match_lookup = _grype_match_lookup(native_matches)
    raw_components = document.get("components", [])
    all_components = raw_components if isinstance(raw_components, list) else []
    components_by_ref = {c.get("bom-ref"): c for c in all_components if isinstance(c, dict)}
    kept_components = [c for c in all_components if isinstance(c, dict) and _is_application_dependency(c)]
    kept_refs = {c.get("bom-ref") for c in kept_components}

    raw_vulns = document.get("vulnerabilities", [])
    all_vulns = raw_vulns if isinstance(raw_vulns, list) else []

    nodes: list[FactNode] = []
    kept_vulns: list[dict] = []
    for vuln in all_vulns:
        if not isinstance(vuln, dict):
            continue
        affects = vuln.get("affects", [])
        component: dict | None = None
        if isinstance(affects, list) and affects and isinstance(affects[0], dict):
            component = components_by_ref.get(affects[0].get("ref"))
        if component is None or component.get("bom-ref") not in kept_refs:
            # Affects something that isn't a real application dependency
            # (a GitHub Actions usage entry, or an unresolved reference) --
            # exclude it from both the finding it would otherwise produce
            # and the SBOM view's vulnerability count.
            continue
        kept_vulns.append(vuln)
        vuln_id = vuln.get("id", "unknown-vuln")
        package = component.get("name", "unknown")
        version = component.get("version") or ""
        purl = component.get("purl")
        title = f"{vuln_id} in {package}@{version}" if version else f"{vuln_id} in {package}"
        match_info = match_lookup.get((vuln_id, package, version), {})
        nodes.append(
            FactNode(
                id=new_fact_node_id(),
                run_id=run_id,
                application_id=application_id,
                node_type="vulnerability",
                name=title,
                attributes={
                    "repo": repo,
                    "cve_id": vuln_id,
                    "severity": _severity_from_ratings(vuln.get("ratings", []) or []),
                    "package": package,
                    "version": version,
                    "purl": purl,
                    "description": str(vuln.get("description", ""))[:1000],
                    # From Grype's native json output only -- blank when
                    # native_matches wasn't available (see this function's
                    # docstring).
                    "fixed_versions": match_info.get("fixed_versions", []),
                    "fix_state": match_info.get("fix_state"),
                    "epss_score": match_info.get("epss_score"),
                    "epss_percentile": match_info.get("epss_percentile"),
                    "known_exploited": match_info.get("known_exploited", False),
                },
                source_ref="grype",
                discovered_at=now,
            )
        )

    nodes.append(
        FactNode(
            id=new_fact_node_id(),
            run_id=run_id,
            application_id=application_id,
            node_type="sbom_document",
            name=f"{repo}: SBOM",
            attributes={
                "format": "cyclonedx-json",
                "document": document,
                "components": kept_components,
                "vulnerabilities": kept_vulns,
                "component_count": len(kept_components),
                "vulnerability_count": len(kept_vulns),
                "no_lockfile_detected": no_lockfile_detected,
                "manifest_files_found": manifest_files_found or [],
            },
            source_ref="grype",
            discovered_at=now,
        )
    )
    return nodes


class GithubRepositoryIngestor(SourceIngestor):
    source_type: ClassVar[str] = "github_repository"

    def fetch(self, *, connection_details: dict | None = None, **kwargs) -> dict:
        """Downloads the repository's tarball (streamed, size-capped),
        extracts it safely into a temp directory, walks the whole tree for
        notable files/dirs, runs Grype against it, and cleans up both temp
        resources before returning -- everything heavy happens here so
        `parse`/`normalize` never need to know about the archive's
        lifecycle, and so cleanup is guaranteed by one `finally` regardless
        of where a failure happens.
        """
        details = connection_details or {}
        validate_github_details(details)
        owner, repo = _parse_owner_repo(details.get("repo_url", ""))
        headers = {"Accept": "application/vnd.github+json"}
        token = details.get("github_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        ref = details.get("ref")
        url = f"https://api.github.com/repos/{owner}/{repo}/tarball"
        if ref:
            url = f"{url}/{ref}"

        tarball_fd, tarball_path = tempfile.mkstemp(suffix=".tar.gz")
        extract_dir = tempfile.mkdtemp(prefix="kresheen-ghrepo-")
        try:
            with os.fdopen(tarball_fd, "wb") as tarball_file, requests.get(
                url, headers=headers, stream=True, timeout=_TARBALL_DOWNLOAD_TIMEOUT_SECONDS
            ) as response:
                response.raise_for_status()
                total = 0
                for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_SIZE):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD_BYTES:
                        raise ValueError(
                            f"Repository archive for {owner}/{repo} exceeds the "
                            f"{_MAX_DOWNLOAD_BYTES}-byte download cap -- aborting."
                        )
                    tarball_file.write(chunk)

            _extract_tarball_safely(tarball_path, extract_dir)
            root = _find_extracted_root(extract_dir)
            matches = _walk_notable_files(root)
            scan_notes: list[str] = []
            grype_result = _run_grype_scan(root, scan_notes)
            if grype_result is None and not scan_notes:
                scan_notes.append("The vulnerability scan did not run, so dependencies were not checked for known vulnerabilities.")
            sbom_document, grype_native_matches = grype_result if grype_result else (None, None)
            k8s_records, k8s_stats = _collect_k8s_records(root)
            return {
                "repo": f"{owner}/{repo}",
                "matches": matches,
                "sbom_document": sbom_document,
                "grype_native_matches": grype_native_matches,
                "k8s_records": k8s_records,
                "k8s_stats": k8s_stats,
                "scan_warnings": scan_notes,
            }
        finally:
            os.unlink(tarball_path)
            shutil.rmtree(extract_dir, ignore_errors=True)

    def parse(self, raw: dict) -> list[dict]:
        repo = raw.get("repo", "")
        records = [{"_repo": repo, **match} for match in raw.get("matches", [])]
        sbom_document = raw.get("sbom_document")
        if sbom_document is not None:
            records.append({"_repo": repo, "_sbom_document": sbom_document})
        grype_native_matches = raw.get("grype_native_matches")
        if grype_native_matches is not None:
            records.append({"_repo": repo, "_grype_native_matches": grype_native_matches})
        if raw.get("scan_warnings"):
            records.append({"_repo": repo, "_scan_warnings": list(raw["scan_warnings"])})
        if raw.get("k8s_records") or raw.get("k8s_stats"):
            records.append(
                {"_repo": repo, "_k8s_records": raw.get("k8s_records", []), "_k8s_stats": raw.get("k8s_stats", {})}
            )
        return records

    def normalize(
        self, records: list[dict], *, run_id: str, application_id: str
    ) -> tuple[list[FactNode], list[FactEdge]]:
        now = datetime.now(UTC)
        nodes: list[FactNode] = []
        repo = ""
        sbom_document: dict | None = None
        grype_native_matches: dict | None = None
        k8s_records: list[dict] = []
        k8s_stats: dict[str, int] = {}
        scan_warnings: list[str] = []
        for record in records:
            repo = record.get("_repo", repo)
            if "_scan_warnings" in record:
                scan_warnings = record["_scan_warnings"]
                continue
            if "_sbom_document" in record:
                sbom_document = record["_sbom_document"]
                continue
            if "_grype_native_matches" in record:
                grype_native_matches = record["_grype_native_matches"]
                continue
            if "_k8s_records" in record:
                k8s_records, k8s_stats = record["_k8s_records"], record.get("_k8s_stats", {})
                continue
            path = record["path"]
            extra = {k: v for k, v in record.items() if k not in ("_repo", "path")}
            nodes.append(
                FactNode(
                    id=new_fact_node_id(),
                    run_id=run_id,
                    application_id=application_id,
                    node_type="code_artifact",
                    name=f"{repo}:{path}",
                    attributes={"file": path, "repo": repo, **extra},
                    source_ref="github_repository",
                    discovered_at=now,
                )
            )

        if scan_warnings:
            # Not a diagram element: only carries the warning to the source's result (engine/source_status.py).
            nodes.append(
                FactNode(
                    id=new_fact_node_id(),
                    run_id=run_id,
                    application_id=application_id,
                    node_type="scan_note",
                    name=f"{repo or 'repository'} scan notes",
                    attributes={"warnings": scan_warnings},
                    source_ref="github_repository",
                    discovered_at=now,
                )
            )

        # A manifest with no companion lockfile can't have its dependency
        # versions resolved by Grype (confirmed live: juice-shop's real
        # repo has package.json but no package-lock.json, and Grype found
        # zero real npm components as a result) -- surfaced to the SBOM
        # view so it can say so honestly instead of showing a misleading
        # "0 components, 0 vulnerabilities".
        manifest_paths = sorted(
            n.attributes["file"] for n in nodes if n.attributes.get("kind") == "dependency_manifest"
        )
        has_lockfile = any(n.attributes.get("kind") == "dependency_lockfile" for n in nodes)
        no_lockfile_detected = bool(manifest_paths) and not has_lockfile

        if sbom_document is not None:
            nodes.extend(
                _facts_from_cyclonedx(
                    sbom_document,
                    run_id=run_id,
                    application_id=application_id,
                    repo=repo,
                    now=now,
                    no_lockfile_detected=no_lockfile_detected,
                    manifest_files_found=manifest_paths,
                    native_matches=grype_native_matches,
                )
            )

        # Hub-and-spoke grouping, not a claim about real data flow: real
        # call-graph/data-flow analysis between components is a separate,
        # not-yet-built feature -- so this repo
        # scan has no way to know how components actually interact. What
        # it can honestly say is "these things were all discovered as part
        # of scanning this one repository", which is a real improvement
        # over every fact rendering as a disconnected floating node on the
        # DFD. The `sbom_document` summary node is excluded -- it isn't a
        # diagram-worthy entity, just a data carrier for the SBOM view.
        edges: list[FactEdge] = []
        hub_targets = [n for n in nodes if n.node_type in ("code_artifact", "vulnerability")]
        if hub_targets:
            hub = FactNode(
                id=new_fact_node_id(),
                run_id=run_id,
                application_id=application_id,
                node_type="external_entity",
                name=repo or "GitHub repository",
                attributes={
                    "note": (
                        "Root node grouping everything discovered while scanning this repository. "
                        "Hub-and-spoke grouping only -- not real data-flow or call relationships."
                    ),
                    "k8s_manifests": k8s_stats,
                },
                source_ref="github_repository",
                discovered_at=now,
            )
            nodes.append(hub)
            edges.extend(
                FactEdge(
                    id=new_fact_edge_id(),
                    run_id=run_id,
                    application_id=application_id,
                    source_node_id=hub.id,
                    target_node_id=target.id,
                    edge_type="discovered_in",
                )
                for target in hub_targets
            )

        # Real components: Kubernetes objects the repository ships. These come
        # from the same builder as an uploaded manifest (workloads, stores,
        # namespaces as boundaries, evidence-based flows) but keep this source
        # as their provenance. Added after the hub, so they are never hub spokes.
        if k8s_records:
            k8s_nodes, k8s_edges = build_k8s_facts(
                k8s_records, run_id=run_id, application_id=application_id, source_ref="github_repository:k8s"
            )
            for node in k8s_nodes:
                node.attributes["source_repo"] = repo  # lets vulnerability evidence find the workloads of this repo
            nodes.extend(k8s_nodes)
            edges.extend(k8s_edges)
        return nodes, edges
