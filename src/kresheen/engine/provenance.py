"""Run provenance stamp.

Ties a run's results to exactly what fed it and which code produced them:
an engine version, a hash of the built-in rule catalogs' actual content
(not just their ids, so editing a rule's severity or wording changes this
too), and a digest per data source. Lets a stale model be detected (the
inputs changed since the last run) and the frozen validation numbers be
tied to a release. Prerequisite for run-to-run diff.

Input digests are computed from each data source's own `connection_details`
(JSON, sorted keys, secret-shaped fields redacted) -- not a resolved git
commit SHA. For a `github_repository` source this means the digest changes
when the user reconfigures what they point at (repo, ref), not necessarily
on every new commit to a moving ref such as `main`. Resolving the tarball's
actual fetched commit SHA is a real improvement on this, not done here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from kresheen.engine.threats.config_rules import all_config_rules
from kresheen.engine.threats.methodology import methodology_rules
from kresheen.models.application import Application
from kresheen.models.data_source import DataSourceConfig
from kresheen.storage.repository import Repository

_SECRET_KEY_HINTS = ("token", "password", "secret", "key")
_DIGEST_LEN = 16  # hex chars; a collision-safe stamp, not a cryptographic identity


def engine_version() -> str:
    try:
        return _pkg_version("kresheen")
    except PackageNotFoundError:
        return "0.0.0-unknown"


def rule_catalog_version() -> str:
    """A stable hash over the built-in rule catalogs' content (STRIDE and any plugin methodology). Deterministic
    across processes (field order is fixed, not dict/set iteration order)."""
    parts = [
        "|".join(str(v) for v in (r.id, r.severity, r.condition, r.boundary_hint, r.when, r.title, r.description, r.cwe, r.attack))
        for r in methodology_rules()
    ]
    parts += [
        "|".join(str(v) for v in (r.id, r.taxonomy_id, r.severity, r.title, r.description, r.cwe, r.attack))
        for r in all_config_rules()
    ]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:_DIGEST_LEN]


def _redact(details: dict) -> dict:
    # A GitHub token moving from plaintext to a stored reference (or being replaced) is not a change to the source's
    # content: the reference and hint keys fold back into the one redacted `github_token` entry the digest always had.
    if details.get("github_token_ref") or details.get("github_token_hint"):
        details = {k: v for k, v in details.items() if k not in ("github_token_ref", "github_token_hint")}
        details["github_token"] = True
    return {
        key: ("<redacted>" if any(hint in key.lower() for hint in _SECRET_KEY_HINTS) else value)
        for key, value in details.items()
    }


def input_digest(data_source: DataSourceConfig) -> str:
    payload = json.dumps(
        {"type": data_source.type, "details": _redact(data_source.connection_details or {})},
        sort_keys=True, default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:_DIGEST_LEN]


@dataclass(frozen=True)
class StalenessResult:
    stale: bool
    new_data_source_ids: list[str] = field(default_factory=list)
    changed_data_source_ids: list[str] = field(default_factory=list)
    removed_data_source_ids: list[str] = field(default_factory=list)


def compute_staleness(application: Application, repo: Repository) -> StalenessResult:
    """Compares each current data source's live digest against the ones
    stamped on the application's latest run. No latest run, or a latest run
    with no provenance stamp (see
    ThreatModelRun.input_digests' docstring), is unconditionally stale -- an
    unknown state is exactly the case a user should be nudged to re-run.
    Shared by the per-application staleness endpoint (`api_applications.py`)
    and the group rollup (`api_groups.py`), so the comparison lives once."""
    latest_run = repo.get_run(application.latest_run_id) if application.latest_run_id else None
    # `engine_version` is stamped together with `input_digests` on completion,
    # so it distinguishes "never stamped" (older or failed run) from
    # "stamped with zero data sources" (a blank model), whose empty digest map
    # is legitimate and must not read as stale forever.
    if latest_run is None or latest_run.engine_version is None:
        return StalenessResult(stale=True)

    current_digests: dict[str, str] = {}
    for ds_id, stored in repo.list_data_source_digests(application.id):
        if stored is None:  # created before digests were stamped: load it once, the slow way
            ds = repo.get_data_source(ds_id)
            if ds is None:
                continue
            stored = input_digest(ds)
        current_digests[ds_id] = stored
    stored_digests = latest_run.input_digests
    new_ids = [ds_id for ds_id in current_digests if ds_id not in stored_digests]
    removed_ids = [ds_id for ds_id in stored_digests if ds_id not in current_digests]
    changed_ids = [
        ds_id
        for ds_id, digest in current_digests.items()
        if ds_id in stored_digests and stored_digests[ds_id] != digest
    ]
    return StalenessResult(
        stale=bool(new_ids or removed_ids or changed_ids),
        new_data_source_ids=new_ids,
        changed_data_source_ids=changed_ids,
        removed_data_source_ids=removed_ids,
    )
