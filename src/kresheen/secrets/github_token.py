"""A GitHub data source's access token, kept out of the data source row.

The token is encrypted with `DbSecretStore` and the data source holds only a reference (`github_token_ref`) and the
last four characters (`github_token_hint`) so the UI can say which token is saved. The plaintext `github_token` key
only ever appears on rows written before this existed (and in memory for the length of one run); such a row is moved
into the secret store as soon as `KRESHEEN_SECRET_KEY` is available (see `secure_legacy_token`).

Nothing here logs a token.
"""

from __future__ import annotations

from kresheen.models.data_source import DataSourceConfig
from kresheen.secrets.store import DbSecretStore, SecretKeyMissing
from kresheen.storage.repository import Repository

PLAINTEXT_KEY = "github_token"
REF_KEY = "github_token_ref"
HINT_KEY = "github_token_hint"
TOKEN_KEYS = (PLAINTEXT_KEY, REF_KEY, HINT_KEY)


def strip_token_keys(details: dict) -> dict:
    """A copy of `details` without any token key; used on client input (a client must not name a secret ref)."""
    return {key: value for key, value in details.items() if key not in TOKEN_KEYS}


def has_token(data_source: DataSourceConfig) -> bool:
    details = data_source.connection_details
    return bool(details.get(REF_KEY) or details.get(PLAINTEXT_KEY))


def token_hint(data_source: DataSourceConfig) -> str | None:
    details = data_source.connection_details
    hint = details.get(HINT_KEY)
    if isinstance(hint, str) and hint:
        return hint
    legacy = details.get(PLAINTEXT_KEY)
    return legacy[-4:] if isinstance(legacy, str) and legacy else None


def set_token(repo: Repository, data_source: DataSourceConfig, token: str) -> None:
    """Encrypts `token` into the secret store and points the data source at it (not saved here). Raises
    SecretKeyMissing before touching anything when the server has no key."""
    store = DbSecretStore(repo)
    old_ref = data_source.connection_details.get(REF_KEY)
    ref = store.set(f"data_source:{data_source.id}", token)
    details = strip_token_keys(data_source.connection_details)
    details[REF_KEY] = ref
    details[HINT_KEY] = token[-4:]
    data_source.connection_details = details
    if isinstance(old_ref, str) and old_ref:
        repo.delete_secret_blob(old_ref)


def clear_token(repo: Repository, data_source: DataSourceConfig) -> None:
    """Deletes the stored secret and removes every token key from the data source (not saved here)."""
    ref = data_source.connection_details.get(REF_KEY)
    if isinstance(ref, str) and ref:
        repo.delete_secret_blob(ref)
    data_source.connection_details = strip_token_keys(data_source.connection_details)


def delete_stored_tokens(repo: Repository, data_sources: list[DataSourceConfig]) -> None:
    for data_source in data_sources:
        ref = data_source.connection_details.get(REF_KEY)
        if isinstance(ref, str) and ref:
            repo.delete_secret_blob(ref)


def secure_legacy_token(repo: Repository, data_source: DataSourceConfig) -> bool:
    """Moves a plaintext `github_token` into the secret store and saves the row without it. Returns True when it did.
    A no-op when there is no plaintext token or the server has no `KRESHEEN_SECRET_KEY` (the row is then still never
    returned by the API, and is moved on the first run or read after the key is set)."""
    legacy = data_source.connection_details.get(PLAINTEXT_KEY)
    if not legacy:
        return False
    if not isinstance(legacy, str):  # not a usable token; drop it rather than keep unknown data
        data_source.connection_details = strip_token_keys(data_source.connection_details)
        repo.save_data_source(data_source)
        return True
    try:
        set_token(repo, data_source, legacy)
    except SecretKeyMissing:
        return False
    repo.save_data_source(data_source)
    return True


def resolve_token(repo: Repository, data_source: DataSourceConfig) -> str | None:
    """The usable token for a run: decrypted from the reference, or a not-yet-moved legacy plaintext value."""
    details = data_source.connection_details
    ref = details.get(REF_KEY)
    if isinstance(ref, str) and ref:
        try:
            return DbSecretStore(repo).get(ref)
        except SecretKeyMissing:
            return None
    legacy = details.get(PLAINTEXT_KEY)
    return legacy if isinstance(legacy, str) and legacy else None
