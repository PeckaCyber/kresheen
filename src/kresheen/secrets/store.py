"""Per-user/per-Application secret storage (Anthropic API keys, Connector
credentials).

This backs the SQLRepository, so a Docker Compose or Helm deployment can store one
encrypted secret per user/Application. The master key comes from `KRESHEEN_SECRET_KEY`.
"""

from __future__ import annotations

import os
import uuid
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken

from kresheen.storage.repository import Repository


class SecretStore(Protocol):
    def get(self, ref: str) -> str | None: ...

    def set(self, owner_scope: str, plaintext: str) -> str: ...


class SecretKeyMissing(RuntimeError):
    """KRESHEEN_SECRET_KEY is not set; the API answers 503 with a clear message instead of a bare 500."""


def _fernet_from_env() -> Fernet:
    key = os.environ.get("KRESHEEN_SECRET_KEY")
    if not key:
        raise SecretKeyMissing(
            "KRESHEEN_SECRET_KEY is not set -- generate one with "
            '`python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"` and keep it somewhere safe '
            "(it encrypts every stored secret)."
        )
    return Fernet(key.encode())


class DbSecretStore:
    """Encrypts with Fernet (authenticated symmetric encryption) before
    handing ciphertext to the repository. The DB file itself is not assumed to
    be encrypted at rest; this covers API keys and connector credentials
    specifically, not the whole database."""

    def __init__(self, repo: Repository, fernet: Fernet | None = None):
        self._repo = repo
        self._fernet = fernet or _fernet_from_env()

    def get(self, ref: str) -> str | None:
        ciphertext = self._repo.get_secret_blob(ref)
        if ciphertext is None:
            return None
        try:
            return self._fernet.decrypt(ciphertext).decode()
        except InvalidToken:
            return None

    def set(self, owner_scope: str, plaintext: str) -> str:
        ref = f"SECRET-{uuid.uuid4().hex[:12]}"
        ciphertext = self._fernet.encrypt(plaintext.encode())
        self._repo.save_secret_blob(ref, ciphertext, owner_scope)
        return ref

    def delete(self, ref: str) -> None:
        self._repo.delete_secret_blob(ref)
