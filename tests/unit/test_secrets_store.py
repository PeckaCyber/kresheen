import pytest
from cryptography.fernet import Fernet

from kresheen.secrets.store import DbSecretStore
from kresheen.storage.sql_repo import SQLRepository


def _repo(tmp_path) -> SQLRepository:
    return SQLRepository(f"sqlite:///{tmp_path}/test.db")


def _store(tmp_path) -> DbSecretStore:
    return DbSecretStore(_repo(tmp_path), fernet=Fernet(Fernet.generate_key()))


def test_set_then_get_roundtrips_the_plaintext(tmp_path):
    store = _store(tmp_path)

    ref = store.set("user:USER-1", "sk-ant-super-secret")

    assert store.get(ref) == "sk-ant-super-secret"


def test_get_returns_none_for_unknown_ref(tmp_path):
    store = _store(tmp_path)

    assert store.get("SECRET-does-not-exist") is None


def test_ciphertext_never_contains_the_plaintext(tmp_path):
    repo = _repo(tmp_path)
    store = DbSecretStore(repo, fernet=Fernet(Fernet.generate_key()))

    ref = store.set("user:USER-1", "sk-ant-super-secret")

    stored_ciphertext = repo.get_secret_blob(ref)
    assert b"sk-ant-super-secret" not in stored_ciphertext


def test_get_returns_none_when_decrypted_with_the_wrong_key(tmp_path):
    repo = _repo(tmp_path)
    writer = DbSecretStore(repo, fernet=Fernet(Fernet.generate_key()))
    reader = DbSecretStore(repo, fernet=Fernet(Fernet.generate_key()))

    ref = writer.set("user:USER-1", "sk-ant-super-secret")

    assert reader.get(ref) is None


def test_delete_removes_the_secret(tmp_path):
    store = _store(tmp_path)
    ref = store.set("user:USER-1", "sk-ant-super-secret")

    store.delete(ref)

    assert store.get(ref) is None


def test_fernet_from_env_requires_the_env_var(monkeypatch):
    monkeypatch.delenv("KRESHEEN_SECRET_KEY", raising=False)
    from kresheen.secrets.store import _fernet_from_env

    with pytest.raises(RuntimeError, match="KRESHEEN_SECRET_KEY"):
        _fernet_from_env()
