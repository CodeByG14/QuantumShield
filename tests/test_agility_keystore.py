import logging, os
import pytest
from quantumshield.agility.keystore import FileKeystore, KeystoreError


def test_crud_status_rotation_and_permissions(tmp_path):
    path = tmp_path / "keys.json"
    store = FileKeystore(path)
    record = store.add("ML-KEM-768", b"private-key-material", key_id="key-a")
    assert store.get("key-a").key_material == b"private-key-material"
    assert store.list_keys()[0]["status"] == "active"
    rotated = store.rotate("key-a", b"new-private-material")
    assert store.get("key-a").status == "retiring"
    assert rotated.key_id != "key-a"
    store.revoke(rotated.key_id)
    assert store.get(rotated.key_id).status == "revoked"
    if os.name == "posix": assert path.stat().st_mode & 0o777 == 0o600


def test_encrypted_round_trip_and_wrong_passphrase(tmp_path):
    path = tmp_path / "encrypted.json"
    FileKeystore(path, passphrase="correct horse battery staple").add("ML-KEM-768", b"secret", key_id="a")
    with pytest.raises(KeystoreError, match="passphrase required"):
        FileKeystore(path)
    assert FileKeystore(path, passphrase="correct horse battery staple").get("a").key_material == b"secret"
    with pytest.raises(KeystoreError, match="cannot decrypt"):
        FileKeystore(path, passphrase="wrong")


def test_logs_and_repr_never_include_key_material(tmp_path, caplog):
    secret = b"DO_NOT_LOG_THIS_PRIVATE_KEY"
    with caplog.at_level(logging.INFO):
        record = FileKeystore(tmp_path / "k.json").add("ML-KEM-768", secret, key_id="safe-id")
    assert secret.decode() not in caplog.text
    assert secret.decode() not in repr(record)
    assert "key_material=<redacted>" in repr(record)
