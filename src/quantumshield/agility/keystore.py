"""Demo-grade file keystore. Never logs or exposes secret material in representations."""
from __future__ import annotations
import base64, json, os, secrets, tempfile, logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_LOG = logging.getLogger(__name__)

class KeystoreError(RuntimeError): pass
class KeyNotFoundError(KeystoreError): pass

@dataclass(frozen=True, repr=False)
class KeyRecord:
    key_id: str
    algorithm: str
    status: str
    created_at: str
    key_material: bytes
    def __repr__(self) -> str: return f"KeyRecord(key_id={self.key_id!r}, algorithm={self.algorithm!r}, status={self.status!r}, key_material=<redacted>)"

class FileKeystore:
    """Local demo storage (0600 on POSIX); use an HSM/KMS for production."""
    def __init__(self, path: str | Path, *, passphrase: str | None = None):
        self.path = Path(path); self.passphrase = passphrase
        if passphrase is not None and not passphrase: raise ValueError("passphrase must not be empty")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, KeyRecord] = {}
        if self.path.exists(): self._load()

    def add(self, algorithm: str, key_material: bytes, *, key_id: str | None = None, status: str = "active") -> KeyRecord:
        if not isinstance(key_material, bytes) or not key_material: raise ValueError("key_material must be non-empty bytes")
        if status not in {"active", "retiring", "revoked"}: raise ValueError("invalid key status")
        key_id = key_id or secrets.token_hex(12)
        if key_id in self._records: raise KeystoreError(f"key id already exists: {key_id}")
        rec = KeyRecord(key_id, algorithm, status, _now(), bytes(key_material)); self._records[key_id] = rec
        try: self._save()
        except Exception: self._records.pop(key_id, None); raise
        _LOG.info("Stored key metadata: key_id=%s algorithm=%s status=%s", key_id, algorithm, status)
        return rec

    def get(self, key_id: str) -> KeyRecord:
        try: return self._records[key_id]
        except KeyError as exc: raise KeyNotFoundError(f"key not found: {key_id}") from exc

    def list_keys(self) -> list[dict[str, str]]:
        return [{"key_id": r.key_id, "algorithm": r.algorithm, "status": r.status, "created_at": r.created_at} for r in self._records.values()]

    def set_status(self, key_id: str, status: str) -> KeyRecord:
        if status not in {"active", "retiring", "revoked"}: raise ValueError("invalid key status")
        old = self.get(key_id); self._records[key_id] = KeyRecord(old.key_id, old.algorithm, status, old.created_at, old.key_material)
        try: self._save()
        except Exception: self._records[key_id] = old; raise
        _LOG.info("Updated key metadata: key_id=%s status=%s", key_id, status)
        return self._records[key_id]

    def rotate(self, key_id: str, new_material: bytes) -> KeyRecord:
        old = self.get(key_id)
        if old.status != "active": raise KeystoreError("only an active key can be rotated")
        self.set_status(key_id, "retiring")
        try: return self.add(old.algorithm, new_material)
        except Exception:
            self.set_status(key_id, "active"); raise

    def revoke(self, key_id: str) -> KeyRecord: return self.set_status(key_id, "revoked")

    def _save(self) -> None:
        records = [{"key_id": r.key_id, "algorithm": r.algorithm, "status": r.status, "created_at": r.created_at, "key_material": base64.b64encode(r.key_material).decode("ascii")} for r in self._records.values()]
        raw = json.dumps({"version": 1, "records": records}, sort_keys=True).encode()
        if self.passphrase is not None:
            salt, nonce = os.urandom(16), os.urandom(12)
            key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(self.passphrase.encode())
            raw = json.dumps({"encrypted": True, "salt": _b64(salt), "nonce": _b64(nonce), "ciphertext": _b64(AESGCM(key).encrypt(nonce, raw, b"quantumshield-keystore-v1"))}).encode()
        _atomic_write(self.path, raw, 0o600)

    def _load(self) -> None:
        try: payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc: raise KeystoreError("keystore file is invalid") from exc
        if payload.get("encrypted"):
            if self.passphrase is None: raise KeystoreError("keystore is encrypted; passphrase required")
            try:
                salt, nonce = _unb64(payload["salt"]), _unb64(payload["nonce"])
                key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(self.passphrase.encode())
                raw = AESGCM(key).decrypt(nonce, _unb64(payload["ciphertext"]), b"quantumshield-keystore-v1")
                payload = json.loads(raw)
            except Exception as exc: raise KeystoreError("cannot decrypt keystore (wrong passphrase or damaged file)") from exc
        try:
            for item in payload["records"]:
                r = KeyRecord(item["key_id"], item["algorithm"], item["status"], item["created_at"], base64.b64decode(item["key_material"], validate=True))
                if r.status not in {"active", "retiring", "revoked"}: raise ValueError("invalid status")
                self._records[r.key_id] = r
        except Exception as exc: raise KeystoreError("keystore contents are invalid") from exc
        if os.name == "posix": self.path.chmod(0o600)

def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name == "posix": os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)
        if os.name == "posix": path.chmod(mode)
    finally:
        if os.path.exists(temp): os.unlink(temp)
def _b64(v: bytes) -> str: return base64.b64encode(v).decode("ascii")
def _unb64(v: str) -> bytes: return base64.b64decode(v, validate=True)
def _now() -> str: return datetime.now(timezone.utc).isoformat()
