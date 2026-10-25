"""Versioned configuration switching with atomic persistence and audit events."""
from __future__ import annotations
import json, os, tempfile, threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any

@dataclass(frozen=True)
class ConfigVersion:
    version: int
    config: dict[str, Any]
    created_at: str

@dataclass(frozen=True)
class AuditEvent:
    action: str
    version: int
    timestamp: str
    outcome: str
    detail: str = ""

class RollbackError(RuntimeError): pass

class RollbackManager:
    """Keep immutable config snapshots; only promote a candidate after health passes."""
    def __init__(self, initial_config: dict[str, Any], *, storage_path: str | Path | None = None,
                 health_check: Callable[[dict[str, Any]], bool] | None = None):
        self._lock = threading.RLock()
        self.storage_path = Path(storage_path) if storage_path else None
        self.health_check = health_check or (lambda _config: True)
        self._versions: list[ConfigVersion] = [ConfigVersion(1, _copy_json(initial_config), _now())]
        self._active = 1
        self._audit: list[AuditEvent] = [AuditEvent("initialize", 1, _now(), "success")]
        if self.storage_path and self.storage_path.is_file():
            self._load_persisted()
        elif self.storage_path:
            self._persist()

    @property
    def active_version(self) -> int: return self._active
    @property
    def active_config(self) -> dict[str, Any]: return _copy_json(self._get(self._active).config)
    @property
    def versions(self) -> tuple[ConfigVersion, ...]: return tuple(self._versions)
    @property
    def audit_log(self) -> tuple[AuditEvent, ...]: return tuple(self._audit)

    def switch(self, config: dict[str, Any]) -> ConfigVersion:
        candidate = _copy_json(config)
        with self._lock:
            next_version = max(v.version for v in self._versions) + 1
            if not self.health_check(_copy_json(candidate)):
                self._audit.append(AuditEvent("switch", next_version, _now(), "rejected", "health check failed"))
                self._persist()
                raise RollbackError("candidate config failed health check; active config unchanged")
            snapshot = ConfigVersion(next_version, candidate, _now())
            previous_active = self._active
            self._versions.append(snapshot)
            self._active = next_version
            try: self._persist()
            except Exception:
                self._versions.pop(); self._active = previous_active
                self._audit.append(AuditEvent("switch", next_version, _now(), "failed", "persistence failed"))
                raise
            self._audit.append(AuditEvent("switch", next_version, _now(), "success"))
            self._persist()
            return snapshot

    def rollback(self, version: int | None = None) -> ConfigVersion:
        with self._lock:
            target = version if version is not None else self._previous_version()
            if target == self._active: raise RollbackError("requested version is already active")
            snapshot = self._get(target)
            if not self.health_check(_copy_json(snapshot.config)):
                self._audit.append(AuditEvent("rollback", target, _now(), "rejected", "health check failed")); self._persist()
                raise RollbackError("target config failed health check; active config unchanged")
            prior = self._active; self._active = target
            try: self._persist()
            except Exception:
                self._active = prior; raise
            self._audit.append(AuditEvent("rollback", target, _now(), "success", f"from version {prior}")); self._persist()
            return snapshot

    def _previous_version(self) -> int:
        choices = [v.version for v in self._versions if v.version != self._active]
        if not choices: raise RollbackError("no previous config version")
        return max(choices)
    def _get(self, version: int) -> ConfigVersion:
        for item in self._versions:
            if item.version == version: return item
        raise RollbackError(f"unknown config version {version}")
    def _load_persisted(self) -> None:
        try:
            payload = json.loads(self.storage_path.read_text(encoding="utf-8"))
            versions = [ConfigVersion(**item) for item in payload["versions"]]
            audit = [AuditEvent(**item) for item in payload["audit_log"]]
            active = int(payload["active_version"])
            if not versions or active not in {item.version for item in versions}:
                raise ValueError("active version does not resolve")
            self._versions, self._audit, self._active = versions, audit, active
        except Exception as exc:
            raise RollbackError(f"persisted rollback state is invalid: {self.storage_path}") from exc

    def _persist(self) -> None:
        if not self.storage_path: return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"active_version": self._active, "versions": [asdict(v) for v in self._versions], "audit_log": [asdict(e) for e in self._audit]}
        fd, temp = tempfile.mkstemp(prefix=f".{self.storage_path.name}.", dir=self.storage_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp, self.storage_path)
        finally:
            if os.path.exists(temp): os.unlink(temp)

def _copy_json(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))
def _now() -> str: return datetime.now(timezone.utc).isoformat()
