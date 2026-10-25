import json
import pytest
from quantumshield.agility.rollback import RollbackManager, RollbackError


def test_rollback_restores_exact_previous_config(tmp_path):
    path = tmp_path / "versions.json"
    initial = {"algorithm": "ML-KEM-768", "nested": {"enabled": True}}
    manager = RollbackManager(initial, storage_path=path)
    manager.switch({"algorithm": "ML-KEM-1024"})
    manager.rollback()
    assert manager.active_config == initial
    payload = json.loads(path.read_text())
    assert payload["active_version"] == 1
    assert [e["action"] for e in payload["audit_log"]][-1] == "rollback"


def test_failed_health_check_does_not_switch(tmp_path):
    manager = RollbackManager({"algorithm": "A"}, storage_path=tmp_path / "v.json", health_check=lambda c: c["algorithm"] != "BAD")
    with pytest.raises(RollbackError): manager.switch({"algorithm": "BAD"})
    assert manager.active_config == {"algorithm": "A"}
    assert manager.audit_log[-1].outcome == "rejected"


def test_snapshots_are_defensively_copied():
    manager = RollbackManager({"items": [1]})
    result = manager.active_config; result["items"].append(2)
    assert manager.active_config == {"items": [1]}


def test_persisted_versions_are_loaded_for_recovery(tmp_path):
    path = tmp_path / "versions.json"
    manager = RollbackManager({"algorithm": "A"}, storage_path=path)
    manager.switch({"algorithm": "B"})
    restarted = RollbackManager({"algorithm": "ignored-initial"}, storage_path=path)
    assert restarted.active_config == {"algorithm": "B"}
    restarted.rollback()
    assert restarted.active_config == {"algorithm": "A"}
