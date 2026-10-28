"""Tests for migration recommendation engine."""

import pytest

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)
from quantumshield.scoring.migration_engine import (
    MigrationRecommendationRegistry,
    MigrationTask,
    generate_migration_recommendation,
    generate_migration_tasks,
)


def make_finding(
    algorithm: str,
    role: CryptoRole,
    *,
    status: FindingStatus = FindingStatus.CONFIRMED,
    confidence: Confidence = Confidence.HIGH,
    finding_id: str = "CRYPTO-001",
    evidence_gap_reason: str | None = None,
):
    """Helper to create a test finding."""
    kwargs = {
        "finding_id": finding_id,
        "algorithm": algorithm,
        "role": role,
        "status": status,
        "evidence": [
            Evidence(
                finding_id=finding_id,
                file_path="test.py",
                line_start=10,
                evidence_type=EvidenceType.API_CALL,
                detection_method=DetectionMethod.REGEX,
                rule_id="TEST-001",
                excerpt="test code",
                confidence=confidence,
            )
        ],
    }
    if status == FindingStatus.UNABLE_TO_ANALYZE:
        kwargs["evidence_gap_reason"] = evidence_gap_reason or "Test finding"

    return CryptoFinding(**kwargs)


def test_registry_loads_successfully():
    """Test that migration recommendation registry loads."""
    registry = MigrationRecommendationRegistry()

    assert registry.version is not None
    assert len(registry.recommendations) > 0
    assert registry.registry_path.exists()


def test_rsa_key_establishment_maps_to_ml_kem():
    """Test that RSA key establishment maps to ML-KEM."""
    finding = make_finding("RSA", CryptoRole.KEY_ESTABLISHMENT)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert "ML-KEM" in rec.target_algorithm
    assert "FIPS 203" in rec.target_standard
    assert rec.action_type == "migrate"
    assert rec.confidence == "high"
    assert len(rec.compatibility_notes) > 0
    assert "drop-in" in rec.compatibility_notes[0].lower()


def test_rsa_signature_maps_to_ml_dsa_or_slh_dsa():
    """Test that RSA signatures map to ML-DSA or SLH-DSA."""
    finding = make_finding("RSA", CryptoRole.SIGNATURE)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert "ML-DSA" in rec.target_algorithm or "SLH-DSA" in rec.target_algorithm
    assert "FIPS 204" in rec.target_standard or "FIPS 205" in rec.target_standard
    assert rec.action_type == "migrate"
    assert len(rec.verification_steps) > 0


def test_ecdh_maps_to_ml_kem():
    """Test that ECDH key exchange maps to ML-KEM."""
    finding = make_finding("ECDH", CryptoRole.KEY_ESTABLISHMENT)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert "ML-KEM" in rec.target_algorithm
    assert "FIPS 203" in rec.target_standard


def test_ecdsa_maps_to_signature_pqc():
    """Test that ECDSA maps to post-quantum signatures."""
    finding = make_finding("ECDSA", CryptoRole.SIGNATURE)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.target_algorithm is not None
    assert rec.source_role == "signature"


def test_aes_symmetric_no_pqc_replacement():
    """Test that AES symmetric encryption doesn't get PQC replacement."""
    finding = make_finding("AES", CryptoRole.SYMMETRIC_ENCRYPTION)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.target_algorithm is None  # No replacement needed
    assert rec.action_type == "review"
    assert "quantum-resistant" in rec.rationale.lower() or "remains" in rec.rationale.lower()


def test_sha256_no_action_needed():
    """Test that strong hashes don't need action."""
    finding = make_finding("SHA-256", CryptoRole.HASH)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.target_algorithm is None
    assert rec.action_type == "no-action-needed"


def test_md5_urgent_classical_weakness():
    """Test that MD5 is flagged as urgent classical weakness."""
    finding = make_finding("MD5", CryptoRole.HASH)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.target_algorithm is not None
    assert "SHA" in rec.target_algorithm
    assert rec.action_type == "urgent-classical"
    assert "classical" in rec.rationale.lower()


def test_sha1_urgent_classical_weakness():
    """Test that SHA-1 is flagged as urgent classical weakness."""
    finding = make_finding("SHA-1", CryptoRole.HASH)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.action_type == "urgent-classical"
    assert "broken" in rec.rationale.lower() or "classical" in rec.rationale.lower()


def test_undetermined_role_requires_manual_review():
    """Test that undetermined roles get manual review recommendation."""
    finding = make_finding("RSA", CryptoRole.UNDETERMINED)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.action_type == "manual-review"
    assert rec.target_algorithm is None
    assert "manual review" in rec.rationale.lower() or "undetermined" in rec.rationale.lower()


def test_library_findings_require_manual_review_investigation():
    """Library-only evidence is investigation-worthy, not an auto-migration."""
    finding = make_finding("library:cryptography", CryptoRole.UNDETERMINED)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.recommendation_id == "REC-099"
    assert rec.action_type == "manual-review"
    assert rec.category == "INVESTIGATION"
    assert rec.target_algorithm is None
    assert rec.target_standard is None


def test_unable_to_analyze_findings_require_manual_review():
    """Unanalyzed findings stay honest and request investigation rather than a fabricated migration."""
    finding = make_finding(
        "UNKNOWN",
        CryptoRole.UNDETERMINED,
        status=FindingStatus.UNABLE_TO_ANALYZE,
    )
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert rec.recommendation_id == "REC-099"
    assert rec.action_type == "manual-review"
    assert rec.target_algorithm is None


def test_ml_kem_not_recommended_for_signatures():
    """Test that ML-KEM is never recommended for signature use."""
    finding = make_finding("RSA", CryptoRole.SIGNATURE)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    # Should recommend ML-DSA or SLH-DSA, not ML-KEM
    assert "ML-KEM" not in (rec.target_algorithm or "")


def test_generate_migration_tasks_creates_ordered_list():
    """Test that migration tasks are generated and ordered."""
    findings = [
        make_finding("MD5", CryptoRole.HASH, finding_id="CRYPTO-001"),  # Urgent
        make_finding("RSA", CryptoRole.KEY_ESTABLISHMENT, finding_id="CRYPTO-002"),  # High
        make_finding("SHA-256", CryptoRole.HASH, finding_id="CRYPTO-003"),  # Low priority
    ]

    tasks = generate_migration_tasks(findings)

    assert len(tasks) == 3

    # Tasks should be ordered by priority
    # MD5 (urgent classical) should be first
    assert tasks[0].source_algorithm == "MD5"
    assert tasks[0].priority <= 15

    # RSA key-establishment should be high priority
    rsa_task = next(t for t in tasks if t.source_algorithm == "RSA")
    assert rsa_task.priority <= 35

    # Each task should have required fields
    for task in tasks:
        assert task.task_id.startswith("TASK-")
        assert task.source_algorithm is not None
        assert task.rationale is not None


def test_task_priority_ordering():
    """Test that task priorities follow expected rules."""
    findings = [
        make_finding("RSA", CryptoRole.SIGNATURE, finding_id="CRYPTO-001"),
        make_finding("RSA", CryptoRole.KEY_ESTABLISHMENT, finding_id="CRYPTO-002"),
        make_finding("SHA-1", CryptoRole.HASH, finding_id="CRYPTO-003"),
        make_finding("AES", CryptoRole.SYMMETRIC_ENCRYPTION, finding_id="CRYPTO-004"),
    ]

    tasks = generate_migration_tasks(findings)

    # SHA-1 (urgent classical) should have lowest priority number
    sha1_task = next(t for t in tasks if t.source_algorithm == "SHA-1")
    assert sha1_task.priority <= 15

    # RSA signature should come before RSA key-establishment
    sig_task = next(t for t in tasks if t.source_role == "signature")
    ke_task = next(t for t in tasks if t.source_role == "key-establishment")
    assert sig_task.priority < ke_task.priority


def test_low_confidence_findings_lower_priority():
    """Test that low-confidence findings get lower priority."""
    high_conf = make_finding(
        "RSA",
        CryptoRole.KEY_ESTABLISHMENT,
        confidence=Confidence.HIGH,
        finding_id="CRYPTO-001",
    )
    # Low confidence findings should be POTENTIAL, not CONFIRMED
    low_conf = make_finding(
        "RSA",
        CryptoRole.KEY_ESTABLISHMENT,
        status=FindingStatus.POTENTIAL,
        confidence=Confidence.LOW,
        finding_id="CRYPTO-002",
    )

    tasks = generate_migration_tasks([high_conf, low_conf])

    high_task = next(t for t in tasks if t.finding_id == "CRYPTO-001")
    low_task = next(t for t in tasks if t.finding_id == "CRYPTO-002")

    # Low confidence must be lower priority and routed to review, not auto-migration.
    assert low_task.priority > high_task.priority
    assert low_task.action_type == "manual-review"
    assert low_task.confidence == "low"


def test_recommendation_includes_verification_steps():
    """Test that recommendations include verification steps."""
    finding = make_finding("RSA", CryptoRole.KEY_ESTABLISHMENT)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert len(rec.verification_steps) > 0
    assert all(isinstance(step, str) for step in rec.verification_steps)


def test_recommendation_includes_prerequisites():
    """Test that recommendations include prerequisites."""
    finding = make_finding("ECDH", CryptoRole.KEY_ESTABLISHMENT)
    rec = generate_migration_recommendation(finding)

    assert rec is not None
    assert len(rec.prerequisites) > 0


def test_task_json_serializable_structure():
    """Test that tasks have structure suitable for JSON serialization."""
    finding = make_finding("RSA", CryptoRole.SIGNATURE)
    tasks = generate_migration_tasks([finding])

    assert len(tasks) == 1
    task = tasks[0]

    # All key fields should be simple types
    assert isinstance(task.task_id, str)
    assert isinstance(task.priority, int)
    assert isinstance(task.rationale, str)
    assert isinstance(task.compatibility_notes, list)
    assert isinstance(task.prerequisites, list)
    assert isinstance(task.verification_steps, list)


# --------------------------------------------------------------------------
# Summary / by_action regression tests (Week 6 Track 2 checklist item 2)
# --------------------------------------------------------------------------


def test_tasks_carry_explicit_action_type_from_recommendation():
    """Each task preserves the recommendation's explicit action_type."""
    cases = [
        ("MD5", CryptoRole.HASH, "urgent-classical"),
        ("RSA", CryptoRole.KEY_ESTABLISHMENT, "migrate"),
        ("ECDH", CryptoRole.KEY_ESTABLISHMENT, "migrate"),
        ("AES", CryptoRole.SYMMETRIC_ENCRYPTION, "review"),
        ("SHA-256", CryptoRole.HASH, "no-action-needed"),
        ("RSA", CryptoRole.UNDETERMINED, "manual-review"),
    ]
    for algorithm, role, expected_action in cases:
        finding = make_finding(algorithm, role, finding_id=f"CRYPTO-{hash(algorithm) % 1000:03d}")
        tasks = generate_migration_tasks([finding])
        assert len(tasks) == 1, f"expected a task for {algorithm}/{role}"
        assert tasks[0].action_type == expected_action, (
            f"{algorithm}/{role}: expected action_type={expected_action}, got {tasks[0].action_type}"
        )


def test_count_by_action_uses_explicit_action_type():
    """_count_by_action must use the explicit action_type, not priority inference."""
    from quantumshield.scoring.migration_plan_writer import _count_by_action

    tasks = [
        MigrationTask(
            task_id="TASK-001", finding_id="F-1", affected_component="c.py",
            source_algorithm="MD5", source_role="hash", source_location="c.py:1",
            recommended_algorithm="SHA-256", recommendation_standard=None,
            rationale="classical weakness", effort_band="small", priority=10,
            confidence="high", action_type="urgent-classical",
        ),
        MigrationTask(
            task_id="TASK-002", finding_id="F-2", affected_component="c.py",
            source_algorithm="RSA", source_role="key-establishment", source_location="c.py:2",
            recommended_algorithm="ML-KEM", recommendation_standard="FIPS 203",
            rationale="shor vulnerable", effort_band="large", priority=30,
            confidence="high", action_type="migrate",
        ),
        MigrationTask(
            task_id="TASK-003", finding_id="F-3", affected_component="c.py",
            source_algorithm="AES", source_role="symmetric-encryption", source_location="c.py:3",
            recommended_algorithm=None, recommendation_standard=None,
            rationale="quantum-safe", effort_band="small", priority=40,
            confidence="high", action_type="review",
        ),
        MigrationTask(
            task_id="TASK-004", finding_id="F-4", affected_component="c.py",
            source_algorithm="RSA", source_role="undetermined", source_location="c.py:4",
            recommended_algorithm=None, recommendation_standard=None,
            rationale="undetermined role", effort_band=None, priority=50,
            confidence="low", action_type="manual-review",
        ),
        MigrationTask(
            task_id="TASK-005", finding_id="F-5", affected_component="c.py",
            source_algorithm="SHA-256", source_role="hash", source_location="c.py:5",
            recommended_algorithm=None, recommendation_standard=None,
            rationale="no action needed", effort_band=None, priority=100,
            confidence="high", action_type="no-action-needed",
        ),
    ]

    counts = _count_by_action(tasks)

    assert counts == {
        "urgent-classical": 1,
        "migrate": 1,
        "review": 1,
        "manual-review": 1,
        "no-action-needed": 1,
    }
    # Per-action counts must sum to the total number of tasks.
    assert sum(counts.values()) == len(tasks) == 5


def test_count_by_action_sums_to_total_for_generated_tasks():
    """For a real set of generated tasks, per-action counts sum to total_tasks."""
    findings = [
        make_finding("MD5", CryptoRole.HASH, finding_id="CRYPTO-001"),  # urgent-classical
        make_finding("SHA-1", CryptoRole.HASH, finding_id="CRYPTO-002"),  # urgent-classical
        make_finding("RSA", CryptoRole.KEY_ESTABLISHMENT, finding_id="CRYPTO-003"),  # migrate
        make_finding("ECDH", CryptoRole.KEY_ESTABLISHMENT, finding_id="CRYPTO-004"),  # migrate
        make_finding("AES", CryptoRole.SYMMETRIC_ENCRYPTION, finding_id="CRYPTO-005"),  # review
        make_finding("SHA-256", CryptoRole.HASH, finding_id="CRYPTO-006"),  # no-action-needed
        make_finding("RSA", CryptoRole.UNDETERMINED, finding_id="CRYPTO-007"),  # manual-review
    ]
    tasks = generate_migration_tasks(findings)

    from quantumshield.scoring.migration_plan_writer import _count_by_action
    counts = _count_by_action(tasks)

    assert sum(counts.values()) == len(tasks) == 7
    assert counts.get("urgent-classical", 0) == 2
    assert counts.get("migrate", 0) == 2
    assert counts.get("review", 0) == 1
    assert counts.get("no-action-needed", 0) == 1
    assert counts.get("manual-review", 0) == 1


def test_build_migration_plan_summary_by_action_matches_tasks():
    """End-to-end: build_migration_plan summary by_action reflects task action_types."""
    from datetime import datetime, timezone
    from quantumshield.scoring.migration_plan_writer import build_migration_plan
    from quantumshield.common.models import (
        AssessmentResult, ProjectContext, CoverageReport, FileRecord, FileOutcome,
    )

    findings = [
        make_finding("MD5", CryptoRole.HASH, finding_id="CRYPTO-001"),
        make_finding("RSA", CryptoRole.SIGNATURE, finding_id="CRYPTO-002"),
        make_finding("AES", CryptoRole.SYMMETRIC_ENCRYPTION, finding_id="CRYPTO-003"),
        make_finding("SHA-256", CryptoRole.HASH, finding_id="CRYPTO-004"),
        make_finding("RSA", CryptoRole.UNDETERMINED, finding_id="CRYPTO-005"),
    ]

    coverage = CoverageReport(
        files_discovered=1, files_eligible=1, files_analyzed=1,
        files_partial=0, files_failed=0, files_unsupported=0,
        files_skipped=0, file_coverage_percent=100.0,
        files=[FileRecord(path="c.py", outcome=FileOutcome.ANALYZED)],
    )

    assessment = AssessmentResult(
        assessment_id="test-assessment",
        scan_timestamp=datetime.now(timezone.utc),
        target="test-target",
        policy_version="1.0",
        project_context=ProjectContext(),
        coverage=coverage,
        findings=findings,
    )

    plan = build_migration_plan(assessment, plan_id="test-plan-id")

    by_action = plan["summary"]["by_action"]
    assert sum(by_action.values()) == plan["summary"]["total_tasks"] == len(findings)
    assert by_action.get("urgent-classical", 0) >= 1  # MD5
    assert by_action.get("migrate", 0) >= 1  # RSA signature
    assert by_action.get("review", 0) >= 1  # AES symmetric
    assert by_action.get("no-action-needed", 0) >= 1  # SHA-256
    assert by_action.get("manual-review", 0) >= 1  # RSA undetermined


def test_registry_rejects_dependency_cycles(tmp_path):
    """Invalid dependency cycles fail at registry load instead of reaching planning."""
    registry_file = tmp_path / "cyclic.yaml"
    registry_file.write_text(
        "version: 'test'\n"
        "recommendations:\n"
        "  - id: REC-A\n    source_algorithms: ['RSA']\n    source_roles: ['signature']\n    depends_on: ['REC-B']\n"
        "  - id: REC-B\n    source_algorithms: ['ECDSA']\n    source_roles: ['signature']\n    depends_on: ['REC-A']\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="dependency cycle"):
        MigrationRecommendationRegistry(registry_file)
