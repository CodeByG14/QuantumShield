"""Rootfs library inventory integration in migration planning and CBOM output."""

from datetime import datetime, timezone

from common.models import (
    Confidence, CoverageReport, CryptoFinding, CryptoRole, DetectionMethod,
    Evidence, EvidenceType, FileOutcome, FileRecord, FindingStatus,
    ProjectContext, ScanResult, AssessmentResult,
)
from discovery.cbom_writer import scan_result_to_cbom
from scoring.migration_plan_writer import build_migration_plan


def coverage(path="rootfs/usr/lib/libssl.so.3"):
    return CoverageReport(
        files_discovered=1, files_eligible=1, files_analyzed=1,
        files_partial=0, files_failed=0, files_unsupported=0,
        files_skipped=0, file_coverage_percent=100.0,
        files=[FileRecord(path=path, outcome=FileOutcome.ANALYZED)],
    )


def rootfs_finding(capability="no", version="3.4.2-1"):
    fid = "CRYPTO-002"
    metadata = {
        "inventory_source": "rootfs",
        "library_name": "openssl",
        "library_version": version,
        "pqc_capability": capability,
        "pqc_capability_reason": "test fixture capability reason",
        "pqc_capability_source": "https://example.test/source",
        "release_track": "regular",
    }
    return CryptoFinding(
        finding_id=fid,
        algorithm="library:openssl",
        variant=f"OpenSSL {version}",
        role=CryptoRole.UNDETERMINED,
        status=FindingStatus.POTENTIAL,
        evidence=[Evidence(
            finding_id=fid,
            file_path="rootfs/usr/lib/libssl.so.3",
            evidence_type=EvidenceType.FILE_EXTENSION,
            detection_method=DetectionMethod.FILE_EXTENSION,
            rule_id="ROOTFS-OPENSSL-FILENAME",
            excerpt="Recognized cryptographic library filename: libssl.so.3",
            confidence=Confidence.MEDIUM,
            metadata=metadata,
        )],
    )


def rsa_finding():
    fid = "CRYPTO-001"
    return CryptoFinding(
        finding_id=fid,
        algorithm="RSA",
        role=CryptoRole.KEY_ESTABLISHMENT,
        status=FindingStatus.CONFIRMED,
        evidence=[Evidence(
            finding_id=fid,
            file_path="app.py",
            line_start=4,
            evidence_type=EvidenceType.API_CALL,
            detection_method=DetectionMethod.REGEX,
            rule_id="TEST-RSA-001",
            excerpt="RSA key establishment",
            confidence=Confidence.HIGH,
        )],
    )


def test_rootfs_library_becomes_migration_prerequisite():
    classical = rsa_finding()
    library = rootfs_finding(capability="no")
    assessment = AssessmentResult(
        assessment_id="rootfs-plan-test",
        scan_timestamp=datetime.now(timezone.utc),
        target="test-app",
        policy_version="1.0",
        project_context=ProjectContext(project_name="rootfs-plan-test"),
        coverage=coverage("app.py"),
        rootfs_coverage=coverage(),
        findings=[classical, library],
    )

    plan = build_migration_plan(assessment, plan_id="rootfs-plan-test")
    task = next(task for task in plan["tasks"] if task["source"]["algorithm"] == "RSA")
    assert any("upgrading or replacing" in item.lower() for item in task["prerequisites"])
    assert plan["metadata"]["rootfs_inventory"]["scanned"] is True
    assert plan["metadata"]["rootfs_inventory"]["pqc_capability_counts"]["no"] == 1
    assert plan["metadata"]["rootfs_inventory"]["library_findings"][0]["library"] == "openssl"


def test_rootfs_library_is_exported_as_generic_library_in_cbom():
    library = rootfs_finding(capability="unknown", version="unknown")
    cbom = scan_result_to_cbom(
        ScanResult(findings=[library], coverage=coverage(), rootfs_coverage=coverage()),
        "test-app",
    )
    component = cbom["components"][0]
    assert component["type"] == "library"
    assert component["name"] == "openssl"
    assert component["purl"] == "pkg:generic/openssl"
    props = {item["name"]: item["value"] for item in component["properties"]}
    assert props["quantumshield:pqc-capability"] == "unknown"
    assert props["quantumshield:inventory-source"] == "rootfs"
