"""Tests for bounded inventory of an already-extracted root filesystem."""

from __future__ import annotations

import os

import pytest

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FileOutcome,
    FindingStatus,
    ProjectContext,
    StageStatus,
    CoverageReport,
    FileRecord,
)
from quantumshield.discovery.pipeline import run_scan
from quantumshield.discovery.rootfs_scanner import RootFSScanError, scan_rootfs
from quantumshield.scoring.assessment_writer import build_assessment


def write_file(root, relative, content=b""):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        content = content.encode("utf-8")
    path.write_bytes(content)
    return path


def by_library(findings):
    return {finding.algorithm: finding for finding in findings}


def installed_dpkg(*packages):
    sections = []
    for package, version in packages:
        sections.append(
            f"Package: {package}\nStatus: install ok installed\nVersion: {version}\nArchitecture: amd64\n"
        )
    return "\n".join(sections)


def test_detects_supported_library_families_from_filenames(tmp_path):
    root = tmp_path / "rootfs"
    for name in (
        "usr/lib/libssl.so.3",
        "usr/lib/libcrypto.so.3",
        "usr/lib/libgnutls.so.30",
        "usr/lib/libgcrypt.so.20",
        "usr/lib/libnss3.so",
        "usr/share/java/bcprov-jdk18on-1.79.jar",
    ):
        write_file(root, name)

    findings, coverage = scan_rootfs(root)
    got = by_library(findings)
    assert set(got) == {
        "library:openssl", "library:gnutls", "library:libgcrypt",
        "library:nss", "library:bouncycastle",
    }
    assert got["library:bouncycastle"].evidence[0].metadata["pqc_capability"] == "yes"
    assert all(f.status == FindingStatus.POTENTIAL for f in findings)
    assert all(f.role == CryptoRole.UNDETERMINED for f in findings)
    assert coverage.files_discovered == 6
    assert coverage.files_analyzed == 6
    assert all(e.file_path.startswith("rootfs/") for f in findings for e in f.evidence)


def test_dpkg_metadata_resolves_native_versions_and_capability(tmp_path):
    root = tmp_path / "rootfs"
    for name in (
        "usr/lib/libssl.so.3", "usr/lib/libgnutls.so.30",
        "usr/lib/libgcrypt.so.20", "usr/lib/libnss3.so",
    ):
        write_file(root, name)
    write_file(
        root,
        "var/lib/dpkg/status",
        installed_dpkg(
            ("libssl3", "3.5.0-1"),
            ("libgnutls30", "3.8.9-1"),
            ("libgcrypt20", "1.12.0-1"),
            ("libnss3", "3.128.0-1"),
        ),
    )

    findings, coverage = scan_rootfs(root)
    got = by_library(findings)
    expected = {
        "library:openssl": ("3.5.0-1", "yes"),
        "library:gnutls": ("3.8.9-1", "unknown"),
        "library:libgcrypt": ("1.12.0-1", "yes"),
        "library:nss": ("3.128.0-1", "yes"),
    }
    for algorithm, (version, capability) in expected.items():
        finding = got[algorithm]
        assert finding.variant is not None and version in finding.variant
        assert {e.metadata["pqc_capability"] for e in finding.evidence} == {capability}
        assert all(e.metadata["pqc_capability_source"].startswith("https://") for e in finding.evidence)
    assert any(e.file_path == "rootfs/usr/lib/libssl.so.3" for e in got["library:openssl"].evidence)
    assert any(e.file_path == "rootfs/var/lib/dpkg/status" for e in got["library:openssl"].evidence)
    assert "rootfs-package-metadata" in coverage.stage_counts


def test_apk_database_metadata_is_supported(tmp_path):
    root = tmp_path / "rootfs"
    write_file(root, "lib/apk/db/installed", "P:openssl\nV:3.5.1-r0\n\nP:libgnutls\nV:3.8.8-r1\n")
    findings, _ = scan_rootfs(root)
    got = by_library(findings)
    assert got["library:openssl"].evidence[0].metadata["pqc_capability"] == "yes"
    assert got["library:gnutls"].evidence[0].metadata["pqc_capability"] == "unknown"


def test_version_table_is_conservative_for_known_thresholds(tmp_path):
    root = tmp_path / "rootfs"
    write_file(root, "usr/lib/libssl.so.3")
    write_file(root, "usr/lib/libgcrypt.so.20")
    write_file(root, "usr/lib/libnss3.so")
    write_file(root, "usr/share/java/bcprov-jdk18on-1.78.1.jar")
    write_file(root, "var/lib/dpkg/status", installed_dpkg(
        ("libssl3", "3.4.2-1"),
        ("libgcrypt20", "1.11.3-1"),
        ("libnss3", "3.120.0-1"),
    ))
    findings, _ = scan_rootfs(root)
    got = by_library(findings)
    assert {e.metadata["pqc_capability"] for e in got["library:openssl"].evidence} == {"no"}
    assert {e.metadata["pqc_capability"] for e in got["library:libgcrypt"].evidence} == {"unknown"}
    assert {e.metadata["pqc_capability"] for e in got["library:nss"].evidence} == {"unknown"}
    assert got["library:bouncycastle"].evidence[0].metadata["pqc_capability"] == "no"


def test_skips_virtual_filesystem_directories(tmp_path):
    root = tmp_path / "rootfs"
    write_file(root, "proc/libssl.so.9")
    write_file(root, "sys/libcrypto.so.9")
    write_file(root, "dev/libssl.so.8")
    write_file(root, "usr/lib/libgnutls.so.30")

    findings, coverage = scan_rootfs(root)
    assert set(by_library(findings)) == {"library:gnutls"}
    paths = {record.path: record for record in coverage.files}
    for directory in ("rootfs/proc", "rootfs/sys", "rootfs/dev"):
        assert paths[directory].outcome == FileOutcome.SKIPPED
    assert not any("/proc/" in p or "/sys/" in p or "/dev/" in p for f in findings for p in [e.file_path for e in f.evidence])


def test_symlinks_are_not_followed_outside_root(tmp_path):
    root = tmp_path / "rootfs"
    secret = write_file(tmp_path, "outside/libssl.so.9")
    link = root / "usr/lib/libssl.so.9"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    findings, coverage = scan_rootfs(root)
    assert findings == []
    record = next(record for record in coverage.files if record.path == "rootfs/usr/lib/libssl.so.9")
    assert record.outcome == FileOutcome.SKIPPED
    assert "symbolic link not followed" in record.reason


def test_symlinked_directories_are_not_followed(tmp_path):
    root = tmp_path / "rootfs"
    outside = tmp_path / "outside"
    write_file(outside, "lib/libssl.so.3")
    linkdir = root / "usr/lib/external"
    linkdir.parent.mkdir(parents=True)
    try:
        linkdir.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    findings, coverage = scan_rootfs(root)
    assert findings == []
    record = next(record for record in coverage.files if record.path == "rootfs/usr/lib/external")
    assert record.outcome == FileOutcome.SKIPPED


def test_metadata_size_cap_is_enforced(tmp_path):
    root = tmp_path / "rootfs"
    write_file(root, "var/lib/dpkg/status", installed_dpkg(("libssl3", "3.5.0-1")) + ("x" * 100))
    findings, coverage = scan_rootfs(root, max_metadata_bytes=32)
    assert findings == []
    record = next(record for record in coverage.files if record.path == "rootfs/var/lib/dpkg/status")
    assert record.outcome == FileOutcome.SKIPPED
    assert "larger than 32 bytes" in record.reason


def test_invalid_metadata_is_reported_as_failed_without_crashing(tmp_path):
    root = tmp_path / "rootfs"
    write_file(root, "var/lib/dpkg/status", b"\xff\xfe\xfa")
    findings, coverage = scan_rootfs(root)
    assert findings == []
    record = next(record for record in coverage.files if record.path == "rootfs/var/lib/dpkg/status")
    assert record.outcome == FileOutcome.FAILED
    assert "cannot parse package metadata" in record.reason


def test_invalid_rootfs_inputs_are_rejected(tmp_path):
    with pytest.raises(RootFSScanError, match="not a directory"):
        scan_rootfs(tmp_path / "missing")
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "rootfs-link"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(RootFSScanError, match="not a symlink"):
        scan_rootfs(alias)


def test_pipeline_keeps_rootfs_coverage_separate_and_assessment_preserves_it(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    write_file(project, "app.py", "def main():\n    return 1\n")
    root = tmp_path / "rootfs"
    write_file(root, "usr/lib/libssl.so.3")
    write_file(root, "var/lib/dpkg/status", installed_dpkg(("libssl3", "3.5.0-1")))

    result = run_scan(project, rootfs=root)
    assert result.coverage.files_discovered == 1
    assert result.rootfs_coverage is not None
    assert result.rootfs_coverage.files_discovered == 2
    assert "library:openssl" in by_library(result.findings)

    assessment = build_assessment(
        result, target=project, context=ProjectContext(project_name="rootfs-test"),
        assessment_id="rootfs-assessment",
    )
    assert assessment.rootfs_coverage is not None
    assert any("extracted-rootfs library inventory" in line for line in assessment.limitations)


def test_scan_without_rootfs_has_no_rootfs_coverage(tmp_path):
    write_file(tmp_path, "app.py", "x = 1\n")
    result = run_scan(tmp_path)
    assert result.rootfs_coverage is None


def test_library_filename_detection_avoids_debug_and_source_decoys(tmp_path):
    root = tmp_path / "rootfs"
    for name in (
        "usr/lib/libssl.so.3.debug",
        "usr/lib/not-libssl.so.3",
        "usr/share/java/bcprov-jdk18on-1.79-sources.jar",
    ):
        write_file(root, name)
    findings, _ = scan_rootfs(root)
    assert findings == []


def test_walk_errors_are_counted_as_failed_coverage(tmp_path, monkeypatch):
    from quantumshield.common.models import FileOutcome
    from quantumshield.discovery import rootfs_scanner

    root = tmp_path / "rootfs"
    root.mkdir()

    def walk_with_error(top, *, topdown, onerror, followlinks):
        assert onerror is not None
        onerror(PermissionError(13, "Permission denied", str(root / "blocked")))
        yield str(root), [], []

    monkeypatch.setattr(rootfs_scanner.os, "walk", walk_with_error)
    _, coverage = rootfs_scanner.scan_rootfs(root)

    blocked = [record for record in coverage.files if record.path == "rootfs/blocked"]
    assert len(blocked) == 1
    assert blocked[0].outcome == FileOutcome.FAILED
