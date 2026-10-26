"""
Discovery pipeline: walk a project once, classify every file exactly once,
run the applicable stages, and return findings plus an honest coverage report.

Stages (chosen by file name / extension):
  source    .py .java
  manifest  requirements*.txt, pyproject.toml
  x509      .pem .crt .cer .der .key
Extension-only detection (.p12 .pfx .jks) yields a finding but is recorded as
UNSUPPORTED in coverage, since the contents are never examined.
"""

import os
from pathlib import Path, PurePosixPath
from typing import Any

from quantumshield.common.models import (
    CoverageReport,
    CryptoFinding,
    FileRecord,
    FileStageResult,
    ScanResult,
    StageStatus,
    assign_ids,
)
from quantumshield.discovery.artifact_scanner import detect_artifact
from quantumshield.discovery.manifest_scanner import scan_manifest
from quantumshield.discovery.rules import CompiledRule, load_rules
from quantumshield.discovery.scanner import LANGUAGE_BY_SUFFIX, scan_source
from quantumshield.discovery.stage import StageOutput
from quantumshield.discovery.tls_scanner import scan_tls_endpoints, TLSEndpointResult
from quantumshield.discovery.x509_scanner import scan_x509
from quantumshield.discovery.config_scanner import is_config_candidate, scan_config
from quantumshield.discovery.rootfs_scanner import scan_rootfs

DEFAULT_RULES = Path(__file__).with_name("patterns.yaml")
MAX_FILE_BYTES = 2_000_000
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".idea", ".vscode",
}
X509_SUFFIXES = {".pem", ".crt", ".cer", ".der", ".key"}


def _stages_for(name: str) -> list[str]:
    lower = name.lower()
    suffix = PurePosixPath(lower).suffix
    if suffix in LANGUAGE_BY_SUFFIX:
        return ["source"]
    if lower == "pyproject.toml" or (lower.startswith("requirements") and lower.endswith(".txt")):
        return ["manifest"]
    if suffix in X509_SUFFIXES:
        return ["x509"]
    if is_config_candidate(name):
        return ["config"]
    return []


def _decode(data: bytes) -> tuple[str | None, str | None]:
    try:
        return data.decode("utf-8-sig"), None
    except UnicodeDecodeError as exc:
        return None, f"not valid UTF-8 (byte offset {exc.start})"


def _run_stage(stage: str, data: bytes, rel: str, name: str, rules: list[CompiledRule]) -> StageOutput:
    if stage == "x509":
        return scan_x509(data, rel)
    text, error = _decode(data)
    if error:
        return StageOutput(ok=False, reason=error)
    if stage == "source":
        return scan_source(text, rel, LANGUAGE_BY_SUFFIX[PurePosixPath(name.lower()).suffix], rules)
    if stage == "config":
        return scan_config(text, rel)
    return scan_manifest(text, rel, name.lower())


def _process_file(path: Path, rel: str, rules: list[CompiledRule], max_bytes: int):
    findings: list[CryptoFinding] = detect_artifact(rel)
    stages = _stages_for(path.name)
    if not stages:
        return FileRecord.from_stage_results(rel, []), findings

    results: list[FileStageResult] = []
    try:
        data = path.read_bytes()
    except OSError as exc:
        reason = f"cannot read file: {exc.strerror or type(exc).__name__}"
        results = [FileStageResult(path=rel, stage=s, status=StageStatus.FAILED, reason=reason) for s in stages]
        return FileRecord.from_stage_results(rel, results), findings

    for stage in stages:
        try:
            out = _run_stage(stage, data, rel, path.name, rules)
        except Exception as exc:  # a scanner bug must show up as FAILED, never crash or pass silently
            out = StageOutput(ok=False, reason=f"internal error: {type(exc).__name__}: {exc}")
        findings.extend(out.findings)
        results.append(
            FileStageResult(
                path=rel,
                stage=stage,
                status=StageStatus.SUCCESS if out.ok else StageStatus.FAILED,
                reason=out.reason,
            )
        )
    return FileRecord.from_stage_results(rel, results), findings


def run_scan(
    target: str | Path,
    rules_path: str | Path = DEFAULT_RULES,
    max_file_bytes: int = MAX_FILE_BYTES,
    tls_endpoints: list[tuple[str, int]] | None = None,
    rootfs: str | Path | None = None,
) -> ScanResult:
    root = Path(target)
    if not root.is_dir():
        raise NotADirectoryError(f"scan target is not a directory: {root}")
    rules = load_rules(rules_path)

    records: list[FileRecord] = []
    findings: list[CryptoFinding] = []
    rootfs_coverage: CoverageReport | None = None

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for d in dirnames:
            p = Path(dirpath) / d
            if p.is_symlink():
                rel = p.relative_to(root).as_posix()
                records.append(FileRecord.from_stage_results(rel, [], skip_reason="symlinked directory not followed"))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            skipped_dir = next((part for part in PurePosixPath(rel).parts[:-1] if part in SKIP_DIRS), None)
            if skipped_dir:
                reason = f"excluded by policy (directory: {skipped_dir})"
            elif path.is_symlink():
                reason = "symlink not followed"
            elif path.stat().st_size > max_file_bytes:
                reason = f"larger than {max_file_bytes} bytes"
            else:
                reason = None
            if reason:
                records.append(FileRecord.from_stage_results(rel, [], skip_reason=reason))
                continue
            record, file_findings = _process_file(path, rel, rules, max_file_bytes)
            records.append(record)
            findings.extend(file_findings)

    # Rootfs inventory is a separate coverage scope. It only examines an
    # explicitly supplied, already-extracted directory and never scans live OS
    # paths or follows symlinks.
    if rootfs is not None:
        rootfs_findings, rootfs_coverage = scan_rootfs(
            rootfs, max_metadata_bytes=max_file_bytes
        )
        findings.extend(rootfs_findings)

    # TLS endpoint scanning
    if tls_endpoints:
        tls_results: list[TLSEndpointResult] = scan_tls_endpoints(tls_endpoints)
        for tls_result in tls_results:
            # Add findings from TLS scan
            findings.extend(tls_result.findings)
            # Add coverage record for endpoint
            endpoint_path = f"tls://{tls_result.host}:{tls_result.port}"
            if tls_result.handshake_successful:
                records.append(FileRecord.from_stage_results(
                    endpoint_path,
                    [FileStageResult(path=endpoint_path, stage="tls", status=StageStatus.SUCCESS, reason=None)]
                ))
            else:
                records.append(FileRecord.from_stage_results(
                    endpoint_path,
                    [FileStageResult(path=endpoint_path, stage="tls", status=StageStatus.FAILED, reason=tls_result.error_message)]
                ))

    records.sort(key=lambda r: r.path)
    return ScanResult(
        findings=assign_ids(findings),
        coverage=CoverageReport.from_records(records),
        rootfs_coverage=rootfs_coverage,
    )
