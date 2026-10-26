from __future__ import annotations

import json
import zipfile

import pytest

from quantumshield.api.source_adapters import (
    SourceInputError,
    canonical_github_url,
    extract_zip_safely,
    parse_bom_scan_result,
    safe_upload_name,
)
from quantumshield.source_contracts import ScanInputKind, ScanSourceMetadata


def test_github_repository_url_is_canonicalized():
    url, name = canonical_github_url("https://github.com/example/crypto-demo")
    assert url == "https://github.com/example/crypto-demo.git"
    assert name == "example/crypto-demo"
    assert ScanSourceMetadata(input_kind=ScanInputKind.GITHUB_REPOSITORY, input_name=name, source_reference=url)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/repo",
        "https://notgithub.com/example/repo",
        "https://user:token@github.com/example/repo",
        "https://github.com/example/repo?token=secret",
        "https://github.com/example/repo/tree/main",
        "https://github.com:bad/example/repo",
    ],
)
def test_github_url_rejects_noncanonical_or_credentialed_input(url):
    with pytest.raises(SourceInputError):
        canonical_github_url(url)


def test_upload_filename_never_preserves_directories():
    assert safe_upload_name("../../private/repo.zip") == "repo.zip"
    assert safe_upload_name(None) == "upload.json"


def test_zip_extracts_under_workspace_and_uses_single_root(tmp_path):
    archive_path = tmp_path / "input.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("repo/src/crypto.py", "import hashlib\n")
        archive.writestr("repo/README.md", "example\n")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = extract_zip_safely(archive_path, workspace)
    assert target == workspace / "source" / "repo"
    assert (target / "src/crypto.py").read_text() == "import hashlib\n"


def test_zip_rejects_parent_path_traversal(tmp_path):
    archive_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escaped.txt", "not allowed")
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(SourceInputError, match="traversal"):
        extract_zip_safely(archive_path, workspace)
    assert not (tmp_path / "escaped.txt").exists()


def test_sbom_import_only_reports_recognized_crypto_libraries():
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {"type": "library", "name": "openssl", "version": "3.4.0", "purl": "pkg:generic/openssl@3.4.0"},
            {"type": "library", "name": "example-logging", "version": "2.0"},
        ],
    }
    result, limitations = parse_bom_scan_result(payload, kind=ScanInputKind.SBOM, input_name="inventory.json")
    assert len(result.findings) == 1
    assert result.findings[0].algorithm == "library:openssl"
    assert result.findings[0].status.value == "potential"
    assert result.findings[0].evidence[0].file_path == "inventory.json"
    assert "Package presence does not prove" in result.findings[0].assumptions[0]
    assert result.coverage.files_discovered == 1
    assert not limitations


def test_cbom_import_preserves_qs_status_when_supported():
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "name": "RSA-2048",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": "2048"},
                },
                "properties": [
                    {"name": "quantumshield:role", "value": "key-establishment"},
                    {"name": "quantumshield:status", "value": "confirmed"},
                    {"name": "quantumshield:confidence", "value": "high"},
                    {"name": "quantumshield:rules", "value": "TEST-RSA"},
                ],
            }
        ],
    }
    result, limitations = parse_bom_scan_result(payload, kind=ScanInputKind.CBOM, input_name="crypto-bom.json")
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.algorithm == "RSA"
    assert finding.key_size == 2048
    assert finding.role.value == "key-establishment"
    assert finding.status.value == "confirmed"
    assert finding.confidence.value == "high"
    assert not limitations


def test_unsupported_bom_format_fails_closed():
    with pytest.raises(SourceInputError, match="CycloneDX JSON"):
        parse_bom_scan_result({"spdxVersion": "SPDX-2.3", "packages": []}, kind=ScanInputKind.CBOM, input_name="wrong.json")
