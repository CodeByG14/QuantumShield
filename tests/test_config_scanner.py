"""Tests for Phase 6A static configuration discovery."""
from __future__ import annotations

from quantumshield.common.models import CryptoRole, FindingStatus
from quantumshield.discovery.config_scanner import is_config_candidate, scan_config
from quantumshield.discovery.pipeline import run_scan


def _metadata(findings):
    return [e.metadata for finding in findings for e in finding.evidence]


def test_nginx_protocols_are_found_with_line_evidence():
    result = scan_config(
        "ssl_protocols TLSv1.2 TLSv1.3;\n",
        "etc/nginx/nginx.conf",
    )
    assert result.ok
    assert {f.variant for f in result.findings} == {"TLSv1.2", "TLSv1.3"}
    assert all(f.algorithm == "TLS" for f in result.findings)
    assert all(f.status == FindingStatus.POTENTIAL for f in result.findings)
    assert all(f.evidence[0].line_start == 1 for f in result.findings)
    assert all(f.evidence[0].metadata["config_family"] == "nginx" for f in result.findings)


def test_apache_cipher_suite_is_decomposed_into_roles():
    result = scan_config(
        "SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256\n",
        "etc/apache2/ssl.conf",
    )
    pairs = {(f.algorithm, f.role) for f in result.findings}
    assert ("ECDH", CryptoRole.KEY_ESTABLISHMENT) in pairs
    assert ("RSA", CryptoRole.SIGNATURE) in pairs
    assert ("AES", CryptoRole.SYMMETRIC_ENCRYPTION) in pairs
    assert ("SHA-256", CryptoRole.HASH) in pairs


def test_openssh_hybrid_kex_tokens_are_preserved_exactly():
    result = scan_config(
        "KexAlgorithms sntrup761x25519-sha512,mlkem768x25519-sha256\n",
        "etc/ssh/sshd_config",
    )
    tokens = {m["algorithm_token"] for m in _metadata(result.findings)}
    assert "sntrup761x25519-sha512" in tokens
    assert "mlkem768x25519-sha256" in tokens
    assert any(f.algorithm == "SNTRUP" and f.role == CryptoRole.KEY_ESTABLISHMENT for f in result.findings)
    assert any(f.algorithm == "ML-KEM" and f.role == CryptoRole.KEY_ESTABLISHMENT for f in result.findings)


def test_openssl_groups_include_classical_and_pq_hybrids():
    result = scan_config(
        "Groups = X25519:secp256r1:MLKEM768\n",
        "etc/ssl/openssl.cnf",
    )
    assert any(f.algorithm == "ECDH" and f.curve == "X25519" for f in result.findings)
    assert any(f.algorithm == "ECDH" for f in result.findings)
    assert any(f.algorithm == "ML-KEM" for f in result.findings)


def test_java_disabled_algorithms_keep_disabled_state():
    result = scan_config(
        "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, RC4, MD5, DH keySize < 2048\n",
        "conf/security/java.security",
    )
    metadata = _metadata(result.findings)
    assert any(m.get("setting_state") == "disabled-or-constrained" and m.get("algorithm_token") == "SSLv3" for m in metadata)
    assert any(f.algorithm == "RC4" for f in result.findings)
    assert any(f.algorithm == "MD5" for f in result.findings)
    assert any(f.algorithm == "DH" for f in result.findings)


def test_comments_and_unrelated_directives_do_not_create_findings():
    result = scan_config(
        "# ssl_protocols SSLv3;\n"
        "  # KexAlgorithms ssh-rsa\n"
        "server_tokens off;\n"
        "ssl_protocols TLSv1.3; # SSLv3 is mentioned only in a comment\n",
        "nginx.conf",
    )
    assert len(result.findings) == 1
    assert result.findings[0].variant == "TLSv1.3"


def test_variable_reference_creates_dynamic_agility_signal():
    result = scan_config(
        "ssl_ciphers $cipher_policy;\n",
        "nginx.conf",
    )
    assert any(
        finding.purpose == "dynamic-algorithm-selection"
        and finding.evidence[0].evidence_type.value == "dynamic-selection"
        for finding in result.findings
    )


def test_unknown_and_malformed_lines_are_tolerated():
    result = scan_config(
        "this is not a supported directive\n"
        "ssl_ciphers ;\n"
        "ssl_protocols TLSv1.3;\n",
        "nginx.conf",
    )
    assert result.ok
    assert len(result.findings) == 1


def test_candidate_names_include_known_configs_and_generic_conf():
    assert is_config_candidate("nginx.conf")
    assert is_config_candidate("sshd_config")
    assert is_config_candidate("java.security")
    assert is_config_candidate("50-custom.conf")
    assert not is_config_candidate("app.py")
    assert not is_config_candidate("README.md")


def test_pipeline_discovers_config_and_records_coverage(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_text("ssl_protocols TLSv1.2 TLSv1.3;\n", encoding="utf-8")
    result = run_scan(tmp_path)

    assert {f.variant for f in result.findings} == {"TLSv1.2", "TLSv1.3"}
    record = next(record for record in result.coverage.files if record.path == "nginx.conf")
    assert record.stages["config"].value == "success"
    assert record.outcome.value == "analyzed"


def test_invalid_utf8_config_is_reported_as_failed_coverage(tmp_path):
    config = tmp_path / "nginx.conf"
    config.write_bytes(b"\xff\xfe")
    result = run_scan(tmp_path)

    record = next(record for record in result.coverage.files if record.path == "nginx.conf")
    assert record.outcome.value == "failed"
    assert record.stages["config"].value == "failed"


def test_policy_alias_is_recorded_without_guessing_algorithms():
    result = scan_config(
        "ssl_ciphers HIGH:DEFAULT;\n",
        "nginx.conf",
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.algorithm == "unknown"
    assert finding.purpose == "static-configuration-setting"
    assert finding.evidence[0].rule_id == "CONFIG-UNRESOLVED-POLICY"
    assert finding.evidence[0].metadata["setting_state"] == "unresolved-alias-or-policy"
