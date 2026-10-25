from quantumshield.common.models import Confidence, CryptoRole, FindingStatus
from quantumshield.discovery.x509_scanner import scan_x509


def run(data, path="k.pem"):
    return scan_x509(data, path)


def test_rsa_certificate_is_parsed_with_evidence(certs):
    out = run(certs.pem(certs.rsa_cert_sign))
    assert out.ok
    (f,) = out.findings
    assert (f.algorithm, f.variant, f.key_size) == ("RSA", "RSA-2048", 2048)
    assert f.status == FindingStatus.CONFIRMED and f.confidence == Confidence.HIGH
    meta = f.evidence[0].metadata
    assert meta["subject"] == "CN=test.local"
    assert len(meta["fingerprint_sha256"]) == 64
    assert meta["signature_algorithm"] == "sha256WithRSAEncryption"
    assert f.evidence[0].line_start == 1


def test_ec_certificate_reports_curve(certs):
    (f,) = run(certs.pem(certs.ec_cert)).findings
    assert (f.algorithm, f.curve, f.variant) == ("EC", "P-256", "P-256")


def test_ed25519_certificate(certs):
    (f,) = run(certs.pem(certs.ed_cert)).findings
    assert f.algorithm == "Ed25519" and f.role == CryptoRole.SIGNATURE
    assert not f.assumptions  # role implied by the key type, nothing assumed


def test_role_from_key_usage(certs):
    assert run(certs.pem(certs.rsa_cert_sign)).findings[0].role == CryptoRole.SIGNATURE
    assert run(certs.pem(certs.rsa_cert_encipher)).findings[0].role == CryptoRole.KEY_ESTABLISHMENT
    # both declared: the conservative reading wins
    assert run(certs.pem(certs.rsa_cert_both)).findings[0].role == CryptoRole.KEY_ESTABLISHMENT


def test_missing_key_usage_defaults_to_signature_and_says_so(certs):
    (f,) = run(certs.pem(certs.rsa_cert_plain)).findings
    assert f.role == CryptoRole.SIGNATURE
    assert any("no keyUsage" in a for a in f.assumptions)


def test_extended_key_usage_sets_purpose(certs):
    (f,) = run(certs.pem(certs.rsa_cert_tls)).findings
    assert f.purpose == "TLS server authentication"


def test_der_certificate_and_der_private_key(certs):
    (c,) = run(certs.der(certs.rsa_cert_sign), "c.der").findings
    assert c.variant == "RSA-2048" and c.evidence[0].line_start is None
    (k,) = run(certs.ec_priv_der, "k.der").findings
    assert k.curve == "P-256" and k.evidence[0].metadata["key_material"] == "private"


def test_private_key_records_algorithm_but_never_key_material(certs):
    out = run(certs.rsa_priv_pem, "k.key")
    (f,) = out.findings
    assert f.variant == "RSA-2048" and f.role == CryptoRole.UNDETERMINED
    assert "BEGIN" not in f.model_dump_json() and "MII" not in f.model_dump_json()


def test_public_key_file(certs):
    (f,) = run(certs.rsa_pub_pem, "pub.pem").findings
    assert f.variant == "RSA-2048" and f.evidence[0].metadata["key_material"] == "public"


def test_passphrase_protected_keys_are_unable_to_analyze(certs):
    for blob in (certs.rsa_priv_enc_pem, certs.rsa_priv_traditional_enc):
        out = run(blob, "enc.key")
        assert not out.ok
        (f,) = out.findings
        assert f.status == FindingStatus.UNABLE_TO_ANALYZE
        assert "passphrase" in f.evidence_gap_reason


def test_empty_and_whitespace_files_fail_visibly():
    for blob in (b"", b"  \n\n"):
        out = run(blob, "server.pem")
        assert not out.ok and out.reason == "file is empty"
        assert out.findings[0].status == FindingStatus.UNABLE_TO_ANALYZE


def test_corrupt_pem_block_fails_visibly():
    out = run(b"-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----\n")
    assert not out.ok
    assert out.findings[0].status == FindingStatus.UNABLE_TO_ANALYZE


def test_garbage_is_not_silently_ignored():
    out = run(b"just some text", "x.key")
    assert not out.ok and out.findings[0].status == FindingStatus.UNABLE_TO_ANALYZE


def test_unknown_pem_label_is_reported_not_dropped():
    out = run(b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n")
    assert not out.ok and "unsupported PEM block" in out.reason


def test_bundle_yields_one_finding_per_block_and_marks_the_stage_failed(certs):
    bundle = (
        certs.pem(certs.rsa_cert_sign)
        + certs.pem(certs.ec_cert)
        + b"-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----\n"
    )
    out = run(bundle, "chain.pem")
    kinds = [(f.algorithm, f.status) for f in out.findings]
    assert kinds == [
        ("RSA", FindingStatus.CONFIRMED),
        ("EC", FindingStatus.CONFIRMED),
        ("unknown", FindingStatus.UNABLE_TO_ANALYZE),
    ]
    assert not out.ok  # one bad block => the file is not fully analyzed
    assert [f.evidence[0].line_start for f in out.findings][0] == 1
    assert out.findings[1].evidence[0].line_start > 1  # line of the block's own BEGIN
