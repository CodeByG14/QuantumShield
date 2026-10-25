from quantumshield.monitor.identity import assign_stable_keys, stable_finding_key


def finding(
    *,
    finding_id="CRYPTO-001",
    algorithm="RSA",
    variant="RSA-2048",
    curve=None,
    role="key-establishment",
    file_path="src/keys.py",
    line=10,
    fingerprint=None,
    excerpt="RSA.generate(2048)",
    rule_id="PY-RSA-001",
):
    metadata = {"fingerprint_sha256": fingerprint} if fingerprint else {}
    return {
        "finding_id": finding_id,
        "algorithm": algorithm,
        "variant": variant,
        "curve": curve,
        "role": role,
        "status": "confirmed",
        "confidence": "high",
        "evidence": [
            {
                "evidence_id": f"{finding_id}-E1",
                "finding_id": finding_id,
                "file_path": file_path,
                "line_start": line,
                "line_end": line,
                "evidence_type": "api-call",
                "detection_method": "regex",
                "rule_id": rule_id,
                "excerpt": excerpt,
                "confidence": "high",
                "metadata": metadata,
            }
        ],
    }


def test_stable_key_ignores_finding_ids_and_line_numbers():
    before = finding(finding_id="CRYPTO-001", line=10)
    after = finding(finding_id="CRYPTO-019", line=81)
    assert stable_finding_key(before) == stable_finding_key(after)
    assert assign_stable_keys([before])[0][0] == assign_stable_keys([after])[0][0]


def test_stable_key_has_required_segments_and_normalizes_algorithm_fields():
    item = finding(algorithm=" rsa ", variant="RSA-2048", file_path="src/./keys.py")
    assert stable_finding_key(item) == "rsa|rsa-2048||key-establishment|src/keys.py|"


def test_same_file_certificates_are_distinct_by_fingerprint():
    first = finding(finding_id="CRYPTO-001", file_path="certs/bundle.pem", fingerprint="aa11")
    second = finding(finding_id="CRYPTO-002", file_path="certs/bundle.pem", fingerprint="bb22")
    keys = [key for key, _ in assign_stable_keys([first, second])]
    assert keys[0] != keys[1]
    assert keys[0].endswith("|aa11")
    assert keys[1].endswith("|bb22")


def test_ordinal_suffix_disambiguates_duplicate_base_keys_without_lines():
    first = finding(finding_id="CRYPTO-001", line=10, rule_id="RULE-A")
    second = finding(finding_id="CRYPTO-002", line=20, rule_id="RULE-B")
    before = dict(assign_stable_keys([first, second]))
    shifted_first = finding(finding_id="CRYPTO-091", line=110, rule_id="RULE-A")
    shifted_second = finding(finding_id="CRYPTO-092", line=120, rule_id="RULE-B")
    after = dict(assign_stable_keys([shifted_first, shifted_second]))
    assert set(before) == set(after)
    assert len(before) == 2
    assert all(key.endswith(("#1", "#2")) for key in before)
