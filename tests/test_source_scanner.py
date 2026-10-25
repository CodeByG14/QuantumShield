import pytest

from quantumshield.common.models import Confidence, CryptoRole, EvidenceType, FindingStatus
from quantumshield.discovery.pipeline import DEFAULT_RULES
from quantumshield.discovery.rules import Language, load_rules
from quantumshield.discovery.scanner import scan_source

RULES = load_rules(DEFAULT_RULES)


def scan(text, lang=Language.PYTHON, path="f.py"):
    return scan_source(text, path, lang, RULES).findings


def one(findings, algorithm, variant=None):
    hits = [f for f in findings if f.algorithm == algorithm and (variant is None or f.variant == variant)]
    assert len(hits) == 1, [(f.algorithm, f.variant) for f in findings]
    return hits[0]


# ---- table-driven: each family resolves as documented ----------------------

CASES = [
    # lang, snippet, algorithm, variant, confidence, status
    (Language.PYTHON, "RSA.generate(2048)", "RSA", "RSA-2048", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "rsa.generate_private_key(public_exponent=3, key_size=3072)", "RSA", "RSA-3072", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "rsa.generate_private_key(public_exponent=3, key_size=bits)", "RSA", None, Confidence.MEDIUM, FindingStatus.POTENTIAL),
    (Language.PYTHON, "ec.generate_private_key(ec.SECP384R1())", "EC", None, Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "ec.generate_private_key(curve)", "EC", None, Confidence.MEDIUM, FindingStatus.POTENTIAL),
    (Language.PYTHON, "dh.generate_parameters(generator=2, key_size=2048)", "DH", "DH-2048", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "AES.new(k, AES.MODE_GCM)", "AES", None, Confidence.MEDIUM, FindingStatus.POTENTIAL),
    (Language.PYTHON, "hashlib.md5(b'x')", "MD5", "MD5", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "hashlib.sha1(b'x')", "SHA-1", "SHA-1", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "hashlib.sha256(b'x')", "SHA-256", "SHA-256", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.PYTHON, "X25519PrivateKey.generate()", "X25519", "X25519", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.JAVA, 'KeyPairGenerator.getInstance("RSA");', "RSA", None, Confidence.MEDIUM, FindingStatus.POTENTIAL),
    (Language.JAVA, 'Cipher.getInstance("AES/GCM/NoPadding");', "AES", None, Confidence.MEDIUM, FindingStatus.POTENTIAL),
    (Language.JAVA, 'Cipher.getInstance("AES256/GCM/NoPadding");', "AES", "AES-256", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.JAVA, 'new ECGenParameterSpec("secp256r1");', "EC", None, Confidence.LOW, FindingStatus.POTENTIAL),
    (Language.JAVA, 'KeyAgreement.getInstance("ECDH");', "ECDH", "ECDH", Confidence.HIGH, FindingStatus.CONFIRMED),
    (Language.JAVA, 'MessageDigest.getInstance("SHA-1");', "SHA-1", "SHA-1", Confidence.HIGH, FindingStatus.CONFIRMED),
]


@pytest.mark.parametrize("lang,snippet,algorithm,variant,confidence,status", CASES)
def test_rule_families(lang, snippet, algorithm, variant, confidence, status):
    f = one(scan(snippet, lang), algorithm)
    assert (f.variant, f.confidence, f.status) == (variant, confidence, status)
    expected_evidence_type = (
        EvidenceType.CURVE_PARAMETER
        if "ECGenParameterSpec" in snippet
        else EvidenceType.API_CALL
    )
    assert f.evidence[0].evidence_type == expected_evidence_type


def test_curve_parameter_is_not_misclassified_as_an_algorithm_variant():
    f = one(scan('new ECGenParameterSpec("secp256r1");', Language.JAVA), "EC")
    assert f.algorithm == "EC"
    assert f.variant is None
    assert f.curve == "P-256"
    assert f.role == CryptoRole.UNDETERMINED
    assert f.status == FindingStatus.POTENTIAL
    assert f.confidence == Confidence.LOW
    assert f.evidence[0].evidence_type == EvidenceType.CURVE_PARAMETER


def test_real_ec_key_generation_with_explicit_curve_remains_confirmed():
    f = one(scan("ec.generate_private_key(ec.SECP256R1())"), "EC")
    assert f.algorithm == "EC"
    assert f.variant is None
    assert f.curve == "P-256"
    assert f.role == CryptoRole.UNDETERMINED
    assert f.status == FindingStatus.CONFIRMED
    assert f.confidence == Confidence.HIGH


@pytest.mark.parametrize(
    "raw_curve,canonical_curve",
    [("secp256r1", "P-256"), ("secp384r1", "P-384"), ("secp256k1", "secp256k1")],
)
def test_standalone_curve_mention_is_potential_not_confirmed(raw_curve, canonical_curve):
    f = one(scan(f'configured_curve = "{raw_curve}"'), "EC")
    assert f.variant is None
    assert f.curve == canonical_curve
    assert f.role == CryptoRole.UNDETERMINED
    assert f.status == FindingStatus.POTENTIAL
    assert f.confidence == Confidence.LOW
    assert f.evidence[0].evidence_type == EvidenceType.KEYWORD


def test_curve_parameter_is_retained_separately_from_ec_generator_call():
    src = 'KeyPairGenerator.getInstance("EC");\nnew ECGenParameterSpec("secp256r1");'
    findings = scan(src, Language.JAVA, "CurveDemo.java")
    parameter = next(f for f in findings if f.curve == "P-256")
    assert parameter.algorithm == "EC"
    assert parameter.variant is None
    assert parameter.status == FindingStatus.POTENTIAL
    assert parameter.confidence == Confidence.LOW


def test_roles_follow_the_call():
    assert one(scan('Signature.getInstance("SHA256withECDSA");', Language.JAVA), "ECDSA").role == CryptoRole.SIGNATURE
    assert one(scan('Cipher.getInstance("RSA/ECB/PKCS1Padding");', Language.JAVA), "RSA").role == CryptoRole.KEY_ESTABLISHMENT
    # key generation alone does not say what the key is for
    assert one(scan("RSA.generate(2048)"), "RSA").role == CryptoRole.UNDETERMINED


# ---- evidence handling ------------------------------------------------------


def test_multiline_call_records_line_range():
    f = one(scan("x = rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=2048,\n)\n"), "RSA")
    e = f.evidence[0]
    assert (e.line_start, e.line_end) == (1, 4)


def test_comment_mention_is_never_confirmed():
    f = one(scan("# we must stop using RSA.generate(2048) here\nx = 1\n"), "RSA")
    assert f.status == FindingStatus.POTENTIAL
    assert f.confidence == Confidence.LOW
    assert f.evidence[0].evidence_type == EvidenceType.COMMENT_MENTION


def test_java_block_and_line_comments():
    src = '/* uses MD5\n   and RSA */\nint x; // SHA-1 is weak\n'
    findings = scan(src, Language.JAVA, "A.java")
    assert {f.algorithm for f in findings} == {"MD5", "RSA", "SHA-1"}
    assert all(f.evidence[0].evidence_type == EvidenceType.COMMENT_MENTION for f in findings)


def test_keyword_in_string_is_low_but_not_a_comment():
    f = one(scan('algo = "ECDH"  # legacy\n'), "ECDH")
    assert f.evidence[0].evidence_type == EvidenceType.KEYWORD
    assert f.status == FindingStatus.POTENTIAL


def test_hash_inside_string_is_not_a_comment():
    f = one(scan('h = hashlib.md5(b"#")\n'), "MD5")
    assert f.status == FindingStatus.CONFIRMED


def test_weak_evidence_is_dropped_where_a_real_call_exists():
    src = "# RSA notes\nfrom Crypto.PublicKey import RSA\nk = RSA.generate(2048)\n"
    f = one(scan(src), "RSA")
    assert [e.evidence_type for e in f.evidence] == [EvidenceType.API_CALL]


def test_duplicate_matches_collapse_to_one_evidence_per_rule_and_line():
    src = "a = b = hashlib.md5(x) or hashlib.md5(y)\n"
    f = one(scan(src), "MD5")
    assert len(f.evidence) == 1


def test_same_algorithm_different_variants_stay_separate():
    src = "RSA.generate(2048)\nRSA.generate(4096)\nRSA.generate(2048)\n"
    findings = [f for f in scan(src) if f.algorithm == "RSA"]
    assert sorted(f.variant for f in findings) == ["RSA-2048", "RSA-4096"]
    assert len(next(f for f in findings if f.variant == "RSA-2048").evidence) == 2


def test_clean_file_has_no_findings():
    assert scan("def add(a, b):\n    return a + b\n") == []
