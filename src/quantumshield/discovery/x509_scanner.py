"""
X.509 stage: parse certificates and public/private keys (PEM or DER).

* One finding per certificate or key; a PEM bundle yields several.
* Private keys: only algorithm and size are recorded, never key material.
* Anything that cannot be read (empty, corrupt, passphrase-protected,
  unsupported type) becomes an UNABLE_TO_ANALYZE finding, and the stage is
  marked failed so coverage cannot count the file as fully analyzed.
* Role comes from the certificate's keyUsage. Without keyUsage a role implied
  by the key type is used; failing that the role defaults to signature,
  recorded as an explicit assumption.
"""

import re
import warnings

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)
from cryptography.x509.oid import ExtendedKeyUsageOID

with warnings.catch_warnings():  # the library warns that finite-field DH is deprecated
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives.asymmetric import dh

    _DH_TYPES = (dh.DHPublicKey, dh.DHPrivateKey)

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)
from quantumshield.discovery.curves import normalize_curve
from quantumshield.discovery.stage import StageOutput

PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
IGNORED_PEM_LABELS = {"EC PARAMETERS"}
PRIVATE_KEY_LABELS = {"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"}

_IMPLIED_ROLE = {
    "Ed25519": CryptoRole.SIGNATURE,
    "Ed448": CryptoRole.SIGNATURE,
    "DSA": CryptoRole.SIGNATURE,
    "X25519": CryptoRole.KEY_ESTABLISHMENT,
    "X448": CryptoRole.KEY_ESTABLISHMENT,
    "DH": CryptoRole.KEY_ESTABLISHMENT,
}

_EKU_PURPOSE = {
    ExtendedKeyUsageOID.SERVER_AUTH: "TLS server authentication",
    ExtendedKeyUsageOID.CLIENT_AUTH: "TLS client authentication",
    ExtendedKeyUsageOID.CODE_SIGNING: "code signing",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "email protection (S/MIME)",
}


def _describe_key(key) -> tuple[str, str, int, str | None] | None:
    """(algorithm, variant, key_size, curve) for a public or private key object."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "RSA", f"RSA-{key.key_size}", key.key_size, None
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        curve = normalize_curve(key.curve.name)
        return "EC", curve, key.curve.key_size, curve
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "DSA", f"DSA-{key.key_size}", key.key_size, None
    if isinstance(key, _DH_TYPES):
        return "DH", f"DH-{key.key_size}", key.key_size, None
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", "Ed25519", 256, None
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", "Ed448", 448, None
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "X25519", "X25519", 256, None
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "X448", "X448", 448, None
    return None


def _evidence(rel_path, line, etype, rule_id, excerpt, confidence, metadata=None) -> Evidence:
    return Evidence(
        file_path=rel_path,
        line_start=line,
        evidence_type=etype,
        detection_method=DetectionMethod.X509,
        rule_id=rule_id,
        excerpt=excerpt,
        confidence=confidence,
        metadata=metadata or {},
    )


def _unable(rel_path, line, reason, label="") -> CryptoFinding:
    return CryptoFinding(
        algorithm="unknown",
        status=FindingStatus.UNABLE_TO_ANALYZE,
        evidence_gap_reason=reason,
        evidence=[
            _evidence(
                rel_path, line, EvidenceType.KEY_FILE, "X509-UNREADABLE-001",
                label or reason, Confidence.LOW,
            )
        ],
    )


def _key_usage_role(cert: x509.Certificate) -> tuple[CryptoRole | None, list[str]]:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None, []
    flags = [
        name
        for name in (
            "digital_signature", "content_commitment", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
        )
        if getattr(ku, name)
    ]
    if {"key_encipherment", "data_encipherment", "key_agreement"} & set(flags):
        return CryptoRole.KEY_ESTABLISHMENT, flags  # conservative if both are declared
    if {"digital_signature", "content_commitment", "key_cert_sign", "crl_sign"} & set(flags):
        return CryptoRole.SIGNATURE, flags
    return CryptoRole.UNDETERMINED, flags


def _certificate_finding(cert: x509.Certificate, rel_path: str, line: int | None) -> CryptoFinding:
    desc = _describe_key(cert.public_key())
    if desc is None:
        return _unable(rel_path, line, f"unsupported public-key type {type(cert.public_key()).__name__}")
    algorithm, variant, size, curve = desc

    role, flags = _key_usage_role(cert)
    assumptions: list[str] = []
    if role is None:
        if algorithm in _IMPLIED_ROLE:
            role = _IMPLIED_ROLE[algorithm]
        else:
            role = CryptoRole.SIGNATURE
            assumptions.append(
                "Certificate declares no keyUsage; role assumed to be signature (authenticity). "
                "Key-establishment use of this key is not ruled out."
            )

    purposes: list[str] = []
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        purposes = [_EKU_PURPOSE[oid] for oid in eku if oid in _EKU_PURPOSE]
    except x509.ExtensionNotFound:
        pass

    sig_oid = cert.signature_algorithm_oid
    metadata = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_algorithm": getattr(sig_oid, "_name", sig_oid.dotted_string),
        "key_usage": ",".join(flags) if flags else "not declared",
    }
    return CryptoFinding(
        algorithm=algorithm,
        variant=variant,
        key_size=size,
        curve=curve,
        role=role,
        purpose=", ".join(purposes) if purposes else None,
        status=FindingStatus.CONFIRMED,
        assumptions=assumptions,
        evidence=[
            _evidence(
                rel_path, line, EvidenceType.CERTIFICATE, "X509-CERT-001",
                f"X.509 certificate, {variant} public key", Confidence.HIGH, metadata,
            )
        ],
    )


def _key_finding(key, material: str, rel_path: str, line: int | None) -> CryptoFinding:
    desc = _describe_key(key)
    if desc is None:
        return _unable(rel_path, line, f"unsupported {material} key type {type(key).__name__}")
    algorithm, variant, size, curve = desc
    return CryptoFinding(
        algorithm=algorithm,
        variant=variant,
        key_size=size,
        curve=curve,
        role=_IMPLIED_ROLE.get(algorithm, CryptoRole.UNDETERMINED),
        status=FindingStatus.CONFIRMED,
        evidence=[
            _evidence(
                rel_path, line, EvidenceType.KEY_FILE,
                "X509-PRIVKEY-001" if material == "private" else "X509-PUBKEY-001",
                f"{material} key, {variant}", Confidence.HIGH, {"key_material": material},
            )
        ],
    )


def _parse_pem_block(label: str, block: bytes, rel_path: str, line: int) -> CryptoFinding | None:
    try:
        if label in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
            return _certificate_finding(x509.load_pem_x509_certificate(block), rel_path, line)
        if label == "PUBLIC KEY":
            return _key_finding(serialization.load_pem_public_key(block), "public", rel_path, line)
        if label == "ENCRYPTED PRIVATE KEY":
            return _unable(rel_path, line, "private key is passphrase-protected; not examined", label)
        if label in PRIVATE_KEY_LABELS:
            return _key_finding(
                serialization.load_pem_private_key(block, password=None), "private", rel_path, line
            )
    except TypeError:
        return _unable(rel_path, line, "private key is passphrase-protected; not examined", label)
    except (ValueError, UnsupportedAlgorithm) as exc:
        return _unable(rel_path, line, f"malformed or unsupported {label.lower()} ({type(exc).__name__})", label)
    return _unable(rel_path, line, f"unsupported PEM block type '{label}'", label)


def _parse_der(data: bytes, rel_path: str) -> CryptoFinding | None:
    loaders = (
        lambda: _certificate_finding(x509.load_der_x509_certificate(data), rel_path, None),
        lambda: _key_finding(serialization.load_der_public_key(data), "public", rel_path, None),
        lambda: _key_finding(serialization.load_der_private_key(data, password=None), "private", rel_path, None),
    )
    for load in loaders:
        try:
            return load()
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    return None


def scan_x509(data: bytes, rel_path: str) -> StageOutput:
    if not data.strip():
        return StageOutput(
            findings=[_unable(rel_path, None, "file is empty", "empty file")],
            ok=False,
            reason="file is empty",
        )

    findings: list[CryptoFinding] = []
    if b"-----BEGIN" in data:
        for m in PEM_BLOCK.finditer(data):
            label = m.group(1).decode("ascii", "replace")
            if label in IGNORED_PEM_LABELS:
                continue
            line = data[: m.start()].count(b"\n") + 1
            finding = _parse_pem_block(label, m.group(0), rel_path, line)
            if finding:
                findings.append(finding)
        if not findings:
            findings.append(_unable(rel_path, None, "no complete PEM block found", "PEM header without a complete block"))
    else:
        finding = _parse_der(data, rel_path)
        findings.append(
            finding
            or _unable(rel_path, None, "not a recognised PEM or DER certificate or key", "unrecognised content")
        )

    gaps = [f.evidence_gap_reason for f in findings if f.status == FindingStatus.UNABLE_TO_ANALYZE]
    return StageOutput(findings=findings, ok=not gaps, reason="; ".join(gaps) if gaps else None)
