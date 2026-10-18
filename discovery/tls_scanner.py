"""Controlled TLS endpoint assessment for QuantumShield Week 6 Track 2.

This scanner accepts a single explicit host:port and performs one bounded
TLS handshake to observe protocol version, cipher suite, and certificate
metadata. It does not enumerate addresses, perform port sweeping, or
execute untrusted code.

Safety constraints:
- Explicit target required (no discovery)
- Connection and handshake timeouts
- No silent certificate verification bypass
- Reliable observations only (no inference)
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)


@dataclass
class TLSEndpointResult:
    """Result of a single TLS endpoint assessment."""

    host: str
    port: int
    scan_timestamp: datetime
    scanner_version: str = "1.0"

    # Connection outcome
    connected: bool = False
    handshake_successful: bool = False
    error_message: str | None = None

    # Protocol details (when handshake succeeds)
    tls_version: str | None = None
    cipher_suite: str | None = None

    # Key exchange group - ONLY if reliably observed
    # Do NOT infer from cipher suite name
    key_exchange_group: str | None = None
    key_exchange_group_source: str = "unknown"  # "inferred" | "observed" | "unknown"

    # Certificate details (when available)
    peer_certificates: list[bytes] = None  # DER-encoded certificates
    certificate_verified: bool = False
    verification_bypassed: bool = False

    # Findings extracted from this endpoint
    findings: list[CryptoFinding] = None

    def __post_init__(self):
        if self.peer_certificates is None:
            self.peer_certificates = []
        if self.findings is None:
            self.findings = []


def scan_tls_endpoint(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    verify_cert: bool = True,
) -> TLSEndpointResult:
    """Scan a single TLS endpoint with explicit host and port.

    Args:
        host: Target hostname or IP address (explicitly supplied)
        port: Target port number
        timeout: Connection and handshake timeout in seconds
        verify_cert: Whether to verify certificate (default True)

    Returns:
        TLSEndpointResult with observed protocol/certificate details

    Safety:
        - No address enumeration or port scanning
        - Single bounded handshake per call
        - Timeouts prevent hanging
        - Certificate verification can be bypassed only with explicit flag
    """
    result = TLSEndpointResult(
        host=host,
        port=port,
        scan_timestamp=datetime.now(timezone.utc),
    )

    if not verify_cert:
        result.verification_bypassed = True

    try:
        # Create SSL context
        context = ssl.create_default_context()

        if not verify_cert:
            # Explicit bypass for inspection (not silent)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        # Attempt connection with timeout
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result.connected = True

            # Wrap socket with TLS
            with context.wrap_socket(sock, server_hostname=host if verify_cert else None) as ssock:
                result.handshake_successful = True

                # Observe TLS version
                result.tls_version = ssock.version()

                # Observe cipher suite
                result.cipher_suite = ssock.cipher()[0] if ssock.cipher() else None

                # Key exchange group - Python's ssl module doesn't reliably expose this
                # for TLS 1.3. We leave it unknown rather than inferring from cipher name.
                result.key_exchange_group = None
                result.key_exchange_group_source = "unknown"

                # Get peer certificate
                try:
                    peer_cert_der = ssock.getpeercert(binary_form=True)
                    if peer_cert_der:
                        result.peer_certificates = [peer_cert_der]
                        result.certificate_verified = verify_cert

                        # Parse certificate and extract findings
                        result.findings = _extract_findings_from_certificate(
                            peer_cert_der,
                            host,
                            port,
                        )
                except Exception as cert_error:
                    result.error_message = f"Certificate retrieval failed: {cert_error}"

    except socket.timeout:
        result.error_message = "Connection timeout"
    except socket.gaierror as e:
        result.error_message = f"Address resolution failed: {e}"
    except ssl.SSLError as e:
        result.error_message = f"TLS handshake failed: {e}"
    except ConnectionRefusedError:
        result.error_message = "Connection refused"
    except Exception as e:
        result.error_message = f"Scan failed: {type(e).__name__}: {e}"

    return result


def _extract_findings_from_certificate(
    cert_der: bytes,
    host: str,
    port: int,
) -> list[CryptoFinding]:
    """Extract cryptographic findings from a TLS certificate.

    Reuses certificate parsing logic similar to x509_scanner but adapted
    for endpoint context.
    """
    findings = []

    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Extract public key algorithm and parameters
        public_key = cert.public_key()
        algorithm = None
        variant = None
        key_size = None
        curve = None
        role = CryptoRole.SIGNATURE  # Certificates primarily used for signatures

        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa

        if isinstance(public_key, rsa.RSAPublicKey):
            algorithm = "RSA"
            key_size = public_key.key_size
            variant = f"RSA-{key_size}"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algorithm = "EC"
            curve_name = public_key.curve.name
            # Normalize curve names
            curve_map = {
                "secp256r1": "P-256",
                "secp384r1": "P-384",
                "secp521r1": "P-521",
            }
            curve = curve_map.get(curve_name.lower(), curve_name)
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            algorithm = "Ed25519"
        elif isinstance(public_key, ed448.Ed448PublicKey):
            algorithm = "Ed448"
        elif isinstance(public_key, dsa.DSAPublicKey):
            algorithm = "DSA"
            key_size = public_key.key_size
        else:
            algorithm = "UNKNOWN"

        if algorithm and algorithm != "UNKNOWN":
            # Get certificate subject for location
            try:
                subject = cert.subject.rfc4514_string()
            except Exception:
                subject = "certificate-subject"

            location = f"{host}:{port} ({subject})"

            finding = CryptoFinding(
                algorithm=algorithm,
                variant=variant,
                key_size=key_size,
                curve=curve,
                role=role,
                status=FindingStatus.CONFIRMED,
                evidence=[
                    Evidence(
                        file_path=location,
                        line_start=None,
                        evidence_type=EvidenceType.CERTIFICATE,
                        detection_method=DetectionMethod.X509,
                        rule_id="TLS-ENDPOINT-CERT",
                        excerpt=f"TLS endpoint certificate for {host}:{port}",
                        confidence=Confidence.HIGH,
                        metadata={
                            "endpoint": f"{host}:{port}",
                            "not_valid_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before),
                            "not_valid_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after),
                            "issuer": cert.issuer.rfc4514_string(),
                        }
                    )
                ],
            )
            findings.append(finding)

    except Exception as e:
        # Certificate parsing failure - create a finding to represent inability to analyze
        finding = CryptoFinding(
            algorithm="UNKNOWN",
            role=CryptoRole.UNDETERMINED,
            status=FindingStatus.UNABLE_TO_ANALYZE,
            evidence_gap_reason=f"Certificate parsing failed: {e}",
            evidence=[
                Evidence(
                    file_path=f"{host}:{port}",
                    evidence_type=EvidenceType.CERTIFICATE,
                    detection_method=DetectionMethod.X509,
                    rule_id="TLS-ENDPOINT-CERT-FAILED",
                    excerpt=f"Failed to parse certificate from {host}:{port}",
                    confidence=Confidence.LOW,
                )
            ],
        )
        findings.append(finding)

    return findings
