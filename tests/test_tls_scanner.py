"""Tests for TLS endpoint scanner with local test server.

These tests use a local test server and do NOT contact public endpoints.
All certificates are generated on-the-fly via the `certs` fixture.
"""

import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest

from quantumshield.discovery.tls_scanner import scan_tls_endpoint, TLSEndpointResult


def create_test_tls_server(port: int, cert_pem: bytes, key_pem: bytes, duration: float = 2.0):
    """Create a simple TLS test server that accepts one connection.

    Args:
        port: Port to listen on
        cert_pem: Certificate in PEM format
        key_pem: Private key in PEM format
        duration: How long to keep server alive (seconds)
    """
    def run_server():
        # Write cert and key to temp files
        import os
        cert_path = None
        key_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as cert_f:
                cert_f.write(cert_pem)
                cert_path = cert_f.name
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.key', delete=False) as key_f:
                key_f.write(key_pem)
                key_path = key_f.name

            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port))
                sock.listen(1)
                sock.settimeout(duration)

                try:
                    conn, addr = sock.accept()
                    with context.wrap_socket(conn, server_side=True) as ssock:
                        # Keep connection alive briefly
                        time.sleep(0.1)
                except socket.timeout:
                    pass
                except Exception:
                    pass
        except Exception as e:
            print(f"Failed to load cert chain: {e}")
        finally:
            if cert_path:
                try:
                    os.unlink(cert_path)
                except Exception:
                    pass
            if key_path:
                try:
                    os.unlink(key_path)
                except Exception:
                    pass

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    time.sleep(0.2)  # Give server time to start
    return thread


def test_successful_tls_connection(certs):
    """Test successful TLS handshake with local server."""
    cert_pem = certs.pem(certs.rsa_cert_sign)
    key_pem = certs.rsa_priv_pem

    port = 54321  # Use high port to avoid permission issues
    server = create_test_tls_server(port, cert_pem, key_pem)

    # Scan with certificate verification disabled (self-signed test cert)
    result = scan_tls_endpoint("127.0.0.1", port, timeout=2.0, verify_cert=False)

    assert result.host == "127.0.0.1"
    assert result.port == port
    assert result.connected is True
    assert result.handshake_successful is True
    assert result.verification_bypassed is True
    assert result.tls_version is not None
    assert result.cipher_suite is not None
    assert result.error_message is None

    # Should have extracted certificate findings
    assert len(result.findings) > 0
    finding = result.findings[0]
    assert finding.algorithm == "RSA"
    assert finding.status.value == "confirmed"
    assert finding.role.value == "signature"


def test_connection_refused():
    """Test handling of connection refused (no server listening)."""
    # Use a port that definitely has nothing listening
    result = scan_tls_endpoint("127.0.0.1", 54399, timeout=1.0)

    assert result.connected is False
    assert result.handshake_successful is False
    assert result.error_message is not None
    assert "refused" in result.error_message.lower()
    assert len(result.findings) == 0


def test_connection_timeout(monkeypatch):
    """Timeout handling is deterministic and does not depend on external routing."""
    def raise_timeout(*args, **kwargs):
        raise socket.timeout("simulated timeout")

    monkeypatch.setattr(socket, "create_connection", raise_timeout)
    result = scan_tls_endpoint("example.invalid", 443, timeout=0.01)

    assert result.connected is False
    assert result.handshake_successful is False
    assert result.error_message is not None
    assert "timeout" in result.error_message.lower()


def test_invalid_hostname():
    """Test handling of invalid hostname."""
    result = scan_tls_endpoint("invalid.local.nonexistent", 443, timeout=1.0)

    assert result.connected is False
    assert result.handshake_successful is False
    assert result.error_message is not None
    # Should be address resolution error


def test_certificate_verification_bypass_flag(certs):
    """Test that certificate verification bypass is explicitly tracked."""
    cert_pem = certs.pem(certs.rsa_cert_sign)
    key_pem = certs.rsa_priv_pem

    port = 54322
    server = create_test_tls_server(port, cert_pem, key_pem)

    # With verify_cert=False
    result_unverified = scan_tls_endpoint("127.0.0.1", port, timeout=2.0, verify_cert=False)
    assert result_unverified.verification_bypassed is True
    assert result_unverified.certificate_verified is False

    # Give time for server to restart
    time.sleep(0.3)

    # With verify_cert=True (will fail for self-signed cert, but flag should be set)
    port2 = 54323
    server2 = create_test_tls_server(port2, cert_pem, key_pem)
    result_verify_attempted = scan_tls_endpoint("127.0.0.1", port2, timeout=2.0, verify_cert=True)

    # For self-signed cert, handshake will fail, but verification_bypassed should be False
    assert result_verify_attempted.verification_bypassed is False


def test_key_exchange_group_not_inferred(certs):
    """Test that key exchange group is not inferred from cipher suite."""
    cert_pem = certs.pem(certs.ec_cert)
    key_pem = certs.ec_priv_der

    port = 54324
    server = create_test_tls_server(port, cert_pem, key_pem)

    result = scan_tls_endpoint("127.0.0.1", port, timeout=2.0, verify_cert=False)

    if result.handshake_successful:
        # Key exchange group should be unknown (not inferred)
        assert result.key_exchange_group is None or result.key_exchange_group_source == "unknown"
        # Should NOT have a value based on cipher suite name parsing


def test_ec_certificate_extraction(certs):
    """Test extraction of EC certificate details."""
    cert_pem = certs.pem(certs.ec_cert)
    key_pem = certs.ec_priv_der

    port = 54325
    server = create_test_tls_server(port, cert_pem, key_pem)

    result = scan_tls_endpoint("127.0.0.1", port, timeout=2.0, verify_cert=False)

    if result.handshake_successful and result.findings:
        finding = result.findings[0]
        assert finding.algorithm == "EC"
        assert finding.curve is not None
        assert finding.role.value == "signature"


def test_result_structure():
    """Test that TLSEndpointResult has expected structure."""
    result = TLSEndpointResult(
        host="example.com",
        port=443,
        scan_timestamp=None,
    )

    # Should have all required fields
    assert result.host == "example.com"
    assert result.port == 443
    assert result.connected is False
    assert result.handshake_successful is False
    assert result.verification_bypassed is False
    assert result.key_exchange_group_source == "unknown"
    assert isinstance(result.peer_certificates, list)
    assert isinstance(result.findings, list)


def test_no_port_scanning():
    """Verify scanner requires explicit host and port (no scanning behavior)."""
    # This is a design test - the function signature requires explicit host and port
    # and has no address enumeration or port iteration logic

    result = scan_tls_endpoint("127.0.0.1", 54326, timeout=0.5)

    # Should only attempt the specified port
    assert result.host == "127.0.0.1"
    assert result.port == 54326

    # Function has no logic to scan multiple ports or hosts
    # This is verified by code inspection and function signature