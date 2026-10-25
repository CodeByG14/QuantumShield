"""Backend protocol for PQC operations.

Supports:
- openssl CLI >= 3.5 (preferred)
- oqs python bindings (optional)
- FakeBackend for testing
"""

from __future__ import annotations

import abc
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# --------------------------------------------------------------------------
# Data structures for benchmark results
# --------------------------------------------------------------------------


@dataclass
class BenchmarkResult:
    """Single benchmark measurement."""
    operation: str  # "keygen", "encaps", "decaps", "sign", "verify"
    algorithm: str  # e.g., "ML-KEM-768", "ML-DSA-65", "X25519", "RSA-2048"
    iterations: int
    median_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float
    mean_ms: float
    # For KEM
    public_key_bytes: int | None = None
    private_key_bytes: int | None = None
    ciphertext_bytes: int | None = None
    shared_secret_bytes: int | None = None
    # For signatures
    signature_bytes: int | None = None
    # Round-trip validation
    round_trip_ok: bool | None = None
    tamper_check_ok: bool | None = None


@dataclass
class BenchmarkEnvironment:
    """Environment information for reproducibility."""
    cpu_model: str
    os: str
    python_version: str
    openssl_version: str | None = None
    liboqs_version: str | None = None
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    iterations: int = 100
    warmup: int = 10


@dataclass
class BenchmarkSuite:
    """Complete benchmark suite results."""
    environment: BenchmarkEnvironment
    results: list[BenchmarkResult] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "environment": {
                "cpu_model": self.environment.cpu_model,
                "os": self.environment.os,
                "python_version": self.environment.python_version,
                "openssl_version": self.environment.openssl_version,
                "liboqs_version": self.environment.liboqs_version,
                "timestamp": self.environment.timestamp,
                "iterations": self.environment.iterations,
                "warmup": self.environment.warmup,
            },
            "results": [
                {
                    "operation": r.operation,
                    "algorithm": r.algorithm,
                    "iterations": r.iterations,
                    "median_ms": r.median_ms,
                    "p95_ms": r.p95_ms,
                    "min_ms": r.min_ms,
                    "max_ms": r.max_ms,
                    "mean_ms": r.mean_ms,
                    "public_key_bytes": r.public_key_bytes,
                    "private_key_bytes": r.private_key_bytes,
                    "ciphertext_bytes": r.ciphertext_bytes,
                    "shared_secret_bytes": r.shared_secret_bytes,
                    "signature_bytes": r.signature_bytes,
                    "round_trip_ok": r.round_trip_ok,
                    "tamper_check_ok": r.tamper_check_ok,
                }
                for r in self.results
            ],
        }


# --------------------------------------------------------------------------
# Backend Protocol
# --------------------------------------------------------------------------


class Backend(abc.ABC):
    """Abstract backend for PQC cryptographic operations."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Backend identifier: 'openssl', 'oqs', 'fake'."""

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this backend is available on the current system."""

    @abc.abstractmethod
    def get_version(self) -> str | None:
        """Return version string of the backend, or None if not available."""

    # KEM operations
    @abc.abstractmethod
    def kem_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate KEM keypair. Returns (public_key, private_key)."""

    @abc.abstractmethod
    def kem_encaps(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate. Returns (ciphertext, shared_secret)."""

    @abc.abstractmethod
    def kem_decaps(self, algorithm: str, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate. Returns shared_secret."""

    # Signature operations
    @abc.abstractmethod
    def sig_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate signature keypair. Returns (public_key, private_key)."""

    @abc.abstractmethod
    def sig_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        """Sign message. Returns signature."""

    @abc.abstractmethod
    def sig_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature. Returns True if valid."""

    # Classical baselines
    @abc.abstractmethod
    def classical_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate classical keypair. Algorithms: X25519, P-256, RSA-2048, Ed25519."""

    @abc.abstractmethod
    def classical_dh(self, algorithm: str, private_key: bytes, peer_public: bytes) -> bytes:
        """Classical key agreement. Returns shared secret."""

    @abc.abstractmethod
    def classical_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        """Classical signature."""

    @abc.abstractmethod
    def classical_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Classical signature verification."""

    # TLS handshake benchmark (Phase 3b)
    @abc.abstractmethod
    def tls_handshake_benchmark(
        self,
        group: str,
        host: str = "127.0.0.1",
        port: int = 4433,
        iterations: int = 30,
    ) -> dict[str, Any]:
        """Run TLS 1.3 handshake benchmark against a local server.

        Returns dict with latency stats and byte counts.
        """


class BackendUnavailableError(RuntimeError):
    """Raised when no suitable backend is available."""
    pass


# --------------------------------------------------------------------------
# OpenSSL CLI Backend (>= 3.5)
# --------------------------------------------------------------------------


class OpenSSLBackend(Backend):
    """OpenSSL CLI backend for PQC operations."""

    def __init__(self, openssl_path: str = "openssl"):
        self.openssl_path = openssl_path
        self._version: str | None = None
        self._version_checked = False

    @property
    def name(self) -> str:
        return "openssl"

    @property
    def available(self) -> bool:
        return self.get_version() is not None

    def get_version(self) -> str | None:
        """Get OpenSSL version, checking for >= 3.5."""
        if self._version_checked:
            return self._version

        try:
            result = subprocess.run(
                [self.openssl_path, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                version_line = result.stdout.strip()
                self._version = version_line
                self._version_checked = True
                # Check major.minor >= 3.5
                parts = version_line.split()
                for part in parts:
                    if part[0].isdigit() and "." in part:
                        version_str = part
                        break
                else:
                    return None
                major_minor = ".".join(version_str.split(".")[:2])
                try:
                    if float(major_minor) >= 3.5:
                        return self._version
                except ValueError:
                    pass
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass
        self._version_checked = True
        return None

    def _run_openssl(self, args: list[str], input_data: bytes | None = None) -> tuple[bytes, bytes]:
        """Run openssl command, return (stdout, stderr)."""
        cmd = [self.openssl_path] + args
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                timeout=30,
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"openssl command timed out: {cmd}") from e
        except FileNotFoundError as e:
            raise BackendUnavailableError(f"openssl not found: {self.openssl_path}") from e
        except OSError as e:
            raise RuntimeError(f"Failed to run openssl: {e}") from e

    # KEM operations using openssl pkeyutl
    def kem_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate KEM keypair using openssl genpkey."""
        # OpenSSL uses names like "ML-KEM-512" directly
        alg_map = {
            "ML-KEM-512": "ML-KEM-512",
            "ML-KEM-768": "ML-KEM-768",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        # Generate private key
        stdout, stderr = self._run_openssl([
            "genpkey", "-algorithm", alg_map[algorithm],
            "-outform", "DER",
        ])
        if stderr and "error" in stderr.lower():
            raise RuntimeError(f"openssl genpkey failed: {stderr}")
        private_key_der = stdout

        # Extract public key
        stdout, stderr = self._run_openssl([
            "pkey", "-in", "/dev/stdin", "-inform", "DER",
            "-pubout", "-outform", "DER",
        ], input_data=private_key_der)
        if stderr and "error" in stderr.lower():
            raise RuntimeError(f"openssl pkey pubout failed: {stderr}")
        public_key_der = stdout

        return public_key_der, private_key_der

    def kem_encaps(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate using openssl pkeyutl -encap with -pubin."""
        import tempfile
        import os

        alg_map = {
            "ML-KEM-512": "ML-KEM-512",
            "ML-KEM-768": "ML-KEM-768",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        # OpenSSL pkeyutl -encap requires file-based I/O
        # -inkey with -pubin for public key, -out for ciphertext, -secret for shared secret
        with tempfile.TemporaryDirectory() as tmpdir:
            pub_path = os.path.join(tmpdir, "pub.der")
            ct_path = os.path.join(tmpdir, "ct.der")
            ss_path = os.path.join(tmpdir, "ss.der")

            with open(pub_path, "wb") as f:
                f.write(public_key)

            stdout, stderr = self._run_openssl([
                "pkeyutl", "-encap",
                "-inkey", pub_path, "-pubin",
                "-out", ct_path,
                "-secret", ss_path,
            ])
            if stderr and "error" in stderr.lower():
                raise RuntimeError(f"openssl pkeyutl -encap failed: {stderr}")

            with open(ct_path, "rb") as f:
                ciphertext = f.read()
            with open(ss_path, "rb") as f:
                shared_secret = f.read()

        return ciphertext, shared_secret

    def kem_decaps(self, algorithm: str, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using openssl pkeyutl -decap."""
        import tempfile
        import os

        alg_map = {
            "ML-KEM-512": "ML-KEM-512",
            "ML-KEM-768": "ML-KEM-768",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path = os.path.join(tmpdir, "priv.der")
            ct_path = os.path.join(tmpdir, "ct.der")
            ss_path = os.path.join(tmpdir, "ss.der")

            with open(priv_path, "wb") as f:
                f.write(private_key)
            with open(ct_path, "wb") as f:
                f.write(ciphertext)

            stdout, stderr = self._run_openssl([
                "pkeyutl", "-decap",
                "-inkey", priv_path,
                "-in", ct_path,
                "-secret", ss_path,
            ])
            if stderr and "error" in stderr.lower():
                raise RuntimeError(f"openssl pkeyutl -decap failed: {stderr}")

            with open(ss_path, "rb") as f:
                shared_secret = f.read()

        return shared_secret

    # Signature operations
    def sig_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate signature keypair."""
        alg_map = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        stdout, stderr = self._run_openssl([
            "genpkey", "-algorithm", alg_map[algorithm],
            "-outform", "DER",
        ])
        if stderr and "error" in stderr.lower():
            raise RuntimeError(f"openssl genpkey failed: {stderr}")
        private_key_der = stdout

        stdout, stderr = self._run_openssl([
            "pkey", "-in", "/dev/stdin", "-inform", "DER",
            "-pubout", "-outform", "DER",
        ], input_data=private_key_der)
        if stderr and "error" in stderr.lower():
            raise RuntimeError(f"openssl pkey pubout failed: {stderr}")
        public_key_der = stdout

        return public_key_der, private_key_der

    def sig_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        """Sign message using openssl pkeyutl -sign with file-based I/O."""
        import tempfile
        import os

        alg_map = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path = os.path.join(tmpdir, "priv.der")
            msg_path = os.path.join(tmpdir, "msg.bin")
            sig_path = os.path.join(tmpdir, "sig.der")

            with open(priv_path, "wb") as f:
                f.write(private_key)
            with open(msg_path, "wb") as f:
                f.write(message)

            stdout, stderr = self._run_openssl([
                "pkeyutl", "-sign",
                "-inkey", priv_path,
                "-in", msg_path,
                "-out", sig_path,
            ])
            if stderr and "error" in stderr.lower():
                raise RuntimeError(f"openssl pkeyutl -sign failed: {stderr}")

            with open(sig_path, "rb") as f:
                signature = f.read()

        return signature

    def sig_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature using openssl pkeyutl -verify with file-based I/O."""
        import tempfile
        import os

        alg_map = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        with tempfile.TemporaryDirectory() as tmpdir:
            pub_path = os.path.join(tmpdir, "pub.der")
            msg_path = os.path.join(tmpdir, "msg.bin")
            sig_path = os.path.join(tmpdir, "sig.der")

            with open(pub_path, "wb") as f:
                f.write(public_key)
            with open(msg_path, "wb") as f:
                f.write(message)
            with open(sig_path, "wb") as f:
                f.write(signature)

            _, stderr = self._run_openssl([
                "pkeyutl", "-verify",
                "-inkey", pub_path, "-pubin",
                "-in", msg_path,
                "-sigfile", sig_path,
            ])

        stderr_str = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else str(stderr)
        return "Verification Failure" not in stderr_str and "error" not in stderr_str.lower()

    # Classical baselines using cryptography library
    def classical_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        """Generate classical keypair using cryptography library."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

        if algorithm == "X25519":
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif algorithm == "P-256":
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif algorithm == "RSA-2048":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif algorithm == "Ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        else:
            raise ValueError(f"Unsupported classical algorithm: {algorithm}")

    def classical_dh(self, algorithm: str, private_key: bytes, peer_public: bytes) -> bytes:
        """Classical key agreement."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519

        if algorithm == "X25519":
            # Load the private key and extract the raw private bytes
            priv_key = serialization.load_der_private_key(private_key, password=None)
            if not isinstance(priv_key, x25519.X25519PrivateKey):
                raise ValueError("Expected X25519 private key")
            priv_raw = priv_key.private_bytes_raw()
            priv = x25519.X25519PrivateKey.from_private_bytes(priv_raw)

            # Load peer public key
            peer_key = serialization.load_der_public_key(peer_public)
            if not isinstance(peer_key, x25519.X25519PublicKey):
                raise ValueError("Expected X25519 public key")
            peer_raw = peer_key.public_bytes_raw()
            peer = x25519.X25519PublicKey.from_public_bytes(peer_raw)

            return priv.exchange(peer)
        elif algorithm == "P-256":
            priv = serialization.load_der_private_key(private_key, password=None)
            peer = serialization.load_der_public_key(peer_public)
            return priv.exchange(ec.ECDH(), peer)
        else:
            raise ValueError(f"Unsupported classical DH algorithm: {algorithm}")

    def classical_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        """Classical signature."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        priv = serialization.load_der_private_key(private_key, password=None)

        if algorithm == "RSA-2048":
            return priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == "P-256":
            return priv.sign(message, ec.ECDSA(hashes.SHA256()))
        elif algorithm == "Ed25519":
            return priv.sign(message)
        else:
            raise ValueError(f"Unsupported classical sign algorithm: {algorithm}")

    def classical_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Classical signature verification."""
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        try:
            pub = serialization.load_der_public_key(public_key)

            if algorithm == "RSA-2048":
                pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            elif algorithm == "P-256":
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            elif algorithm == "Ed25519":
                pub.verify(signature, message)
            else:
                raise ValueError(f"Unsupported classical verify algorithm: {algorithm}")
            return True
        except Exception:
            return False

    def tls_handshake_benchmark(
        self,
        group: str,
        host: str = "127.0.0.1",
        port: int = 0,
        iterations: int = 30,
    ) -> dict[str, Any]:
        """Measure local TLS 1.3 client-handshake command latency.

        A temporary local OpenSSL server and self-signed certificate are created
        for this benchmark. Only loopback hosts are accepted. The reported time
        includes starting ``openssl s_client`` and is therefore a command-level
        latency measurement, not a pure in-process TLS library benchmark.
        """
        import socket
        import statistics
        import tempfile
        from pathlib import Path

        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("TLS benchmark is restricted to loopback hosts")
        if iterations < 1:
            raise ValueError("iterations must be at least 1")
        if not self.available:
            raise BackendUnavailableError("OpenSSL is not available")

        with tempfile.TemporaryDirectory(prefix="quantumshield-tls-bench-") as temp_dir:
            temp = Path(temp_dir)
            cert_path, key_path = temp / "server.crt", temp / "server.key"
            cert_cmd = [
                self.openssl_path, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path), "-days", "1",
                "-subj", "/CN=localhost",
            ]
            cert_proc = subprocess.run(cert_cmd, capture_output=True, text=True, timeout=30)
            if cert_proc.returncode != 0:
                raise RuntimeError(f"Could not create temporary benchmark certificate: {cert_proc.stderr.strip()}")

            bind_host = "::1" if host == "::1" else "127.0.0.1"
            if port == 0:
                family = socket.AF_INET6 if bind_host == "::1" else socket.AF_INET
                with socket.socket(family, socket.SOCK_STREAM) as probe:
                    probe.bind((bind_host, 0))
                    port = probe.getsockname()[1]

            server_cmd = [
                self.openssl_path, "s_server", "-accept", f"{bind_host}:{port}",
                "-cert", str(cert_path), "-key", str(key_path), "-tls1_3",
                "-groups", group, "-quiet",
            ]
            server = subprocess.Popen(server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5.0
                while True:
                    if server.poll() is not None:
                        error = server.stderr.read() if server.stderr else ""
                        raise RuntimeError(f"OpenSSL TLS benchmark server failed for group {group}: {error.strip()}")
                    try:
                        with socket.create_connection((bind_host, port), timeout=0.1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("Timed out waiting for local TLS benchmark server")
                        time.sleep(0.05)

                latencies: list[float] = []
                for _ in range(iterations):
                    client_cmd = [
                        self.openssl_path, "s_client", "-connect", f"{bind_host}:{port}",
                        "-tls1_3", "-groups", group, "-brief", "-no-CAfile", "-no-CApath",
                    ]
                    started = time.perf_counter()
                    client = subprocess.run(client_cmd, input="", capture_output=True, text=True, timeout=10)
                    elapsed_ms = (time.perf_counter() - started) * 1000.0
                    output = client.stdout + client.stderr
                    if client.returncode != 0 or "Protocol version: TLSv1.3" not in output:
                        raise RuntimeError(f"TLS handshake failed for group {group}: {output.strip()[-1000:]}")
                    latencies.append(elapsed_ms)

                ordered = sorted(latencies)
                return {
                    "group": group,
                    "host": bind_host,
                    "port": port,
                    "iterations": iterations,
                    "median_ms": statistics.median(ordered),
                    "p95_ms": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
                    "min_ms": ordered[0],
                    "max_ms": ordered[-1],
                    "mean_ms": statistics.mean(ordered),
                    "measurement_scope": "local OpenSSL s_client process plus TLS 1.3 handshake",
                }
            finally:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=2)


# --------------------------------------------------------------------------
# OQS Python Bindings Backend
# --------------------------------------------------------------------------


class OQSBackend(Backend):
    """liboqs Python bindings backend."""

    def __init__(self):
        self._oqs = None
        self._version: str | None = None
        self._checked = False

    @property
    def name(self) -> str:
        return "oqs"

    @property
    def available(self) -> bool:
        return self.get_version() is not None

    def get_version(self) -> str | None:
        if self._checked:
            return self._version
        try:
            import oqs
            self._oqs = oqs
            self._version = getattr(oqs, "__version__", "unknown")
            self._checked = True
            return self._version
        except ImportError:
            self._checked = True
            return None

    def _require_oqs(self):
        if not self.available:
            raise BackendUnavailableError("oqs python bindings not available")

    def kem_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        self._require_oqs()
        alg_map = {
            "ML-KEM-512": "ML-KEM-512",
            "ML-KEM-768": "ML-KEM-768",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        kem = self._oqs.KeyEncapsulation(alg_map[algorithm])
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        return public_key, private_key

    def kem_encaps(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        self._require_oqs()
        alg_map = {
            "ML-KEM-512": "ML-KEM-512",
            "ML-KEM-768": "ML-KEM-768",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        kem = self._oqs.KeyEncapsulation(alg_map[algorithm])
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def kem_decaps(self, algorithm: str, private_key: bytes, ciphertext: bytes) -> bytes:
        self._require_oqs()
        alg_map = {
            "ML-KEM-512": "ML-KEM-512",
            "ML-KEM-768": "ML-KEM-768",
            "ML-KEM-1024": "ML-KEM-1024",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

        kem = self._oqs.KeyEncapsulation(alg_map[algorithm])
        kem.import_secret_key(private_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    def sig_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        self._require_oqs()
        alg_map = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        sig = self._oqs.Signature(alg_map[algorithm])
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
        return public_key, private_key

    def sig_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        self._require_oqs()
        alg_map = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        sig = self._oqs.Signature(alg_map[algorithm])
        sig.import_secret_key(private_key)
        return sig.sign(message)

    def sig_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self._require_oqs()
        alg_map = {
            "ML-DSA-44": "ML-DSA-44",
            "ML-DSA-65": "ML-DSA-65",
            "ML-DSA-87": "ML-DSA-87",
            "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f": "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s": "SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f": "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s": "SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f": "SLH-DSA-SHA2-256f",
        }
        if algorithm not in alg_map:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        sig = self._oqs.Signature(alg_map[algorithm])
        return sig.verify(message, signature, public_key)

    # Classical baselines use cryptography library (same as OpenSSL backend)
    def classical_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        self._require_oqs()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

        if algorithm == "X25519":
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif algorithm == "P-256":
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif algorithm == "RSA-2048":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif algorithm == "Ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        else:
            raise ValueError(f"Unsupported classical algorithm: {algorithm}")

    def classical_dh(self, algorithm: str, private_key: bytes, peer_public: bytes) -> bytes:
        self._require_oqs()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519

        if algorithm == "X25519":
            priv = x25519.X25519PrivateKey.from_private_bytes(
                serialization.load_der_private_key(private_key, password=None).private_bytes_raw()
            )
            peer = x25519.X25519PublicKey.from_public_bytes(
                serialization.load_der_public_key(peer_public).public_bytes_raw()
            )
            return priv.exchange(peer)
        elif algorithm == "P-256":
            priv = serialization.load_der_private_key(private_key, password=None)
            peer = serialization.load_der_public_key(peer_public)
            return priv.exchange(ec.ECDH(), peer)
        else:
            raise ValueError(f"Unsupported classical DH algorithm: {algorithm}")

    def classical_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        self._require_oqs()
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        priv = serialization.load_der_private_key(private_key, password=None)

        if algorithm == "RSA-2048":
            return priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == "P-256":
            return priv.sign(message, ec.ECDSA(hashes.SHA256()))
        elif algorithm == "Ed25519":
            return priv.sign(message)
        else:
            raise ValueError(f"Unsupported classical sign algorithm: {algorithm}")

    def classical_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self._require_oqs()
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        try:
            pub = serialization.load_der_public_key(public_key)

            if algorithm == "RSA-2048":
                pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            elif algorithm == "P-256":
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            elif algorithm == "Ed25519":
                pub.verify(signature, message)
            else:
                raise ValueError(f"Unsupported classical verify algorithm: {algorithm}")
            return True
        except Exception:
            return False

    def tls_handshake_benchmark(
        self,
        group: str,
        host: str = "127.0.0.1",
        port: int = 4433,
        iterations: int = 30,
    ) -> dict[str, Any]:
        raise NotImplementedError("TLS handshake benchmark not implemented for oqs backend")


# --------------------------------------------------------------------------
# Fake Backend for Testing
# --------------------------------------------------------------------------


class FakeBackend(Backend):
    """Fake backend for testing - returns deterministic fake data."""

    def __init__(self):
        self._call_log: list[tuple[str, tuple, dict]] = []
        # Track last signed message per private key for tamper detection
        self._last_signed: dict[bytes, tuple[str, bytes]] = {}

    @property
    def name(self) -> str:
        return "fake"

    @property
    def available(self) -> bool:
        return True

    def get_version(self) -> str | None:
        return "fake-1.0"

    def _log(self, method: str, args: tuple, kwargs: dict):
        self._call_log.append((method, args, kwargs))

    def _verify_key_match(self, private_key: bytes, message: bytes) -> bool:
        """Check if the message matches the last signed message for this key."""
        entry = self._last_signed.get(private_key)
        if entry is None:
            return False
        alg, last_msg = entry
        return message == last_msg

    # Fixed sizes for each algorithm
    _kem_sizes = {
        "ML-KEM-512": (800, 1632, 768, 32),
        "ML-KEM-768": (1184, 2400, 1088, 32),
        "ML-KEM-1024": (1568, 3168, 1568, 32),
    }
    _sig_sizes = {
        "ML-DSA-44": (1312, 2560, 2420),
        "ML-DSA-65": (1952, 4032, 3309),
        "ML-DSA-87": (2592, 4896, 4627),
        "SLH-DSA-SHA2-128s": (32, 64, 7856),
        "SLH-DSA-SHA2-128f": (32, 64, 17088),
        "SLH-DSA-SHA2-192s": (48, 96, 16224),
        "SLH-DSA-SHA2-192f": (48, 96, 35664),
        "SLH-DSA-SHA2-256s": (64, 128, 29792),
        "SLH-DSA-SHA2-256f": (64, 128, 49856),
    }
    _classical_sizes = {
        "X25519": (32, 32),
        "P-256": (91, 121),  # approximate DER sizes
        "RSA-2048": (294, 1219),
        "Ed25519": (32, 32),
    }

    def kem_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        self._log("kem_keygen", (algorithm,), {})
        if algorithm not in self._kem_sizes:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
        pk_len, sk_len, _, _ = self._kem_sizes[algorithm]
        return b"P" * pk_len, b"S" * sk_len

    def kem_encaps(self, algorithm: str, public_key: bytes) -> tuple[bytes, bytes]:
        self._log("kem_encaps", (algorithm,), {"public_key_len": len(public_key)})
        if algorithm not in self._kem_sizes:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
        _, _, ct_len, ss_len = self._kem_sizes[algorithm]
        return b"C" * ct_len, b"S" * ss_len

    def kem_decaps(self, algorithm: str, private_key: bytes, ciphertext: bytes) -> bytes:
        self._log("kem_decaps", (algorithm,), {"private_key_len": len(private_key), "ciphertext_len": len(ciphertext)})
        if algorithm not in self._kem_sizes:
            raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
        _, _, _, ss_len = self._kem_sizes[algorithm]
        return b"S" * ss_len

    def sig_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        self._log("sig_keygen", (algorithm,), {})
        if algorithm not in self._sig_sizes:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        pk_len, sk_len, _ = self._sig_sizes[algorithm]
        return b"P" * pk_len, b"S" * sk_len

    def sig_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        self._log("sig_sign", (algorithm,), {"private_key_len": len(private_key), "message_len": len(message)})
        if algorithm not in self._sig_sizes:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        _, _, sig_len = self._sig_sizes[algorithm]
        self._last_signed[private_key] = (algorithm, message)
        return b"S" * sig_len

    def sig_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self._log("sig_verify", (algorithm,), {"public_key_len": len(public_key), "message_len": len(message), "signature_len": len(signature)})
        if algorithm not in self._sig_sizes:
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        # Find the private key that signed this (in fake backend, we track by private key)
        # For testing, we check if message matches what was signed with this private key
        # Since we don't have the private key here, we can't do full verification
        # But we can at least track if the SAME private key was used to sign
        # For round-trip tests, the verify is called with the same key pair
        # We'll check if any tracked message matches
        for stored_key, (stored_alg, stored_msg) in self._last_signed.items():
            if stored_alg == algorithm and stored_msg == message:
                return True
        return False

    def classical_keygen(self, algorithm: str) -> tuple[bytes, bytes]:
        self._log("classical_keygen", (algorithm,), {})
        if algorithm not in self._classical_sizes:
            raise ValueError(f"Unsupported classical algorithm: {algorithm}")
        pk_len, sk_len = self._classical_sizes[algorithm]
        return b"P" * pk_len, b"S" * sk_len

    def classical_dh(self, algorithm: str, private_key: bytes, peer_public: bytes) -> bytes:
        self._log("classical_dh", (algorithm,), {"private_key_len": len(private_key), "peer_public_len": len(peer_public)})
        if algorithm == "X25519":
            return b"S" * 32
        elif algorithm == "P-256":
            return b"S" * 32
        else:
            raise ValueError(f"Unsupported classical DH algorithm: {algorithm}")

    def classical_sign(self, algorithm: str, private_key: bytes, message: bytes) -> bytes:
        self._log("classical_sign", (algorithm,), {"private_key_len": len(private_key), "message_len": len(message)})
        if algorithm == "RSA-2048":
            sig = b"S" * 256
        elif algorithm == "P-256":
            sig = b"S" * 64
        elif algorithm == "Ed25519":
            sig = b"S" * 64
        else:
            raise ValueError(f"Unsupported classical sign algorithm: {algorithm}")
        self._last_signed[private_key] = (algorithm, message)
        return sig

    def classical_verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self._log("classical_verify", (algorithm,), {"public_key_len": len(public_key), "message_len": len(message), "signature_len": len(signature)})
        for stored_key, (stored_alg, stored_msg) in self._last_signed.items():
            if stored_alg == algorithm and stored_msg == message:
                return True
        return False

    def tls_handshake_benchmark(
        self,
        group: str,
        host: str = "127.0.0.1",
        port: int = 4433,
        iterations: int = 30,
    ) -> dict[str, Any]:
        self._log("tls_handshake_benchmark", (group, host, port, iterations), {})
        return {
            "group": group,
            "iterations": iterations,
            "median_ms": 1.5,
            "p95_ms": 2.1,
            "min_ms": 1.0,
            "max_ms": 3.5,
            "mean_ms": 1.6,
            "client_bytes": 1216 if "MLKEM" in group else 64,
            "server_bytes": 1400 if "MLKEM" in group else 1200,
            "note": "fake backend - simulated results",
        }


# --------------------------------------------------------------------------
# Backend Factory
# --------------------------------------------------------------------------


def get_backend(prefer: str | None = None) -> Backend:
    """Get the best available backend.

    Args:
        prefer: 'openssl', 'oqs', or 'fake'. If None, auto-detect.

    Returns:
        Backend instance.

    Raises:
        BackendUnavailableError: If no backend is available.
    """
    if prefer == "fake":
        return FakeBackend()

    if prefer == "openssl" or prefer is None:
        backend = OpenSSLBackend()
        if backend.available:
            return backend

    if prefer == "oqs" or prefer is None:
        backend = OQSBackend()
        if backend.available:
            return backend

    # Fallback to fake for testing
    if prefer is None:
        return FakeBackend()

    raise BackendUnavailableError(f"No suitable backend found (preferred: {prefer})")


def list_available_backends() -> list[str]:
    """List names of available backends."""
    backends = []
    for backend_cls in [OpenSSLBackend, OQSBackend, FakeBackend]:
        backend = backend_cls()
        if backend.available:
            backends.append(backend.name)
    return backends