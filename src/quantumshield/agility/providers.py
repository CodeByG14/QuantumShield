"""Provider adapters for crypto-agility.

Classical providers use the cryptography library.
PQC providers use Phase 3 backend interfaces.
"""

from __future__ import annotations

import abc
import warnings
from dataclasses import dataclass
from typing import Any, Optional

from quantumshield.transition.backend import (
    Backend,
    BackendUnavailableError,
    FakeBackend,
    OpenSSLBackend,
    OQSBackend,
    get_backend,
    list_available_backends,
)


class ProviderError(RuntimeError):
    """Raised when a provider operation fails."""
    pass


class AlgorithmNotSupportedError(ProviderError):
    """Raised when an algorithm is not supported by the provider."""
    pass


class ProviderUnavailableError(ProviderError):
    """Raised when the underlying backend is unavailable."""
    pass


# --------------------------------------------------------------------------
# Abstract Provider Interfaces
# --------------------------------------------------------------------------


class KEMProvider(abc.ABC):
    """Abstract interface for Key Encapsulation Mechanism providers."""

    @property
    @abc.abstractmethod
    def algorithm(self) -> str:
        """Canonical algorithm name."""
        pass

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this provider is available for use."""
        pass

    @abc.abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Generate keypair. Returns (public_key, private_key)."""
        pass

    @abc.abstractmethod
    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate. Returns (ciphertext, shared_secret)."""
        pass

    @abc.abstractmethod
    def decaps(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate. Returns shared_secret."""
        pass


class SignatureProvider(abc.ABC):
    """Abstract interface for Digital Signature providers."""

    @property
    @abc.abstractmethod
    def algorithm(self) -> str:
        """Canonical algorithm name."""
        pass

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this provider is available for use."""
        pass

    @abc.abstractmethod
    def keygen(self) -> tuple[bytes, bytes]:
        """Generate keypair. Returns (public_key, private_key)."""
        pass

    @abc.abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign message. Returns signature."""
        pass

    @abc.abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify signature. Returns True if valid."""
        pass


class HashProvider(abc.ABC):
    """Abstract interface for Hash providers."""

    @property
    @abc.abstractmethod
    def algorithm(self) -> str:
        """Canonical algorithm name."""
        pass

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this provider is available for use."""
        pass

    @abc.abstractmethod
    def hash(self, data: bytes) -> bytes:
        """Compute hash. Returns digest."""
        pass


class AEADProvider(abc.ABC):
    """Abstract interface for AEAD providers."""

    @property
    @abc.abstractmethod
    def algorithm(self) -> str:
        """Canonical algorithm name."""
        pass

    @property
    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this provider is available for use."""
        pass

    @abc.abstractmethod
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt. Returns ciphertext + tag."""
        pass

    @abc.abstractmethod
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt. Returns plaintext."""
        pass


class ClassicalAEADProvider(AEADProvider):
    """Authenticated encryption using AES-GCM or ChaCha20-Poly1305."""
    _SUPPORTED = {"AES-128-GCM": {"key_bytes": 16, "security_level": 1},
                  "AES-256-GCM": {"key_bytes": 32, "security_level": 2},
                  "ChaCha20-Poly1305": {"key_bytes": 32, "security_level": 2}}

    def __init__(self, algorithm: str):
        if algorithm not in self._SUPPORTED:
            raise AlgorithmNotSupportedError(f"Unsupported AEAD algorithm: {algorithm}")
        self._algorithm = algorithm

    @property
    def algorithm(self) -> str: return self._algorithm
    @property
    def available(self) -> bool: return True

    def _cipher(self, key: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        expected = self._SUPPORTED[self.algorithm]["key_bytes"]
        if len(key) != expected: raise ValueError(f"{self.algorithm} requires a {expected}-byte key")
        return ChaCha20Poly1305(key) if self.algorithm == "ChaCha20-Poly1305" else AESGCM(key)

    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        if len(nonce) != 12: raise ValueError("AEAD nonce must be 12 bytes")
        return self._cipher(key).encrypt(nonce, plaintext, associated_data)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = b"") -> bytes:
        if len(nonce) != 12: raise ValueError("AEAD nonce must be 12 bytes")
        return self._cipher(key).decrypt(nonce, ciphertext, associated_data)


# --------------------------------------------------------------------------
# Classical Providers (cryptography library)
# --------------------------------------------------------------------------


class ClassicalKEMProvider(KEMProvider):
    """Classical KEM provider using cryptography library."""

    _SUPPORTED = {
        "X25519": {"kind": "kem", "security_level": 1},
        "P-256": {"kind": "kem", "security_level": 1},
    }

    def __init__(self, algorithm: str):
        if algorithm not in self._SUPPORTED:
            raise AlgorithmNotSupportedError(f"Unsupported classical KEM algorithm: {algorithm}")
        self._algorithm = algorithm

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def available(self) -> bool:
        return True  # cryptography is a hard dependency

    def keygen(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519

        if self._algorithm == "X25519":
            priv = x25519.X25519PrivateKey.generate()
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif self._algorithm == "P-256":
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        raise AlgorithmNotSupportedError(f"Unsupported algorithm: {self._algorithm}")

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519

        if self._algorithm == "X25519":
            peer_key = serialization.load_der_public_key(public_key)
            if not isinstance(peer_key, x25519.X25519PublicKey):
                raise ValueError("Expected X25519 public key")
            ephemeral_priv = x25519.X25519PrivateKey.generate()
            ephemeral_pub = ephemeral_priv.public_key()
            shared_secret = ephemeral_priv.exchange(peer_key)
            ciphertext = ephemeral_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return ciphertext, shared_secret
        elif self._algorithm == "P-256":
            peer_key = serialization.load_der_public_key(public_key)
            if not isinstance(peer_key, ec.EllipticCurvePublicKey):
                raise ValueError("Expected P-256 public key")
            ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
            ephemeral_pub = ephemeral_priv.public_key()
            shared_secret = ephemeral_priv.exchange(ec.ECDH(), peer_key)
            ciphertext = ephemeral_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            return ciphertext, shared_secret
        raise AlgorithmNotSupportedError(f"Unsupported algorithm: {self._algorithm}")

    def decaps(self, private_key: bytes, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, x25519

        if self._algorithm == "X25519":
            priv_key = serialization.load_der_private_key(private_key, password=None)
            if not isinstance(priv_key, x25519.X25519PrivateKey):
                raise ValueError("Expected X25519 private key")
            peer_key = serialization.load_der_public_key(ciphertext)
            if not isinstance(peer_key, x25519.X25519PublicKey):
                raise ValueError("Expected X25519 public key (ephemeral)")
            return priv_key.exchange(peer_key)
        elif self._algorithm == "P-256":
            priv = serialization.load_der_private_key(private_key, password=None)
            peer = serialization.load_der_public_key(ciphertext)
            return priv.exchange(ec.ECDH(), peer)
        raise AlgorithmNotSupportedError(f"Unsupported algorithm: {self._algorithm}")


class ClassicalSignatureProvider(SignatureProvider):
    """Classical signature provider using cryptography library."""

    _SUPPORTED = {
        "RSA-2048": {"kind": "sig", "security_level": 1},
        "P-256": {"kind": "sig", "security_level": 1},
        "Ed25519": {"kind": "sig", "security_level": 1},
    }

    def __init__(self, algorithm: str):
        if algorithm not in self._SUPPORTED:
            raise AlgorithmNotSupportedError(f"Unsupported classical signature algorithm: {algorithm}")
        self._algorithm = algorithm

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def available(self) -> bool:
        return True

    def keygen(self) -> tuple[bytes, bytes]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

        if self._algorithm == "RSA-2048":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif self._algorithm == "P-256":
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        elif self._algorithm == "Ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            return (
                pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            )
        raise AlgorithmNotSupportedError(f"Unsupported algorithm: {self._algorithm}")

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        priv = serialization.load_der_private_key(private_key, password=None)

        if self._algorithm == "RSA-2048":
            return priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
        elif self._algorithm == "P-256":
            return priv.sign(message, ec.ECDSA(hashes.SHA256()))
        elif self._algorithm == "Ed25519":
            return priv.sign(message)
        raise AlgorithmNotSupportedError(f"Unsupported algorithm: {self._algorithm}")

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

        try:
            pub = serialization.load_der_public_key(public_key)

            if self._algorithm == "RSA-2048":
                pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
            elif self._algorithm == "P-256":
                pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            elif self._algorithm == "Ed25519":
                pub.verify(signature, message)
            else:
                raise AlgorithmNotSupportedError(f"Unsupported algorithm: {self._algorithm}")
            return True
        except Exception:
            return False


class ClassicalHashProvider(HashProvider):
    """Classical hash provider using cryptography library."""

    _SUPPORTED = {
        "SHA-256": {"kind": "hash", "security_level": 1, "hash_alg": "SHA256"},
        "SHA-384": {"kind": "hash", "security_level": 2, "hash_alg": "SHA384"},
        "SHA-512": {"kind": "hash", "security_level": 3, "hash_alg": "SHA512"},
    }

    def __init__(self, algorithm: str):
        if algorithm not in self._SUPPORTED:
            raise AlgorithmNotSupportedError(f"Unsupported hash algorithm: {algorithm}")
        self._algorithm = algorithm
        self._hash_name = self._SUPPORTED[algorithm]["hash_alg"]

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def available(self) -> bool:
        return True

    def hash(self, data: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes

        hash_alg = getattr(hashes, self._hash_name)()
        digest = hashes.Hash(hash_alg)
        digest.update(data)
        return digest.finalize()


# --------------------------------------------------------------------------
# PQC Providers (Phase 3 Backends)
# --------------------------------------------------------------------------


class PQCKEMProvider(KEMProvider):
    """PQC KEM provider using Phase 3 backends."""

    _SUPPORTED = {
        "ML-KEM-512": {"kind": "kem", "security_level": 1},
        "ML-KEM-768": {"kind": "kem", "security_level": 3},
        "ML-KEM-1024": {"kind": "kem", "security_level": 5},
    }

    def __init__(self, algorithm: str, backend: Optional[Backend] = None, prefer: Optional[str] = None):
        if algorithm not in self._SUPPORTED:
            raise AlgorithmNotSupportedError(f"Unsupported PQC KEM algorithm: {algorithm}")
        self._algorithm = algorithm
        self._backend = backend or get_backend(prefer=prefer)

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def available(self) -> bool:
        return self._backend.available

    def keygen(self) -> tuple[bytes, bytes]:
        if not self._backend.available:
            raise ProviderUnavailableError(f"Backend {self._backend.name} is not available")
        return self._backend.kem_keygen(self._algorithm)

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        if not self._backend.available:
            raise ProviderUnavailableError(f"Backend {self._backend.name} is not available")
        return self._backend.kem_encaps(self._algorithm, public_key)

    def decaps(self, private_key: bytes, ciphertext: bytes) -> bytes:
        if not self._backend.available:
            raise ProviderUnavailableError(f"Backend {self._backend.name} is not available")
        return self._backend.kem_decaps(self._algorithm, private_key, ciphertext)


class PQCSignatureProvider(SignatureProvider):
    """PQC signature provider using Phase 3 backends."""

    _SUPPORTED = {
        "ML-DSA-44": {"kind": "sig", "security_level": 2},
        "ML-DSA-65": {"kind": "sig", "security_level": 3},
        "ML-DSA-87": {"kind": "sig", "security_level": 5},
        "SLH-DSA-SHA2-128s": {"kind": "sig", "security_level": 1},
        "SLH-DSA-SHA2-128f": {"kind": "sig", "security_level": 1},
        "SLH-DSA-SHA2-192s": {"kind": "sig", "security_level": 3},
        "SLH-DSA-SHA2-192f": {"kind": "sig", "security_level": 3},
        "SLH-DSA-SHA2-256s": {"kind": "sig", "security_level": 5},
        "SLH-DSA-SHA2-256f": {"kind": "sig", "security_level": 5},
    }

    def __init__(self, algorithm: str, backend: Optional[Backend] = None, prefer: Optional[str] = None):
        if algorithm not in self._SUPPORTED:
            raise AlgorithmNotSupportedError(f"Unsupported PQC signature algorithm: {algorithm}")
        self._algorithm = algorithm
        self._backend = backend or get_backend(prefer=prefer)

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @property
    def available(self) -> bool:
        return self._backend.available

    def keygen(self) -> tuple[bytes, bytes]:
        if not self._backend.available:
            raise ProviderUnavailableError(f"Backend {self._backend.name} is not available")
        return self._backend.sig_keygen(self._algorithm)

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        if not self._backend.available:
            raise ProviderUnavailableError(f"Backend {self._backend.name} is not available")
        return self._backend.sig_sign(self._algorithm, private_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not self._backend.available:
            raise ProviderUnavailableError(f"Backend {self._backend.name} is not available")
        return self._backend.sig_verify(self._algorithm, public_key, message, signature)


# --------------------------------------------------------------------------
# Provider Factory Functions
# --------------------------------------------------------------------------


def create_kem_provider(algorithm: str, backend: Optional[Backend] = None, prefer: Optional[str] = None) -> KEMProvider:
    """Factory for KEM providers (classical or PQC)."""
    if algorithm in ClassicalKEMProvider._SUPPORTED:
        return ClassicalKEMProvider(algorithm)
    if algorithm in PQCKEMProvider._SUPPORTED:
        return PQCKEMProvider(algorithm, backend=backend, prefer=prefer)
    raise AlgorithmNotSupportedError(f"No KEM provider for algorithm: {algorithm}")


def create_signature_provider(algorithm: str, backend: Optional[Backend] = None, prefer: Optional[str] = None) -> SignatureProvider:
    """Factory for signature providers (classical or PQC)."""
    if algorithm in ClassicalSignatureProvider._SUPPORTED:
        return ClassicalSignatureProvider(algorithm)
    if algorithm in PQCSignatureProvider._SUPPORTED:
        return PQCSignatureProvider(algorithm, backend=backend, prefer=prefer)
    raise AlgorithmNotSupportedError(f"No signature provider for algorithm: {algorithm}")


def create_aead_provider(algorithm: str) -> AEADProvider:
    """Factory for classical authenticated-encryption providers."""
    if algorithm in ClassicalAEADProvider._SUPPORTED:
        return ClassicalAEADProvider(algorithm)
    raise AlgorithmNotSupportedError(f"No AEAD provider for algorithm: {algorithm}")


def list_supported_aead_algorithms() -> list[str]:
    return list(ClassicalAEADProvider._SUPPORTED)


def create_hash_provider(algorithm: str) -> HashProvider:
    """Factory for hash providers."""
    if algorithm in ClassicalHashProvider._SUPPORTED:
        return ClassicalHashProvider(algorithm)
    raise AlgorithmNotSupportedError(f"No hash provider for algorithm: {algorithm}")


def list_supported_kem_algorithms() -> list[str]:
    """List all supported KEM algorithms."""
    return list(ClassicalKEMProvider._SUPPORTED.keys()) + list(PQCKEMProvider._SUPPORTED.keys())


def list_supported_signature_algorithms() -> list[str]:
    """List all supported signature algorithms."""
    return list(ClassicalSignatureProvider._SUPPORTED.keys()) + list(PQCSignatureProvider._SUPPORTED.keys())


def list_supported_hash_algorithms() -> list[str]:
    """List all supported hash algorithms."""
    return list(ClassicalHashProvider._SUPPORTED.keys())


def check_algorithm_availability(algorithm: str, backend: Optional[Backend] = None) -> tuple[bool, str]:
    """Check if an algorithm is available.

    Returns:
        (available: bool, reason: str)
    """
    if algorithm in ClassicalKEMProvider._SUPPORTED:
        return True, "classical (cryptography)"
    if algorithm in ClassicalSignatureProvider._SUPPORTED:
        return True, "classical (cryptography)"
    if algorithm in ClassicalHashProvider._SUPPORTED:
        return True, "classical (cryptography)"
    if algorithm in ClassicalAEADProvider._SUPPORTED:
        return True, "classical (cryptography)"
    if algorithm in PQCKEMProvider._SUPPORTED:
        if backend is None:
            backend = get_backend()
        if backend.available:
            return True, f"pqc ({backend.name})"
        return False, f"pqc backend unavailable ({backend.name})"
    if algorithm in PQCSignatureProvider._SUPPORTED:
        if backend is None:
            backend = get_backend()
        if backend.available:
            return True, f"pqc ({backend.name})"
        return False, f"pqc backend unavailable ({backend.name})"
    return False, "unknown algorithm"


# --------------------------------------------------------------------------
# Registration Helpers for Registry
# --------------------------------------------------------------------------


def register_all_providers(registry: Optional[Any] = None) -> None:
    """Register all known providers in the global registry.

    Args:
        registry: Optional ProviderRegistry instance. If None, uses global registry.
    """
    from quantumshield.agility.registry import (
        ProviderRegistry,
        ProviderMetadata,
        AlgorithmKind,
        ProviderStatus,
        get_registry,
        register_provider,
    )

    reg = registry or get_registry()

    # Classical KEMs
    for alg in ClassicalKEMProvider._SUPPORTED:
        meta = ProviderMetadata(
            name="cryptography",
            kind=AlgorithmKind.KEM,
            security_level=ClassicalKEMProvider._SUPPORTED[alg]["security_level"],
            status=ProviderStatus.AVAILABLE,
            version=None,
            algorithm=alg,
        )
        reg.register(alg, lambda a=alg: ClassicalKEMProvider(a), meta, allow_override=True)

    # Classical Signatures
    for alg in ClassicalSignatureProvider._SUPPORTED:
        meta = ProviderMetadata(
            name="cryptography",
            kind=AlgorithmKind.SIGNATURE,
            security_level=ClassicalSignatureProvider._SUPPORTED[alg]["security_level"],
            status=ProviderStatus.AVAILABLE,
            version=None,
            algorithm=alg,
        )
        reg.register(alg, lambda a=alg: ClassicalSignatureProvider(a), meta, allow_override=True)

    # Authenticated encryption
    for alg in ClassicalAEADProvider._SUPPORTED:
        meta = ProviderMetadata(
            name="cryptography", kind=AlgorithmKind.AEAD,
            security_level=ClassicalAEADProvider._SUPPORTED[alg]["security_level"],
            status=ProviderStatus.AVAILABLE, version=None, algorithm=alg,
        )
        reg.register(alg, lambda a=alg: ClassicalAEADProvider(a), meta, allow_override=True)

    # Hashes
    for alg in ClassicalHashProvider._SUPPORTED:
        meta = ProviderMetadata(
            name="cryptography",
            kind=AlgorithmKind.HASH,
            security_level=ClassicalHashProvider._SUPPORTED[alg]["security_level"],
            status=ProviderStatus.AVAILABLE,
            version=None,
            algorithm=alg,
        )
        reg.register(alg, lambda a=alg: ClassicalHashProvider(a), meta, allow_override=True)

    # PQC KEMs - use backend auto-detection
    for alg in PQCKEMProvider._SUPPORTED:
        # Check which backend is available
        backend = get_backend()
        status = ProviderStatus.AVAILABLE if backend.available else ProviderStatus.UNAVAILABLE
        meta = ProviderMetadata(
            name=backend.name if backend.available else "openssl",
            kind=AlgorithmKind.KEM,
            security_level=PQCKEMProvider._SUPPORTED[alg]["security_level"],
            status=status,
            version=backend.get_version() if backend.available else None,
            algorithm=alg,
        )
        reg.register(alg, lambda a=alg: PQCKEMProvider(a), meta, allow_override=True)

    # PQC Signatures
    for alg in PQCSignatureProvider._SUPPORTED:
        backend = get_backend()
        status = ProviderStatus.AVAILABLE if backend.available else ProviderStatus.UNAVAILABLE
        meta = ProviderMetadata(
            name=backend.name if backend.available else "openssl",
            kind=AlgorithmKind.SIGNATURE,
            security_level=PQCSignatureProvider._SUPPORTED[alg]["security_level"],
            status=status,
            version=backend.get_version() if backend.available else None,
            algorithm=alg,
        )
        reg.register(alg, lambda a=alg: PQCSignatureProvider(a), meta, allow_override=True)