"""Tests for quantumshield.transition.backend module."""

import pytest

from quantumshield.transition.backend import (
    Backend,
    BackendUnavailableError,
    FakeBackend,
    OpenSSLBackend,
    OQSBackend,
    get_backend,
    list_available_backends,
)


class TestBackendProtocol:
    """Test the Backend abstract base class interface."""

    def test_backend_cannot_be_instantiated_directly(self):
        """Backend is abstract and cannot be instantiated."""
        with pytest.raises(TypeError):
            Backend()


class TestFakeBackend:
    """Tests for FakeBackend implementation."""

    @pytest.fixture
    def backend(self):
        return FakeBackend()

    def test_name(self, backend):
        assert backend.name == "fake"

    def test_available(self, backend):
        assert backend.available is True

    def test_get_version(self, backend):
        version = backend.get_version()
        assert isinstance(version, str)
        assert "fake" in version.lower()

    # KEM operations
    def test_kem_keygen_ml_kem_512(self, backend):
        pub, priv = backend.kem_keygen("ML-KEM-512")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)
        assert len(pub) > 0
        assert len(priv) > 0

    def test_kem_keygen_ml_kem_768(self, backend):
        pub, priv = backend.kem_keygen("ML-KEM-768")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_kem_keygen_ml_kem_1024(self, backend):
        pub, priv = backend.kem_keygen("ML-KEM-1024")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_kem_encaps_ml_kem_512(self, backend):
        pub, _ = backend.kem_keygen("ML-KEM-512")
        ct, ss = backend.kem_encaps("ML-KEM-512", pub)
        assert isinstance(ct, bytes)
        assert isinstance(ss, bytes)
        assert len(ct) > 0
        assert len(ss) == 32

    def test_kem_decaps_ml_kem_512(self, backend):
        pub, priv = backend.kem_keygen("ML-KEM-512")
        ct, ss1 = backend.kem_encaps("ML-KEM-512", pub)
        ss2 = backend.kem_decaps("ML-KEM-512", priv, ct)
        assert ss1 == ss2

    def test_kem_round_trip_all_algorithms(self, backend):
        for alg in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
            pub, priv = backend.kem_keygen(alg)
            ct, ss1 = backend.kem_encaps(alg, pub)
            ss2 = backend.kem_decaps(alg, priv, ct)
            assert ss1 == ss2, f"Round-trip failed for {alg}"

    def test_kem_unsupported_algorithm(self, backend):
        with pytest.raises(ValueError):
            backend.kem_keygen("UNSUPPORTED-KEM")

    # Signature operations
    def test_sig_keygen_ml_dsa_44(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-44")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_sig_keygen_ml_dsa_65(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-65")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_sig_keygen_ml_dsa_87(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-87")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_sig_keygen_slh_dsa(self, backend):
        pub, priv = backend.sig_keygen("SLH-DSA-SHA2-128s")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_sig_sign_verify_ml_dsa_44(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-44")
        message = b"test message"
        sig = backend.sig_sign("ML-DSA-44", priv, message)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

        result = backend.sig_verify("ML-DSA-44", pub, message, sig)
        assert result is True

    def test_sig_verify_tampered_fails(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-44")
        message = b"test message"
        sig = backend.sig_sign("ML-DSA-44", priv, message)

        tampered = message + b"X"
        result = backend.sig_verify("ML-DSA-44", pub, tampered, sig)
        assert result is False

    def test_sig_round_trip_all_algorithms(self, backend):
        for alg in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s"]:
            pub, priv = backend.sig_keygen(alg)
            message = b"test message for " + alg.encode()
            sig = backend.sig_sign(alg, priv, message)
            verify_ok = backend.sig_verify(alg, pub, message, sig)
            assert verify_ok is True, f"Verify failed for {alg}"

            tampered = message + b"X"
            tamper_ok = backend.sig_verify(alg, pub, tampered, sig)
            assert tamper_ok is False, f"Tamper check failed for {alg}"

    def test_sig_unsupported_algorithm(self, backend):
        with pytest.raises(ValueError):
            backend.sig_keygen("UNSUPPORTED-SIG")

    # Classical operations
    def test_classical_keygen_x25519(self, backend):
        pub, priv = backend.classical_keygen("X25519")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_classical_keygen_p256(self, backend):
        pub, priv = backend.classical_keygen("P-256")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_classical_keygen_rsa2048(self, backend):
        pub, priv = backend.classical_keygen("RSA-2048")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_classical_keygen_ed25519(self, backend):
        pub, priv = backend.classical_keygen("Ed25519")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    def test_classical_dh_x25519(self, backend):
        pub1, priv1 = backend.classical_keygen("X25519")
        pub2, priv2 = backend.classical_keygen("X25519")
        ss1 = backend.classical_dh("X25519", priv1, pub2)
        ss2 = backend.classical_dh("X25519", priv2, pub1)
        assert ss1 == ss2
        assert len(ss1) == 32

    def test_classical_dh_p256(self, backend):
        pub1, priv1 = backend.classical_keygen("P-256")
        pub2, priv2 = backend.classical_keygen("P-256")
        ss1 = backend.classical_dh("P-256", priv1, pub2)
        ss2 = backend.classical_dh("P-256", priv2, pub1)
        assert ss1 == ss2
        assert len(ss1) == 32

    def test_classical_sign_verify_rsa2048(self, backend):
        pub, priv = backend.classical_keygen("RSA-2048")
        message = b"test message"
        sig = backend.classical_sign("RSA-2048", priv, message)
        assert isinstance(sig, bytes)

        result = backend.classical_verify("RSA-2048", pub, message, sig)
        assert result is True

    def test_classical_sign_verify_p256(self, backend):
        pub, priv = backend.classical_keygen("P-256")
        message = b"test message"
        sig = backend.classical_sign("P-256", priv, message)
        result = backend.classical_verify("P-256", pub, message, sig)
        assert result is True

    def test_classical_sign_verify_ed25519(self, backend):
        pub, priv = backend.classical_keygen("Ed25519")
        message = b"test message"
        sig = backend.classical_sign("Ed25519", priv, message)
        result = backend.classical_verify("Ed25519", pub, message, sig)
        assert result is True

    def test_classical_verify_tampered_fails(self, backend):
        pub, priv = backend.classical_keygen("Ed25519")
        message = b"test message"
        sig = backend.classical_sign("Ed25519", priv, message)
        tampered = message + b"X"
        result = backend.classical_verify("Ed25519", pub, tampered, sig)
        assert result is False

    def test_classical_unsupported_algorithm(self, backend):
        with pytest.raises(ValueError):
            backend.classical_keygen("UNSUPPORTED")


class TestOpenSSLBackend:
    """Tests for OpenSSLBackend (only run if OpenSSL is available)."""

    @pytest.fixture
    def backend(self):
        return OpenSSLBackend()

    def test_name(self, backend):
        assert backend.name == "openssl"

    def test_get_version(self, backend):
        version = backend.get_version()
        if backend.available:
            assert version is not None
            assert "OpenSSL" in version
        else:
            assert version is None

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_kem_keygen(self, backend):
        pub, priv = backend.kem_keygen("ML-KEM-512")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)
        assert len(pub) > 0
        assert len(priv) > 0

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_kem_round_trip(self, backend):
        pub, priv = backend.kem_keygen("ML-KEM-512")
        ct, ss1 = backend.kem_encaps("ML-KEM-512", pub)
        ss2 = backend.kem_decaps("ML-KEM-512", priv, ct)
        assert ss1 == ss2

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_sig_keygen_ml_dsa(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-44")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_sig_sign_verify_ml_dsa(self, backend):
        pub, priv = backend.sig_keygen("ML-DSA-44")
        message = b"test message"
        sig = backend.sig_sign("ML-DSA-44", priv, message)
        assert backend.sig_verify("ML-DSA-44", pub, message, sig) is True

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_sig_slh_dsa(self, backend):
        pub, priv = backend.sig_keygen("SLH-DSA-SHA2-128s")
        message = b"test message"
        sig = backend.sig_sign("SLH-DSA-SHA2-128s", priv, message)
        assert backend.sig_verify("SLH-DSA-SHA2-128s", pub, message, sig) is True

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_classical_keygen(self, backend):
        pub, priv = backend.classical_keygen("X25519")
        assert isinstance(pub, bytes)
        assert isinstance(priv, bytes)

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_classical_dh_x25519(self, backend):
        pub1, priv1 = backend.classical_keygen("X25519")
        pub2, priv2 = backend.classical_keygen("X25519")
        ss1 = backend.classical_dh("X25519", priv1, pub2)
        ss2 = backend.classical_dh("X25519", priv2, pub1)
        assert ss1 == ss2

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_classical_sign_verify_ed25519(self, backend):
        pub, priv = backend.classical_keygen("Ed25519")
        message = b"test message"
        sig = backend.classical_sign("Ed25519", priv, message)
        assert backend.classical_verify("Ed25519", pub, message, sig) is True

    @pytest.mark.skipif(not OpenSSLBackend().available, reason="OpenSSL not available")
    def test_classical_sign_verify_rsa2048(self, backend):
        pub, priv = backend.classical_keygen("RSA-2048")
        message = b"test message"
        sig = backend.classical_sign("RSA-2048", priv, message)
        assert backend.classical_verify("RSA-2048", pub, message, sig) is True


class TestOQSBackend:
    """Tests for OQSBackend (scaffold only)."""

    @pytest.fixture
    def backend(self):
        return OQSBackend()

    def test_name(self, backend):
        assert backend.name == "oqs"

    def test_available_false(self, backend):
        assert backend.available is False

    def test_get_version_none(self, backend):
        assert backend.get_version() is None

    def test_kem_keygen_raises(self, backend):
        with pytest.raises(BackendUnavailableError):
            backend.kem_keygen("ML-KEM-512")

    def test_sig_keygen_raises(self, backend):
        with pytest.raises(BackendUnavailableError):
            backend.sig_keygen("ML-DSA-44")

    def test_classical_keygen_raises(self, backend):
        with pytest.raises(BackendUnavailableError):
            backend.classical_keygen("X25519")


class TestBackendFactory:
    """Tests for backend factory functions."""

    def test_list_available_backends(self):
        backends = list_available_backends()
        assert isinstance(backends, list)
        assert "fake" in backends
        assert "openssl" in backends

    def test_get_backend_fake(self):
        backend = get_backend("fake")
        assert isinstance(backend, FakeBackend)

    def test_get_backend_openssl(self):
        backend = get_backend("openssl")
        assert isinstance(backend, OpenSSLBackend)

    def test_get_backend_oqs_unavailable(self):
        with pytest.raises(BackendUnavailableError):
            get_backend("oqs")

    def test_get_backend_unknown_raises(self):
        with pytest.raises(BackendUnavailableError):
            get_backend("unknown")

    def test_get_backend_auto_detect(self):
        backend = get_backend()
        assert backend is not None
        assert hasattr(backend, "name")


class TestAlgorithmConstants:
    """Test that algorithm lists are properly defined."""

    def test_kem_algorithms(self):
        from quantumshield.transition.benchmark import KEM_ALGORITHMS
        assert KEM_ALGORITHMS == ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

    def test_sig_algorithms(self):
        from quantumshield.transition.benchmark import SIG_ALGORITHMS
        assert SIG_ALGORITHMS == ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

    def test_slh_dsa_algorithms(self):
        from quantumshield.transition.benchmark import SLH_DSA_ALGORITHMS
        assert SLH_DSA_ALGORITHMS == ["SLH-DSA-SHA2-128s"]

    def test_classical_kem_baselines(self):
        from quantumshield.transition.benchmark import CLASSICAL_KEM_BASELINES
        assert CLASSICAL_KEM_BASELINES == ["X25519", "P-256"]

    def test_classical_sig_baselines(self):
        from quantumshield.transition.benchmark import CLASSICAL_SIG_BASELINES
        assert CLASSICAL_SIG_BASELINES == ["RSA-2048", "P-256", "Ed25519"]