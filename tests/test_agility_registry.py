"""Tests for agility provider registry."""

from __future__ import annotations

import pytest

from quantumshield.agility.registry import (
    ProviderRegistry,
    ProviderMetadata,
    AlgorithmKind,
    ProviderStatus,
    get_registry,
    register_provider,
    unregister_provider,
    get_provider_factory,
    get_provider_metadata,
    create_provider,
    list_registered_algorithms,
    list_provider_metadata,
)


def dummy_factory(algorithm: str):
    return f"provider-for-{algorithm}"


class TestProviderRegistry:
    """Tests for ProviderRegistry class."""

    def test_register_and_lookup(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(
            name="test",
            kind=AlgorithmKind.KEM,
            security_level=3,
            algorithm="TEST-KEM",
        )
        reg.register("TEST-KEM", dummy_factory, meta)

        assert reg.is_registered("TEST-KEM")
        assert reg.get_factory("TEST-KEM") is not None
        assert reg.get_metadata("TEST-KEM") == meta

    def test_register_duplicate_raises(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(
            name="test",
            kind=AlgorithmKind.KEM,
            algorithm="TEST-KEM",
        )
        reg.register("TEST-KEM", dummy_factory, meta)

        with pytest.raises(ValueError, match="already registered"):
            reg.register("TEST-KEM", dummy_factory, meta)

    def test_register_allow_override(self):
        reg = ProviderRegistry()
        meta1 = ProviderMetadata(name="test1", kind=AlgorithmKind.KEM, algorithm="TEST-KEM")
        meta2 = ProviderMetadata(name="test2", kind=AlgorithmKind.KEM, algorithm="TEST-KEM")
        reg.register("TEST-KEM", dummy_factory, meta1)
        reg.register("TEST-KEM", dummy_factory, meta2, allow_override=True)

        assert reg.get_metadata("TEST-KEM").name == "test2"

    def test_unregister(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST-KEM")
        reg.register("TEST-KEM", dummy_factory, meta)

        assert reg.unregister("TEST-KEM") is True
        assert not reg.is_registered("TEST-KEM")
        assert reg.get_factory("TEST-KEM") is None
        assert reg.get_metadata("TEST-KEM") is None

    def test_unregister_nonexistent_returns_false(self):
        reg = ProviderRegistry()
        assert reg.unregister("NONEXISTENT") is False

    def test_create_provider(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST-KEM")
        reg.register("TEST-KEM", dummy_factory, meta)

        provider = reg.create_provider("TEST-KEM")
        assert provider == "provider-for-TEST-KEM"

    def test_create_provider_unregistered_raises(self):
        reg = ProviderRegistry()
        with pytest.raises(KeyError, match="not registered"):
            reg.create_provider("UNKNOWN")

    def test_is_available(self):
        reg = ProviderRegistry()
        meta_avail = ProviderMetadata(
            name="test", kind=AlgorithmKind.KEM, algorithm="AVAIL-KEM",
            status=ProviderStatus.AVAILABLE
        )
        meta_unavail = ProviderMetadata(
            name="test", kind=AlgorithmKind.KEM, algorithm="UNAVAIL-KEM",
            status=ProviderStatus.UNAVAILABLE
        )
        reg.register("AVAIL-KEM", dummy_factory, meta_avail)
        reg.register("UNAVAIL-KEM", dummy_factory, meta_unavail)

        assert reg.is_available("AVAIL-KEM") is True
        assert reg.is_available("UNAVAIL-KEM") is False
        assert reg.is_available("UNKNOWN") is False

    def test_list_algorithms_all(self):
        reg = ProviderRegistry()
        for alg, kind in [("KEM1", AlgorithmKind.KEM), ("KEM2", AlgorithmKind.KEM),
                           ("SIG1", AlgorithmKind.SIGNATURE), ("HASH1", AlgorithmKind.HASH)]:
            meta = ProviderMetadata(name="test", kind=kind, algorithm=alg)
            reg.register(alg, dummy_factory, meta)

        all_algs = reg.list_algorithms()
        assert set(all_algs) == {"KEM1", "KEM2", "SIG1", "HASH1"}
        assert all_algs == sorted(all_algs)  # Should be sorted

    def test_list_algorithms_by_kind(self):
        reg = ProviderRegistry()
        for alg, kind in [("KEM1", AlgorithmKind.KEM), ("KEM2", AlgorithmKind.KEM),
                           ("SIG1", AlgorithmKind.SIGNATURE)]:
            meta = ProviderMetadata(name="test", kind=kind, algorithm=alg)
            reg.register(alg, dummy_factory, meta)

        kems = reg.list_algorithms(AlgorithmKind.KEM)
        assert set(kems) == {"KEM1", "KEM2"}

        sigs = reg.list_algorithms(AlgorithmKind.SIGNATURE)
        assert sigs == ["SIG1"]

        hashes = reg.list_algorithms(AlgorithmKind.HASH)
        assert hashes == []

    def test_list_metadata(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST-KEM", security_level=3)
        reg.register("TEST-KEM", dummy_factory, meta)

        metadatas = reg.list_metadata()
        assert len(metadatas) == 1
        assert metadatas[0].algorithm == "TEST-KEM"
        assert metadatas[0].security_level == 3

    def test_invalid_algorithm_name_raises(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST-KEM")

        with pytest.raises(ValueError, match="non-empty string"):
            reg.register("", dummy_factory, meta)

        with pytest.raises(ValueError, match="non-empty string"):
            reg.register(None, dummy_factory, meta)  # type: ignore

    def test_invalid_factory_raises(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST-KEM")

        with pytest.raises(ValueError, match="callable"):
            reg.register("TEST-KEM", "not-a-callable", meta)  # type: ignore

    def test_invalid_metadata_raises(self):
        reg = ProviderRegistry()
        with pytest.raises(ValueError, match="ProviderMetadata"):
            reg.register("TEST-KEM", dummy_factory, "not-metadata")  # type: ignore

    def test_metadata_algorithm_mismatch_raises(self):
        reg = ProviderRegistry()
        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="OTHER-KEM")

        with pytest.raises(ValueError, match="does not match"):
            reg.register("TEST-KEM", dummy_factory, meta)

    def test_by_kind_tracking(self):
        reg = ProviderRegistry()
        meta_kem = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="KEM1")
        meta_sig = ProviderMetadata(name="test", kind=AlgorithmKind.SIGNATURE, algorithm="SIG1")
        reg.register("KEM1", dummy_factory, meta_kem)
        reg.register("SIG1", dummy_factory, meta_sig)

        assert reg.get_algorithms_by_kind(AlgorithmKind.KEM) == ["KEM1"]
        assert reg.get_algorithms_by_kind(AlgorithmKind.SIGNATURE) == ["SIG1"]
        assert reg.get_algorithms_by_kind(AlgorithmKind.HASH) == []

        reg.unregister("KEM1")
        assert reg.get_algorithms_by_kind(AlgorithmKind.KEM) == []


class TestGlobalRegistry:
    """Tests for global registry functions."""

    def test_global_registry_functions(self):
        # Clear any existing state first
        reg = get_registry()
        for alg in list_registered_algorithms():
            unregister_provider(alg)

        meta = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="GLOBAL-KEM")
        register_provider("GLOBAL-KEM", dummy_factory, meta)

        assert get_provider_factory("GLOBAL-KEM") is not None
        assert get_provider_metadata("GLOBAL-KEM") == meta
        assert create_provider("GLOBAL-KEM") == "provider-for-GLOBAL-KEM"
        assert "GLOBAL-KEM" in list_registered_algorithms()

        unregister_provider("GLOBAL-KEM")
        assert "GLOBAL-KEM" not in list_registered_algorithms()


class TestAlgorithmKind:
    """Tests for AlgorithmKind enum."""

    def test_values(self):
        assert AlgorithmKind.KEM == "kem"
        assert AlgorithmKind.SIGNATURE == "sig"
        assert AlgorithmKind.HASH == "hash"
        assert AlgorithmKind.AEAD == "aead"


class TestProviderStatus:
    """Tests for ProviderStatus enum."""

    def test_values(self):
        assert ProviderStatus.AVAILABLE == "available"
        assert ProviderStatus.UNAVAILABLE == "unavailable"
        assert ProviderStatus.DEGRADED == "degraded"


class TestProviderMetadata:
    """Tests for ProviderMetadata."""

    def test_is_available(self):
        meta_avail = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST",
                                      status=ProviderStatus.AVAILABLE)
        meta_unavail = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST",
                                         status=ProviderStatus.UNAVAILABLE)
        meta_degraded = ProviderMetadata(name="test", kind=AlgorithmKind.KEM, algorithm="TEST",
                                          status=ProviderStatus.DEGRADED)

        assert meta_avail.is_available() is True
        assert meta_unavail.is_available() is False
        assert meta_degraded.is_available() is False  # DEGRADED is not AVAILABLE