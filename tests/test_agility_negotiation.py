import pytest
from quantumshield.agility.config import get_default_config, load_config_from_string
from quantumshield.agility.negotiation import NegotiationEngine, NoMutualAlgorithmError, PQCRequiredError
from quantumshield.agility.registry import ProviderRegistry, ProviderMetadata, AlgorithmKind, ProviderStatus


def registry_for(*algorithms):
    r = ProviderRegistry()
    for name, kind in algorithms:
        r.register(name, lambda _name: object(), ProviderMetadata(name="test", kind=kind, status=ProviderStatus.AVAILABLE, algorithm=name))
    return r


def test_selects_highest_priority_mutual_algorithm():
    cfg = get_default_config(); r = registry_for(("ML-KEM-768", AlgorithmKind.KEM), ("ML-KEM-512", AlgorithmKind.KEM))
    result = NegotiationEngine(cfg, r).negotiate("tls-kem", ["ML-KEM-768", "ML-KEM-512"], ["ML-KEM-512", "ML-KEM-768"])
    assert result.algorithm == "ML-KEM-768" and result.source == "mutual-preference"


def test_fallback_only_when_advertised_by_both_peers():
    cfg = get_default_config(); r = registry_for(("ML-KEM-512", AlgorithmKind.KEM))
    result = NegotiationEngine(cfg, r).negotiate("tls-kem", ["ML-KEM-512"], ["ML-KEM-512"])
    assert result.algorithm == "ML-KEM-512"
    assert result.source == "fallback"


def test_no_mutual_algorithm_raises():
    cfg = get_default_config(); r = registry_for(("X25519", AlgorithmKind.KEM))
    with pytest.raises(NoMutualAlgorithmError):
        NegotiationEngine(cfg, r).negotiate("tls-kem", ["X25519"], ["ML-KEM-512"])


def test_require_pqc_never_downgrades_to_classical():
    cfg = get_default_config(); r = registry_for(("X25519", AlgorithmKind.KEM))
    with pytest.raises(PQCRequiredError):
        NegotiationEngine(cfg, r).negotiate("tls-kem", ["X25519"], ["X25519"])


def test_unregistered_algorithm_is_not_assumed_available():
    cfg = get_default_config()
    with pytest.raises(NoMutualAlgorithmError):
        NegotiationEngine(cfg, ProviderRegistry()).negotiate("tls-kem", ["ML-KEM-768"], ["ML-KEM-768"])


def test_unknown_purpose_raises():
    with pytest.raises(Exception, match="Unknown purpose"):
        NegotiationEngine(get_default_config(), ProviderRegistry()).negotiate("missing", [], [])


def test_configured_fallback_order_is_used_when_only_fallbacks_are_mutual():
    cfg = get_default_config()
    r = registry_for(("ML-KEM-512", AlgorithmKind.KEM), ("X25519", AlgorithmKind.KEM))
    result = NegotiationEngine(cfg, r).negotiate("tls-kem", ["X25519", "ML-KEM-512"], ["ML-KEM-512", "X25519"])
    assert result.algorithm == "ML-KEM-512"
    assert result.source == "fallback"
