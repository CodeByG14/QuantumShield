"""Deterministic, policy-enforcing algorithm negotiation."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable

from quantumshield.agility.config import AgilityConfig, PurposeConfig
from quantumshield.agility.registry import ProviderRegistry, get_registry


class NegotiationError(RuntimeError):
    """No policy-compliant algorithm could be negotiated."""

class NoMutualAlgorithmError(NegotiationError):
    """Peer preference lists have no mutually supported algorithm."""

class PQCRequiredError(NegotiationError):
    """Policy requires post-quantum cryptography but none can be selected."""

@dataclass(frozen=True)
class NegotiationResult:
    purpose: str
    algorithm: str
    source: str
    is_pqc: bool

# Conservative allow-list: names are canonical algorithm identifiers used by Phase 3.
_PQC_PREFIXES = ("ML-KEM", "ML-DSA", "SLH-DSA", "ML-KEM-", "ML-DSA-")

def is_pqc_algorithm(name: str, config: AgilityConfig | None = None) -> bool:
    spec = config.get_algorithm(name) if config else None
    if spec is not None and spec.provider in {"openssl", "oqs"} and name.startswith(_PQC_PREFIXES):
        return True
    return name.startswith(_PQC_PREFIXES)

class NegotiationEngine:
    """Select the highest-priority mutual algorithm without policy downgrades.

    `client_preferences` order is used as the primary preference order. A configured
    fallback is considered only if it is explicitly advertised by both peers.
    Registered algorithms must have an available provider; an unknown/unregistered
    algorithm is not assumed to be operational.
    """
    def __init__(self, config: AgilityConfig, registry: ProviderRegistry | None = None):
        self.config = config
        self.registry = registry or get_registry()

    def negotiate(self, purpose: str, client_preferences: Iterable[str], server_preferences: Iterable[str]) -> NegotiationResult:
        policy = self.config.get_purpose(purpose)
        if policy is None:
            raise NegotiationError(f"Unknown purpose: {purpose}")
        client = list(dict.fromkeys(client_preferences))
        server = set(server_preferences)
        allowed = set(policy.allowed) if policy.allowed else set(self.config.algorithms)
        advertised = [a for a in client if a in server and a in allowed]
        mutual = [a for a in advertised if self._operational(a)]
        if not mutual:
            raise NoMutualAlgorithmError(f"No mutual available algorithm for purpose '{purpose}'")
        if policy.require_pqc:
            mutual = [a for a in mutual if is_pqc_algorithm(a, self.config)]
            if not mutual:
                raise PQCRequiredError(f"Purpose '{purpose}' requires PQC; no mutually supported, available PQC algorithm")
        fallback_order = list(policy.fallback)
        primary_mutual = [a for a in mutual if a not in fallback_order]
        if primary_mutual:
            return NegotiationResult(purpose, primary_mutual[0], "mutual-preference", is_pqc_algorithm(primary_mutual[0], self.config))
        # If all mutual candidates are configured fallbacks, honour the explicit fallback order.
        for candidate in fallback_order:
            if candidate in mutual:
                return NegotiationResult(purpose, candidate, "fallback", is_pqc_algorithm(candidate, self.config))
        if policy.require_pqc:
            raise PQCRequiredError(f"Purpose '{purpose}' requires PQC; no compliant fallback")
        raise NoMutualAlgorithmError(f"No mutual available algorithm for purpose '{purpose}'")

    def _operational(self, algorithm: str) -> bool:
        # Explicitly configured algorithms can be used without registry initialization only
        # when the config says nothing about provider availability? Require registry for safe selection.
        if not self.registry.is_registered(algorithm):
            return False
        return self.registry.is_available(algorithm)
