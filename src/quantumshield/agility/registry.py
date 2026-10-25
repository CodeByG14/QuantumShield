"""Provider registry for crypto-agility.

Maps canonical algorithm names to provider factories and metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class AlgorithmKind(str, Enum):
    """Type of cryptographic algorithm."""
    KEM = "kem"
    SIGNATURE = "sig"
    HASH = "hash"
    AEAD = "aead"


class ProviderStatus(str, Enum):
    """Provider availability status."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"  # Available but with limitations


@dataclass(frozen=True)
class ProviderMetadata:
    """Metadata for a registered provider."""
    name: str  # Provider identifier: "openssl", "oqs", "cryptography", "fake"
    kind: AlgorithmKind
    security_level: int | None = None
    status: ProviderStatus = ProviderStatus.UNAVAILABLE
    version: str | None = None
    limitations: list[str] = field(default_factory=list)
    # Canonical algorithm name this provider implements
    algorithm: str = ""

    def is_available(self) -> bool:
        """Check if provider is available for use."""
        return self.status == ProviderStatus.AVAILABLE


# Type alias for provider factory functions
# Factory takes algorithm name and returns a provider instance
ProviderFactory = Callable[[str], Any]


class ProviderRegistry:
    """Registry mapping canonical algorithm names to provider factories and metadata."""

    def __init__(self):
        self._factories: dict[str, ProviderFactory] = {}
        self._metadata: dict[str, ProviderMetadata] = {}
        self._by_kind: dict[AlgorithmKind, set[str]] = {
            AlgorithmKind.KEM: set(),
            AlgorithmKind.SIGNATURE: set(),
            AlgorithmKind.HASH: set(),
            AlgorithmKind.AEAD: set(),
        }

    def register(
        self,
        algorithm: str,
        factory: ProviderFactory,
        metadata: ProviderMetadata,
        *,
        allow_override: bool = False,
    ) -> None:
        """Register a provider for an algorithm.

        Args:
            algorithm: Canonical algorithm name (e.g., "ML-KEM-768")
            factory: Callable that creates a provider instance for the algorithm
            metadata: ProviderMetadata describing the provider
            allow_override: If True, replace existing registration. If False (default),
                           raise an error on duplicate algorithm.

        Raises:
            ValueError: If algorithm is already registered and allow_override is False,
                       or if metadata is invalid.
        """
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError("Algorithm name must be a non-empty string")

        if not callable(factory):
            raise ValueError("Factory must be callable")

        if not isinstance(metadata, ProviderMetadata):
            raise ValueError("Metadata must be a ProviderMetadata instance")

        if metadata.algorithm != algorithm:
            raise ValueError(f"Metadata algorithm '{metadata.algorithm}' does not match registration '{algorithm}'")

        if algorithm in self._factories and not allow_override:
            raise ValueError(
                f"Algorithm '{algorithm}' already registered. "
                f"Use allow_override=True to replace."
            )

        self._factories[algorithm] = factory
        self._metadata[algorithm] = metadata
        self._by_kind[metadata.kind].add(algorithm)

    def unregister(self, algorithm: str) -> bool:
        """Unregister a provider.

        Args:
            algorithm: Canonical algorithm name to remove.

        Returns:
            True if the algorithm was registered and removed, False if not found.
        """
        if algorithm not in self._factories:
            return False

        metadata = self._metadata[algorithm]
        self._factories.pop(algorithm)
        self._metadata.pop(algorithm)
        self._by_kind[metadata.kind].discard(algorithm)
        return True

    def get_factory(self, algorithm: str) -> ProviderFactory | None:
        """Get the factory for an algorithm.

        Args:
            algorithm: Canonical algorithm name.

        Returns:
            Factory callable if registered, None otherwise.
        """
        return self._factories.get(algorithm)

    def get_metadata(self, algorithm: str) -> ProviderMetadata | None:
        """Get metadata for an algorithm.

        Args:
            algorithm: Canonical algorithm name.

        Returns:
            ProviderMetadata if registered, None otherwise.
        """
        return self._metadata.get(algorithm)

    def create_provider(self, algorithm: str) -> Any:
        """Create a provider instance for the algorithm.

        Args:
            algorithm: Canonical algorithm name.

        Returns:
            Provider instance from the factory.

        Raises:
            KeyError: If algorithm is not registered.
            Exception: Any exception from the factory.
        """
        factory = self._factories.get(algorithm)
        if factory is None:
            raise KeyError(f"Algorithm '{algorithm}' not registered")
        return factory(algorithm)

    def is_registered(self, algorithm: str) -> bool:
        """Check if an algorithm is registered."""
        return algorithm in self._factories

    def is_available(self, algorithm: str) -> bool:
        """Check if an algorithm is registered AND its provider is available.

        Note: This checks the metadata status, which may be a cached/stale value.
        For runtime capability detection, use the provider's own availability check.
        """
        metadata = self._metadata.get(algorithm)
        if metadata is None:
            return False
        return metadata.is_available()

    def list_algorithms(self, kind: AlgorithmKind | None = None) -> list[str]:
        """List registered algorithms, optionally filtered by kind.

        Args:
            kind: Filter by AlgorithmKind, or None for all.

        Returns:
            Sorted list of canonical algorithm names.
        """
        if kind is None:
            return sorted(self._factories.keys())
        return sorted(self._by_kind.get(kind, set()))

    def list_metadata(self, kind: AlgorithmKind | None = None) -> list[ProviderMetadata]:
        """List metadata for registered algorithms.

        Args:
            kind: Filter by AlgorithmKind, or None for all.

        Returns:
            List of ProviderMetadata, sorted by algorithm name.
        """
        algos = self.list_algorithms(kind)
        return [self._metadata[alg] for alg in algos]

    def get_algorithms_by_kind(self, kind: AlgorithmKind) -> list[str]:
        """Get algorithms of a specific kind (alias for list_algorithms with kind)."""
        return self.list_algorithms(kind)


# Global registry instance
_global_registry = ProviderRegistry()


def get_registry() -> ProviderRegistry:
    """Get the global provider registry."""
    return _global_registry


def register_provider(
    algorithm: str,
    factory: ProviderFactory,
    metadata: ProviderMetadata,
    *,
    allow_override: bool = False,
) -> None:
    """Register a provider in the global registry."""
    _global_registry.register(algorithm, factory, metadata, allow_override=allow_override)


def unregister_provider(algorithm: str) -> bool:
    """Unregister a provider from the global registry."""
    return _global_registry.unregister(algorithm)


def get_provider_factory(algorithm: str) -> ProviderFactory | None:
    """Get factory from global registry."""
    return _global_registry.get_factory(algorithm)


def get_provider_metadata(algorithm: str) -> ProviderMetadata | None:
    """Get metadata from global registry."""
    return _global_registry.get_metadata(algorithm)


def create_provider(algorithm: str) -> Any:
    """Create provider from global registry."""
    return _global_registry.create_provider(algorithm)


def list_registered_algorithms(kind: AlgorithmKind | None = None) -> list[str]:
    """List algorithms in global registry."""
    return _global_registry.list_algorithms(kind)


def list_provider_metadata(kind: AlgorithmKind | None = None) -> list[ProviderMetadata]:
    """List metadata from global registry."""
    return _global_registry.list_metadata(kind)