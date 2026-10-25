"""QuantumShield Crypto-Agility Framework.

Provides configuration-driven algorithm selection, provider abstraction,
hybrid key combining, and cryptographic agility primitives.
"""

from quantumshield.agility.config import (
    AgilityConfig,
    AlgorithmSpec,
    PurposeConfig,
    AgilityConfigError,
    load_config,
    load_config_from_string,
    get_default_config,
    DEFAULT_CONFIG_YAML,
)
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
from quantumshield.agility.providers import (
    KEMProvider,
    SignatureProvider,
    HashProvider,
    AEADProvider,
    ClassicalAEADProvider,
    ClassicalKEMProvider,
    ClassicalSignatureProvider,
    ClassicalHashProvider,
    PQCKEMProvider,
    PQCSignatureProvider,
    ProviderError,
    AlgorithmNotSupportedError,
    ProviderUnavailableError,
    create_kem_provider,
    create_signature_provider,
    create_hash_provider,
    create_aead_provider,
    list_supported_aead_algorithms,
    list_supported_kem_algorithms,
    list_supported_signature_algorithms,
    list_supported_hash_algorithms,
    check_algorithm_availability,
    register_all_providers,
)
from quantumshield.agility.negotiation import (
    NegotiationEngine, NegotiationResult, NegotiationError,
    NoMutualAlgorithmError, PQCRequiredError, is_pqc_algorithm,
)
from quantumshield.agility.rollback import RollbackManager, RollbackError, ConfigVersion, AuditEvent
from quantumshield.agility.keystore import FileKeystore, KeyRecord, KeystoreError, KeyNotFoundError
from quantumshield.agility.scoring import score_agility
from quantumshield.agility.hybrid import (
    HybridCombinerParams,
    combine_secrets,
    combine_two_secrets,
    demonstrate_context_separation,
    demonstrate_input_sensitivity,
)

__all__ = [
    # Config
    "AgilityConfig",
    "AlgorithmSpec",
    "PurposeConfig",
    "AgilityConfigError",
    "load_config",
    "load_config_from_string",
    "get_default_config",
    "DEFAULT_CONFIG_YAML",
    # Registry
    "ProviderRegistry",
    "ProviderMetadata",
    "AlgorithmKind",
    "ProviderStatus",
    "get_registry",
    "register_provider",
    "unregister_provider",
    "get_provider_factory",
    "get_provider_metadata",
    "create_provider",
    "list_registered_algorithms",
    "list_provider_metadata",
    # Providers
    "KEMProvider",
    "SignatureProvider",
    "HashProvider",
    "AEADProvider",
    "ClassicalAEADProvider",
    "ClassicalKEMProvider",
    "ClassicalSignatureProvider",
    "ClassicalHashProvider",
    "PQCKEMProvider",
    "PQCSignatureProvider",
    "ProviderError",
    "AlgorithmNotSupportedError",
    "ProviderUnavailableError",
    "create_kem_provider",
    "create_signature_provider",
    "create_hash_provider",
    "create_aead_provider",
    "list_supported_aead_algorithms",
    "list_supported_kem_algorithms",
    "list_supported_signature_algorithms",
    "list_supported_hash_algorithms",
    "check_algorithm_availability",
    "register_all_providers",
    # Negotiation, rollback, keystore, scoring
    "NegotiationEngine", "NegotiationResult", "NegotiationError",
    "NoMutualAlgorithmError", "PQCRequiredError", "is_pqc_algorithm",
    "RollbackManager", "RollbackError", "ConfigVersion", "AuditEvent",
    "FileKeystore", "KeyRecord", "KeystoreError", "KeyNotFoundError",
    "score_agility",
    # Hybrid
    "HybridCombinerParams",
    "combine_secrets",
    "combine_two_secrets",
    "demonstrate_context_separation",
    "demonstrate_input_sensitivity",
]

__version__ = "0.1.0"