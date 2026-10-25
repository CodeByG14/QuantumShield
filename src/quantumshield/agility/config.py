"""Crypto-agility configuration loader and validator.

Supports per-purpose algorithm selection, allowed lists, ordered fallbacks,
deprecation dates, and canonical algorithm names.
"""

from __future__ import annotations

import datetime
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class AgilityConfigError(ValueError):
    """Raised when configuration is invalid."""
    pass


@dataclass(frozen=True)
class AlgorithmSpec:
    """Specification for a single algorithm in configuration."""
    name: str
    kind: str  # "kem", "sig", "hash", "aead"
    security_level: int | None = None
    status: str = "active"  # "active", "deprecated", "legacy"
    deprecation_date: str | None = None  # ISO format YYYY-MM-DD
    provider: str | None = None  # "openssl", "oqs", "cryptography"


@dataclass(frozen=True)
class PurposeConfig:
    """Configuration for a cryptographic purpose."""
    purpose: str
    algorithm: str  # Primary algorithm (canonical name)
    allowed: list[str] = field(default_factory=list)  # Allowed algorithms for this purpose
    fallback: list[str] = field(default_factory=list)  # Ordered fallback preferences
    require_pqc: bool = False  # If True, never silently downgrade to classical


@dataclass(frozen=True)
class AgilityConfig:
    """Complete crypto-agility configuration."""
    version: str
    algorithms: dict[str, AlgorithmSpec] = field(default_factory=dict)
    purposes: dict[str, PurposeConfig] = field(default_factory=dict)
    defaults: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_algorithm(self, name: str) -> AlgorithmSpec | None:
        """Get algorithm spec by canonical name."""
        return self.algorithms.get(name)

    def get_purpose(self, purpose: str) -> PurposeConfig | None:
        """Get purpose configuration."""
        return self.purposes.get(purpose)

    def list_algorithms(self, kind: str | None = None, status: str | None = None) -> list[AlgorithmSpec]:
        """List algorithms, optionally filtered by kind and/or status."""
        result = []
        for alg in self.algorithms.values():
            if kind and alg.kind != kind:
                continue
            if status and alg.status != status:
                continue
            result.append(alg)
        return result

    def list_purposes(self) -> list[str]:
        """List all configured purposes."""
        return list(self.purposes.keys())


def _parse_date(date_str: str | None) -> datetime.date | None:
    """Parse ISO date string, return None if empty or None."""
    if not date_str:
        return None
    try:
        return datetime.date.fromisoformat(date_str)
    except ValueError as e:
        raise AgilityConfigError(f"Invalid date format '{date_str}': must be YYYY-MM-DD") from e


def _validate_algorithm_spec(name: str, spec: dict[str, Any]) -> AlgorithmSpec:
    """Validate and convert raw algorithm spec."""
    required_fields = ["kind"]
    for field_name in required_fields:
        if field_name not in spec:
            raise AgilityConfigError(f"Algorithm '{name}': missing required field '{field_name}'")

    kind = spec["kind"]
    if kind not in {"kem", "sig", "hash", "aead"}:
        raise AgilityConfigError(f"Algorithm '{name}': invalid kind '{kind}' (must be kem, sig, hash, or aead)")

    security_level = spec.get("security_level")
    if security_level is not None:
        if not isinstance(security_level, int) or security_level < 0:
            raise AgilityConfigError(f"Algorithm '{name}': security_level must be a non-negative integer")

    status = spec.get("status", "active")
    if status not in {"active", "deprecated", "legacy"}:
        raise AgilityConfigError(f"Algorithm '{name}': invalid status '{status}'")

    deprecation_date = _parse_date(spec.get("deprecation_date"))

    provider = spec.get("provider")
    if provider is not None and provider not in {"openssl", "oqs", "cryptography"}:
        warnings.warn(
            f"Algorithm '{name}': unknown provider '{provider}'",
            UserWarning,
            stacklevel=2,
        )

    return AlgorithmSpec(
        name=name,
        kind=kind,
        security_level=security_level,
        status=status,
        deprecation_date=spec.get("deprecation_date"),
        provider=provider,
    )


def _validate_purpose_config(name: str, spec: dict[str, Any], known_algorithms: set[str]) -> PurposeConfig:
    """Validate and convert raw purpose config."""
    if "algorithm" not in spec:
        raise AgilityConfigError(f"Purpose '{name}': missing required field 'algorithm'")

    primary = spec["algorithm"]
    if primary not in known_algorithms:
        raise AgilityConfigError(f"Purpose '{name}': primary algorithm '{primary}' not defined in algorithms")

    allowed = spec.get("allowed", [])
    for alg in allowed:
        if alg not in known_algorithms:
            raise AgilityConfigError(f"Purpose '{name}': allowed algorithm '{alg}' not defined in algorithms")

    fallback = spec.get("fallback", [])
    for alg in fallback:
        if alg not in known_algorithms:
            raise AgilityConfigError(f"Purpose '{name}': fallback algorithm '{alg}' not defined in algorithms")

    # Check for duplicates between algorithm, allowed, and fallback
    all_algs = {primary} | set(allowed) | set(fallback)
    if len(all_algs) != 1 + len(allowed) + len(fallback):
        # This is okay - duplicates are allowed but we warn
        pass

    require_pqc = spec.get("require_pqc", False)

    return PurposeConfig(
        purpose=name,
        algorithm=primary,
        allowed=allowed,
        fallback=fallback,
        require_pqc=require_pqc,
    )


def load_config(path: str | Path) -> AgilityConfig:
    """Load and validate agility configuration from YAML file.

    Args:
        path: Path to YAML configuration file.

    Returns:
        Validated AgilityConfig instance.

    Raises:
        AgilityConfigError: If configuration is invalid.
        FileNotFoundError: If file does not exist.
        yaml.YAMLError: If YAML is malformed.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raise AgilityConfigError("Configuration file is empty")

    if not isinstance(raw, dict):
        raise AgilityConfigError("Configuration root must be a mapping")

    # Validate version
    version = raw.get("version")
    if not version:
        raise AgilityConfigError("Missing required field 'version'")
    if not isinstance(version, str):
        raise AgilityConfigError("Field 'version' must be a string")

    # Validate algorithms
    raw_algorithms = raw.get("algorithms", {})
    if not isinstance(raw_algorithms, dict):
        raise AgilityConfigError("Field 'algorithms' must be a mapping")

    algorithms = {}
    seen_names = set()
    for name, spec in raw_algorithms.items():
        if not isinstance(name, str):
            raise AgilityConfigError("Algorithm names must be strings")
        if name in seen_names:
            raise AgilityConfigError(f"Duplicate algorithm name: '{name}'")
        seen_names.add(name)

        if not isinstance(spec, dict):
            raise AgilityConfigError(f"Algorithm '{name}': spec must be a mapping")

        algorithms[name] = _validate_algorithm_spec(name, spec)

    known_algorithms = set(algorithms.keys())

    # Validate purposes
    raw_purposes = raw.get("purposes", {})
    if not isinstance(raw_purposes, dict):
        raise AgilityConfigError("Field 'purposes' must be a mapping")

    purposes = {}
    for name, spec in raw_purposes.items():
        if not isinstance(name, str):
            raise AgilityConfigError("Purpose names must be strings")
        if name in purposes:
            raise AgilityConfigError(f"Duplicate purpose name: '{name}'")

        if not isinstance(spec, dict):
            raise AgilityConfigError(f"Purpose '{name}': spec must be a mapping")

        purposes[name] = _validate_purpose_config(name, spec, known_algorithms)

    # Validate defaults (optional)
    defaults = raw.get("defaults", {})
    if not isinstance(defaults, dict):
        raise AgilityConfigError("Field 'defaults' must be a mapping")

    # Metadata (optional)
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise AgilityConfigError("Field 'metadata' must be a mapping")

    # Check for contradictory deprecation dates
    today = datetime.date.today()
    for alg in algorithms.values():
        if alg.deprecation_date:
            dep_date = _parse_date(alg.deprecation_date)
            if dep_date and dep_date < today and alg.status == "active":
                warnings.warn(
                    f"Algorithm '{alg.name}': deprecation date {alg.deprecation_date} is in the past but status is 'active'",
                    UserWarning,
                    stacklevel=2,
                )

    return AgilityConfig(
        version=version,
        algorithms=algorithms,
        purposes=purposes,
        defaults=defaults,
        metadata=metadata,
    )


def load_config_from_string(yaml_str: str) -> AgilityConfig:
    """Load and validate agility configuration from YAML string.

    Args:
        yaml_str: YAML configuration as string.

    Returns:
        Validated AgilityConfig instance.

    Raises:
        AgilityConfigError: If configuration is invalid.
        yaml.YAMLError: If YAML is malformed.
    """
    raw = yaml.safe_load(yaml_str)
    if raw is None:
        raise AgilityConfigError("Configuration is empty")

    # Reuse the same validation logic by writing to a temp approach
    # but easier: just validate the parsed dict directly
    # We'll extract the validation into a helper
    return _validate_raw_config(raw)


def _validate_raw_config(raw: dict[str, Any]) -> AgilityConfig:
    """Validate already-parsed config dict."""
    if not isinstance(raw, dict):
        raise AgilityConfigError("Configuration root must be a mapping")

    version = raw.get("version")
    if not version:
        raise AgilityConfigError("Missing required field 'version'")
    if not isinstance(version, str):
        raise AgilityConfigError("Field 'version' must be a string")

    raw_algorithms = raw.get("algorithms", {})
    if not isinstance(raw_algorithms, dict):
        raise AgilityConfigError("Field 'algorithms' must be a mapping")

    algorithms = {}
    for name, spec in raw_algorithms.items():
        if not isinstance(name, str):
            raise AgilityConfigError("Algorithm names must be strings")
        if name in algorithms:
            raise AgilityConfigError(f"Duplicate algorithm name: '{name}'")
        if not isinstance(spec, dict):
            raise AgilityConfigError(f"Algorithm '{name}': spec must be a mapping")
        algorithms[name] = _validate_algorithm_spec(name, spec)

    known_algorithms = set(algorithms.keys())

    raw_purposes = raw.get("purposes", {})
    if not isinstance(raw_purposes, dict):
        raise AgilityConfigError("Field 'purposes' must be a mapping")

    purposes = {}
    for name, spec in raw_purposes.items():
        if not isinstance(name, str):
            raise AgilityConfigError("Purpose names must be strings")
        if name in purposes:
            raise AgilityConfigError(f"Duplicate purpose name: '{name}'")
        if not isinstance(spec, dict):
            raise AgilityConfigError(f"Purpose '{name}': spec must be a mapping")
        purposes[name] = _validate_purpose_config(name, spec, known_algorithms)

    defaults = raw.get("defaults", {})
    if not isinstance(defaults, dict):
        raise AgilityConfigError("Field 'defaults' must be a mapping")

    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise AgilityConfigError("Field 'metadata' must be a mapping")

    today = datetime.date.today()
    for alg in algorithms.values():
        if alg.deprecation_date:
            dep_date = _parse_date(alg.deprecation_date)
            if dep_date and dep_date < today and alg.status == "active":
                warnings.warn(
                    f"Algorithm '{alg.name}': deprecation date {alg.deprecation_date} is in the past but status is 'active'",
                    UserWarning,
                    stacklevel=2,
                )

    return AgilityConfig(
        version=version,
        algorithms=algorithms,
        purposes=purposes,
        defaults=defaults,
        metadata=metadata,
    )


# Default configuration as a string for embedding
DEFAULT_CONFIG_YAML = """
version: "1.0"
metadata:
  description: "QuantumShield default crypto-agility configuration"
  created: "2026-10-25"

algorithms:
  # PQC KEMs
  ML-KEM-512:
    kind: kem
    security_level: 1
    status: active
    provider: openssl
  ML-KEM-768:
    kind: kem
    security_level: 3
    status: active
    provider: openssl
  ML-KEM-1024:
    kind: kem
    security_level: 5
    status: active
    provider: openssl

  # PQC Signatures
  ML-DSA-44:
    kind: sig
    security_level: 2
    status: active
    provider: openssl
  ML-DSA-65:
    kind: sig
    security_level: 3
    status: active
    provider: openssl
  ML-DSA-87:
    kind: sig
    security_level: 5
    status: active
    provider: openssl
  SLH-DSA-SHA2-128s:
    kind: sig
    security_level: 1
    status: active
    provider: openssl
  SLH-DSA-SHA2-128f:
    kind: sig
    security_level: 1
    status: active
    provider: openssl
  SLH-DSA-SHA2-192s:
    kind: sig
    security_level: 3
    status: active
    provider: openssl
  SLH-DSA-SHA2-192f:
    kind: sig
    security_level: 3
    status: active
    provider: openssl
  SLH-DSA-SHA2-256s:
    kind: sig
    security_level: 5
    status: active
    provider: openssl
  SLH-DSA-SHA2-256f:
    kind: sig
    security_level: 5
    status: active
    provider: openssl

  # Classical KEMs
  X25519:
    kind: kem
    security_level: 1
    status: deprecated
    deprecation_date: "2030-01-01"
    provider: cryptography
  P-256:
    kind: kem
    security_level: 1
    status: deprecated
    deprecation_date: "2030-01-01"
    provider: cryptography

  # Classical Signatures
  RSA-2048:
    kind: sig
    security_level: 1
    status: legacy
    deprecation_date: "2025-01-01"
    provider: cryptography
  P-256:
    kind: sig
    security_level: 1
    status: deprecated
    deprecation_date: "2030-01-01"
    provider: cryptography
  Ed25519:
    kind: sig
    security_level: 1
    status: deprecated
    deprecation_date: "2030-01-01"
    provider: cryptography

  # Hashes
  SHA-256:
    kind: hash
    security_level: 1
    status: active
    provider: cryptography
  SHA-384:
    kind: hash
    security_level: 2
    status: active
    provider: cryptography
  SHA-512:
    kind: hash
    security_level: 3
    status: active
    provider: cryptography

purposes:
  tls-kem:
    algorithm: ML-KEM-768
    allowed:
      - ML-KEM-512
      - ML-KEM-768
      - ML-KEM-1024
      - X25519
    fallback:
      - ML-KEM-512
      - X25519
    require_pqc: true

  tls-signature:
    algorithm: ML-DSA-65
    allowed:
      - ML-DSA-44
      - ML-DSA-65
      - ML-DSA-87
      - Ed25519
    fallback:
      - ML-DSA-44
      - Ed25519
    require_pqc: true

  signing:
    algorithm: ML-DSA-65
    allowed:
      - ML-DSA-44
      - ML-DSA-65
      - ML-DSA-87
      - SLH-DSA-SHA2-128s
      - SLH-DSA-SHA2-128f
      - Ed25519
    fallback:
      - ML-DSA-44
      - Ed25519
    require_pqc: true

  hashing:
    algorithm: SHA-256
    allowed:
      - SHA-256
      - SHA-384
      - SHA-512
    fallback: []

defaults:
  default_kem: ML-KEM-768
  default_signature: ML-DSA-65
  default_hash: SHA-256
  agility_scoring:
    configurable_weight: 1.0
    static_weight: 1.0
"""


def get_default_config() -> AgilityConfig:
    """Get the built-in default configuration."""
    return _validate_raw_config(yaml.safe_load(DEFAULT_CONFIG_YAML))