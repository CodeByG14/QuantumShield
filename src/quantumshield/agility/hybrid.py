"""Illustrative hybrid secret combiner for crypto-agility.

This module provides an HKDF-based combiner for deriving a shared secret
from multiple input secrets (e.g., classical + PQC key exchanges).

IMPORTANT: This is an ILLUSTRATIVE combiner for demonstration and testing
purposes only. It does NOT implement a formally standardized hybrid
key-establishment protocol (such as RFC 8784 or IETF hybrid drafts).
It makes no claim of interoperability with other implementations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class HybridCombinerParams:
    """Parameters for the hybrid combiner."""
    hash_algorithm: str = "SHA-256"  # "SHA-256", "SHA-384", "SHA-512"
    output_length: int = 32  # bytes
    info: bytes = b"quantumshield-hybrid-v1"
    salt: Optional[bytes] = None


def _get_hash_algorithm(name: str) -> hashes.HashAlgorithm:
    """Convert string name to cryptography hash algorithm."""
    name = name.upper().replace("-", "")
    if name == "SHA256":
        return hashes.SHA256()
    elif name == "SHA384":
        return hashes.SHA384()
    elif name == "SHA512":
        return hashes.SHA512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {name}. Use SHA-256, SHA-384, or SHA-512.")


def combine_secrets(
    secrets: list[bytes],
    context: bytes,
    params: Optional[HybridCombinerParams] = None,
) -> bytes:
    """Combine multiple input secrets into a single output secret using HKDF.

    This is an ILLUSTRATIVE implementation for demonstration purposes.
    It does NOT implement a standardized hybrid key agreement protocol.

    Args:
        secrets: List of input secrets to combine. Each must be non-empty.
        context: Explicit context string for domain separation. Must be non-empty.
        params: Optional HybridCombinerParams for customization.

    Returns:
        Derived secret of length params.output_length.

    Raises:
        ValueError: If inputs are invalid (empty secrets, empty context, etc.).

    Example:
        >>> classical_secret = b"x25519-shared-secret"
        >>> pqc_secret = b"mlkem-shared-secret"
        >>> combined = combine_secrets([classical_secret, pqc_secret], b"tls-1.3-hybrid")
    """
    if params is None:
        params = HybridCombinerParams()

    # Validate inputs
    if not secrets:
        raise ValueError("At least one secret must be provided")
    for i, secret in enumerate(secrets):
        if not secret:
            raise ValueError(f"Secret at index {i} is empty")
        if not isinstance(secret, bytes):
            raise ValueError(f"Secret at index {i} must be bytes")

    if not context:
        raise ValueError("Context must be non-empty")
    if not isinstance(context, bytes):
        raise ValueError("Context must be bytes")

    if params.output_length <= 0:
        raise ValueError("Output length must be positive")
    if params.output_length > 1024:
        raise ValueError("Output length too large (max 1024 bytes)")

    # Concatenate all secrets with length prefixes for unambiguous encoding
    # This prevents ambiguity if secrets have variable lengths
    concatenated = b""
    for secret in secrets:
        # 4-byte big-endian length prefix
        concatenated += len(secret).to_bytes(4, "big") + secret

    # Use HKDF with the concatenated secrets as input keying material
    # The context is used as the 'info' parameter for domain separation
    hash_alg = _get_hash_algorithm(params.hash_algorithm)

    hkdf = HKDF(
        algorithm=hash_alg,
        length=params.output_length,
        salt=params.salt,
        info=params.info + context,
    )

    return hkdf.derive(concatenated)


def combine_two_secrets(
    secret1: bytes,
    secret2: bytes,
    context: bytes,
    params: Optional[HybridCombinerParams] = None,
) -> bytes:
    """Convenience function for combining exactly two secrets.

    Args:
        secret1: First input secret.
        secret2: Second input secret.
        context: Context for domain separation.
        params: Optional parameters.

    Returns:
        Derived secret.
    """
    return combine_secrets([secret1, secret2], context, params)


def demonstrate_context_separation() -> dict[str, bytes]:
    """Demonstrate that different contexts produce different outputs.

    Returns:
        Dictionary mapping context names to derived secrets.
    """
    secret1 = b"classical-shared-secret-32bytes!!"
    secret2 = b"pqc-shared-secret-32bytes-length"

    contexts = {
        "tls-1.3": b"tls-1.3-hybrid",
        "ssh-2.0": b"ssh-2.0-hybrid",
        "ike-v2": b"ike-v2-hybrid",
        "custom-app": b"my-application-v1",
    }

    results = {}
    for name, ctx in contexts.items():
        results[name] = combine_two_secrets(secret1, secret2, ctx)

    # Verify all outputs are different
    outputs = list(results.values())
    assert len(set(outputs)) == len(outputs), "Context separation failed: duplicate outputs"

    return results


def demonstrate_input_sensitivity() -> dict[str, bytes]:
    """Demonstrate that changing either input secret changes the output.

    Returns:
        Dictionary mapping scenario names to derived secrets.
    """
    base_secret1 = b"classical-shared-secret-32bytes!!"
    base_secret2 = b"pqc-shared-secret-32bytes-length"
    context = b"test-context"

    results = {
        "base": combine_two_secrets(base_secret1, base_secret2, context),
        "changed_secret1": combine_two_secrets(
            b"different-classical-secret-32bytes", base_secret2, context
        ),
        "changed_secret2": combine_two_secrets(
            base_secret1, b"different-pqc-secret-32bytes-length", context
        ),
        "swapped": combine_two_secrets(base_secret2, base_secret1, context),  # order matters
    }

    # Verify all outputs are different
    outputs = list(results.values())
    assert len(set(outputs)) == len(outputs), "Input sensitivity failed: duplicate outputs"

    return results


# --------------------------------------------------------------------------
# Self-test / Demo
# --------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Hybrid Combiner Demo ===\n")

    # Context separation
    print("1. Context Separation Test:")
    ctx_results = demonstrate_context_separation()
    for name, output in ctx_results.items():
        print(f"   {name}: {output.hex()[:32]}...")
    print("   ✓ All contexts produce distinct outputs\n")

    # Input sensitivity
    print("2. Input Sensitivity Test:")
    sens_results = demonstrate_input_sensitivity()
    for name, output in sens_results.items():
        print(f"   {name}: {output.hex()[:32]}...")
    print("   ✓ Changing any input changes the output\n")

    # Basic usage
    print("3. Basic Usage:")
    classical = b"x25519-shared-secret"
    pqc = b"mlkem768-shared-secret"
    combined = combine_two_secrets(classical, pqc, b"tls-1.3")
    print(f"   Classical: {classical.hex()}")
    print(f"   PQC:       {pqc.hex()}")
    print(f"   Combined:  {combined.hex()}")
    print()

    # With custom params
    print("4. Custom Parameters (SHA-384, 48-byte output):")
    custom_params = HybridCombinerParams(
        hash_algorithm="SHA-384",
        output_length=48,
        info=b"custom-app",
    )
    combined_custom = combine_two_secrets(classical, pqc, b"my-context", custom_params)
    print(f"   Output length: {len(combined_custom)} bytes")
    print(f"   Output: {combined_custom.hex()[:64]}...")
    print()

    print("=== Demo Complete ===")
    print("\nNote: This is an ILLUSTRATIVE combiner only.")
    print("It does NOT implement a standardized hybrid key agreement protocol.")