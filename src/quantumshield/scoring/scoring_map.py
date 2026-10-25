"""
QuantumShield Quantum Factor Lookup Table

Authoritative algorithm → quantum_factor → tier mapping.
Source: docs/quantum-factor-lookup-table.md
Date: 2026-09-27
"""

# Core quantum factor lookup table keyed by algorithm family name
QUANTUM_FACTOR_TABLE = {
    # Shor-vulnerable algorithms (factor 1.5) — public-key crypto broken completely
    "RSA": {"factor": 1.5, "tier": "shor-vulnerable"},
    "ECDSA": {"factor": 1.5, "tier": "shor-vulnerable"},
    "ECDH": {"factor": 1.5, "tier": "shor-vulnerable"},
    "DH": {"factor": 1.5, "tier": "shor-vulnerable"},
    "DSA": {"factor": 1.5, "tier": "shor-vulnerable"},
    
    # Named EC curves (all Shor-vulnerable)
    "P-256": {"factor": 1.5, "tier": "shor-vulnerable"},
    "P-384": {"factor": 1.5, "tier": "shor-vulnerable"},
    "secp256k1": {"factor": 1.5, "tier": "shor-vulnerable"},
    
    # Grover-affected algorithms (factor 1.2) — symmetric crypto weakened but not broken
    # Default AES to 128-bit assumption (conservative — over-flag until key-size detection added)
    "AES": {"factor": 1.2, "tier": "grover-affected"},
    "AES-128": {"factor": 1.2, "tier": "grover-affected"},
    "AES-192": {"factor": 1.2, "tier": "grover-affected"},
    "MD5": {"factor": 1.2, "tier": "grover-affected"},
    "SHA-1": {"factor": 1.2, "tier": "grover-affected"},
    "SHA1": {"factor": 1.2, "tier": "grover-affected"},
    "SHA-256": {"factor": 1.2, "tier": "grover-affected"},
    "SHA256": {"factor": 1.2, "tier": "grover-affected"},
    
    # Quantum-safe algorithms (factor 1.0)
    "AES-256": {"factor": 1.0, "tier": "quantum-safe"},
    "SHA-384": {"factor": 1.0, "tier": "quantum-safe"},
    "SHA384": {"factor": 1.0, "tier": "quantum-safe"},
    "SHA-512": {"factor": 1.0, "tier": "quantum-safe"},
    "SHA512": {"factor": 1.0, "tier": "quantum-safe"},
    "SHA-3": {"factor": 1.0, "tier": "quantum-safe"},
    "SHA3": {"factor": 1.0, "tier": "quantum-safe"},
    
    # NIST-standardized PQC algorithms (the target, not a risk)
    "ML-KEM": {"factor": 1.0, "tier": "quantum-safe"},
    "ML-DSA": {"factor": 1.0, "tier": "quantum-safe"},
    "SLH-DSA": {"factor": 1.0, "tier": "quantum-safe"},
}


def get_quantum_factor(algorithm_name):
    """
    Get quantum factor and tier for a given algorithm name.
    
    Args:
        algorithm_name: Algorithm family name (e.g., "RSA", "AES", "MD5")
    
    Returns:
        dict with "factor" and "tier" keys, or None if not found
    """
    return QUANTUM_FACTOR_TABLE.get(algorithm_name)


def get_algorithm_family(variant_name):
    """
    Extract algorithm family from variant name.
    
    Examples:
        "RSA-2048" -> "RSA"
        "AES-128-GCM" -> "AES-128"
        "ECDSA" -> "ECDSA"
        "MD5" -> "MD5"
    
    Args:
        variant_name: Full variant string from CBOM
    
    Returns:
        Algorithm family name for lookup
    """
    # Try exact match first
    if variant_name in QUANTUM_FACTOR_TABLE:
        return variant_name
    
    # Try splitting on hyphen and taking first part
    base = variant_name.split("-")[0]
    if base in QUANTUM_FACTOR_TABLE:
        return base
    
    # Try first two parts (for AES-256, AES-128, etc.)
    parts = variant_name.split("-")
    if len(parts) >= 2:
        two_part = f"{parts[0]}-{parts[1]}"
        if two_part in QUANTUM_FACTOR_TABLE:
            return two_part
    
    # Fallback to base
    return base
