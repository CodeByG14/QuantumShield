"""Elliptic-curve name normalisation shared by the source and X.509 stages."""

_ALIASES = {
    "secp256r1": "P-256",
    "prime256v1": "P-256",
    "p-256": "P-256",
    "nist256p": "P-256",
    "secp384r1": "P-384",
    "p-384": "P-384",
    "nist384p": "P-384",
    "secp521r1": "P-521",
    "p-521": "P-521",
    "nist521p": "P-521",
    "secp256k1": "secp256k1",
}


def normalize_curve(raw: str) -> str:
    """Map the many spellings of a curve to one canonical name (unknown names pass through)."""
    cleaned = raw.strip()
    return _ALIASES.get(cleaned.lower(), cleaned)
