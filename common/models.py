from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DetectionMethod(str, Enum):
    REGEX = "regex"
    MANIFEST = "manifest"
    FILE_EXTENSION = "file-extension"


class Tier(str, Enum):
    SHOR_VULNERABLE = "shor-vulnerable"
    GROVER_AFFECTED = "grover-affected"
    QUANTUM_SAFE = "quantum-safe"
    UNKNOWN = "unknown"


class CryptoFinding(BaseModel):
    """
    Canonical shape for every detected cryptographic asset, regardless of
    which detector (source regex, manifest parser, cert/key file scan)
    produced it. This is the contract that discovery writes into and
    everything downstream (CBOM writer, scoring, dashboard) reads from.
    """

    algorithm: str = Field(
        ..., description='e.g. "RSA", "AES", "unknown" for unparsed cert/key files'
    )
    variant: Optional[str] = Field(
        default=None,
        description='e.g. "RSA-2048" — may be unknown for manifest/cert hits',
    )
    purpose: Optional[str] = Field(
        default=None,
        description='e.g. "TLS", "signing", "encryption" — often unknown for regex hits',
    )
    file: str = Field(..., description="Path to the file this finding came from")
    line: Optional[int] = Field(
        default=None, description="Line number — absent for manifest/cert findings"
    )
    evidence: str = Field(
        ...,
        description="Matched text, library name, or filename that triggered detection",
    )
    detection_method: DetectionMethod
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str = Field(
        ..., description="Which scanner module produced this finding, e.g. 'scanner.py'"
    )

    class Config:
        use_enum_values = True
