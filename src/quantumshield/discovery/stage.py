"""Result type returned by every analysis stage."""

from dataclasses import dataclass, field

from quantumshield.common.models import CryptoFinding


@dataclass
class StageOutput:
    findings: list[CryptoFinding] = field(default_factory=list)
    ok: bool = True  # False => the stage could not fully examine the file
    reason: str | None = None  # why, when ok is False
