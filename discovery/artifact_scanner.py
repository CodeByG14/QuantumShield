"""
Artifact detector: password-protected key containers whose contents we cannot parse.

This is a classifier, not an analysis stage. The file is reported as a
low-confidence potential asset, and coverage records it as UNSUPPORTED because
its contents are never examined.
"""

from pathlib import PurePosixPath

from common.models import (
    Confidence,
    CryptoFinding,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)

ARTIFACT_SUFFIXES = {".p12": "PKCS#12", ".pfx": "PKCS#12", ".jks": "Java KeyStore"}


def detect_artifact(rel_path: str) -> list[CryptoFinding]:
    suffix = PurePosixPath(rel_path).suffix.lower()
    container = ARTIFACT_SUFFIXES.get(suffix)
    if container is None:
        return []
    return [
        CryptoFinding(
            algorithm="unknown",
            status=FindingStatus.POTENTIAL,
            evidence=[
                Evidence(
                    file_path=rel_path,
                    evidence_type=EvidenceType.FILE_EXTENSION,
                    detection_method=DetectionMethod.FILE_EXTENSION,
                    rule_id="ARTIFACT-001",
                    excerpt=f"{container} container ({suffix}); contents not parsed",
                    confidence=Confidence.LOW,
                    metadata={"container": container},
                )
            ],
        )
    ]
