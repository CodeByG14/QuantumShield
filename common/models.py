"""
QuantumShield shared data models (Week 5 schema).

Single contract between discovery, coverage, assessment and reporting.
Nothing here scans files or computes risk -- it only defines shapes and the
integrity rules those shapes must obey, so that invalid states (a CONFIRMED
finding with no strong evidence, a FAILED file counted as analyzed) cannot be
constructed at all.

Serialise with ``model.model_dump(mode="json")`` so enums become strings.
"""

from collections import Counter
from datetime import datetime
from enum import Enum
from typing import Literal
from pathlib import PurePosixPath
import fnmatch
import warnings

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

EXCERPT_MAX_CHARS = 200

COVERAGE_METRIC_NOTE = (
    "File coverage = files analyzed / files discovered. It measures how much of "
    "the project the scanner processed, not how complete cryptographic discovery is."
)


class _Strict(BaseModel):
    """Base for all models: unknown fields are errors, so typos fail loudly."""

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------


class DetectionMethod(str, Enum):
    REGEX = "regex"
    MANIFEST = "manifest"
    FILE_EXTENSION = "file-extension"
    X509 = "x509"


class EvidenceType(str, Enum):
    API_CALL = "api-call"
    KEYWORD = "keyword"
    CURVE_PARAMETER = "curve-parameter"
    COMMENT_MENTION = "comment-mention"
    DEPENDENCY = "dependency"
    CERTIFICATE = "certificate"
    KEY_FILE = "key-file"
    FILE_EXTENSION = "file-extension"


class Confidence(str, Enum):
    """How strong the evidence is. Independent of risk."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


_CONFIDENCE_RANK = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


def confidence_rank(c: Confidence) -> int:
    return _CONFIDENCE_RANK[c]


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"  # specific, non-comment, high-confidence evidence
    POTENTIAL = "potential"  # plausible, actual cryptographic use not established
    UNABLE_TO_ANALYZE = "unable-to-analyze"  # material found but could not be examined


class CryptoRole(str, Enum):
    KEY_ESTABLISHMENT = "key-establishment"
    SIGNATURE = "signature"
    SYMMETRIC_ENCRYPTION = "symmetric-encryption"
    HASH = "hash"
    MAC = "mac"
    UNDETERMINED = "undetermined"


class Tier(str, Enum):
    """Week 3 quantum-vulnerability tiers (kept; feeds the vulnerability factor)."""

    SHOR_VULNERABLE = "shor-vulnerable"
    GROVER_AFFECTED = "grover-affected"
    QUANTUM_SAFE = "quantum-safe"
    UNKNOWN = "unknown"


class FileOutcome(str, Enum):
    ANALYZED = "analyzed"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"


class StageStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"


class RiskLevel(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    VERY_HIGH = "very-high"
    CRITICAL = "critical"


class RiskKind(str, Enum):
    HNDL_CONFIDENTIALITY = "hndl-confidentiality"  # harvest-now-decrypt-later applies
    SIGNATURE_TRANSITION = "signature-transition"  # quantum-vulnerable signature: migration priority, not HNDL
    CLASSICAL_WEAKNESS = "classical-weakness"  # classical cryptographic weakness independent of quantum
    NOT_HNDL_APPLICABLE = "not-hndl-applicable"  # e.g. strong hashes, MACs
    NOT_ASSESSED = "not-assessed"  # role undetermined / could not analyze


# --------------------------------------------------------------------------
# Evidence and findings
# --------------------------------------------------------------------------


class Evidence(_Strict):
    """One piece of material that supports a finding."""

    evidence_id: str | None = None  # assigned by assign_ids()
    finding_id: str | None = None  # assigned by assign_ids()
    file_path: str
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    evidence_type: EvidenceType
    detection_method: DetectionMethod
    rule_id: str
    excerpt: str = ""
    confidence: Confidence
    metadata: dict[str, str] = Field(default_factory=dict)  # e.g. cert fingerprint

    @field_validator("excerpt")
    @classmethod
    def _normalise_excerpt(cls, v: str) -> str:
        # Single line, bounded: repositories can contain secrets, so never keep
        # more than a short excerpt.
        v = " ".join(v.split())
        if len(v) > EXCERPT_MAX_CHARS:
            v = v[: EXCERPT_MAX_CHARS - 1] + "\u2026"
        return v

    @model_validator(mode="after")
    def _check_lines(self):
        if self.line_start is not None and self.line_end is None:
            self.line_end = self.line_start
        if self.line_end is not None and self.line_start is None:
            raise ValueError("line_end given without line_start")
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end must be >= line_start")
        return self

    @property
    def location(self) -> str:
        if self.line_start is None:
            return self.file_path
        return f"{self.file_path}:{self.line_start}"


class CryptoFinding(_Strict):
    """A detected cryptographic asset together with what supports it."""

    finding_id: str | None = None  # assigned by assign_ids()
    algorithm: str  # family, e.g. "RSA"; "unknown" when unresolved
    variant: str | None = None  # e.g. "RSA-2048"; None when size is unresolved
    key_size: int | None = Field(default=None, gt=0)
    curve: str | None = None
    role: CryptoRole = CryptoRole.UNDETERMINED
    purpose: str | None = None
    status: FindingStatus
    evidence: list[Evidence] = Field(default_factory=list)
    evidence_gap_reason: str | None = None
    assumptions: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _ignore_computed_keys(cls, data):
        # `confidence` is derived; accept (and discard) it when re-loading JSON.
        if isinstance(data, dict) and "confidence" in data:
            data = {k: v for k, v in data.items() if k != "confidence"}
        return data

    @computed_field  # type: ignore[prop-decorator]
    @property
    def confidence(self) -> Confidence:
        """Strongest evidence confidence; UNKNOWN when there is no evidence."""
        if not self.evidence:
            return Confidence.UNKNOWN
        return max((e.confidence for e in self.evidence), key=confidence_rank)

    @model_validator(mode="after")
    def _integrity(self):
        if not self.evidence and not self.evidence_gap_reason:
            raise ValueError(
                "a finding needs evidence, or an explicit evidence_gap_reason"
            )
        if (
            self.status == FindingStatus.UNABLE_TO_ANALYZE
            and not self.evidence_gap_reason
        ):
            raise ValueError("UNABLE_TO_ANALYZE requires evidence_gap_reason")
        if self.status == FindingStatus.CONFIRMED and not any(
            e.confidence == Confidence.HIGH
            and e.evidence_type != EvidenceType.COMMENT_MENTION
            for e in self.evidence
        ):
            raise ValueError(
                "CONFIRMED requires at least one non-comment HIGH-confidence evidence"
            )
        return self

    @property
    def primary_location(self) -> str | None:
        return self.evidence[0].location if self.evidence else None


def assign_ids(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """
    Deterministically sort findings (file, line, algorithm) and assign
    CRYPTO-001.. and CRYPTO-001-E1.. identifiers. Returns the sorted list.
    """

    def key(f: CryptoFinding):
        if f.evidence:
            e = f.evidence[0]
            return (e.file_path, e.line_start or 0, f.algorithm)
        return ("", 0, f.algorithm)

    ordered = sorted(findings, key=key)
    for i, f in enumerate(ordered, start=1):
        f.finding_id = f"CRYPTO-{i:03d}"
        for j, e in enumerate(f.evidence, start=1):
            e.finding_id = f.finding_id
            e.evidence_id = f"{f.finding_id}-E{j}"
    return ordered


# --------------------------------------------------------------------------
# Coverage
# --------------------------------------------------------------------------


class FileStageResult(_Strict):
    """What one analysis stage did with one file."""

    path: str
    stage: str  # "source" | "manifest" | "artifact" | "x509"
    status: StageStatus
    reason: str | None = None


class FileRecord(_Strict):
    path: str
    outcome: FileOutcome
    stages: dict[str, StageStatus] = Field(default_factory=dict)
    reason: str | None = None

    @classmethod
    def from_stage_results(
        cls,
        path: str,
        results: list[FileStageResult],
        skip_reason: str | None = None,
    ) -> "FileRecord":
        """
        Derive the file's single outcome from its per-stage results.

        skip_reason set      -> SKIPPED     (excluded by policy)
        no stage attempted   -> UNSUPPORTED (no scanner handles this file type)
        all stages succeeded -> ANALYZED
        all stages failed    -> FAILED
        mixed                -> PARTIAL
        """
        if skip_reason:
            return cls(path=path, outcome=FileOutcome.SKIPPED, reason=skip_reason)

        if not results:
            suffix = PurePosixPath(path).suffix.lower() or "(no extension)"
            return cls(
                path=path,
                outcome=FileOutcome.UNSUPPORTED,
                reason=f"no analysis stage supports '{suffix}' files",
            )

        stages = {r.stage: r.status for r in results}
        failures = [
            f"{r.stage}: {r.reason}" for r in results if r.status == StageStatus.FAILED
        ]
        statuses = set(stages.values())
        if statuses == {StageStatus.SUCCESS}:
            outcome = FileOutcome.ANALYZED
        elif statuses == {StageStatus.FAILED}:
            outcome = FileOutcome.FAILED
        else:
            outcome = FileOutcome.PARTIAL
        return cls(
            path=path,
            outcome=outcome,
            stages=stages,
            reason="; ".join(failures) if failures else None,
        )


class CoverageReport(_Strict):
    """Accounts for every discovered file; nothing is silently dropped."""

    files_discovered: int
    files_eligible: int  # at least one analysis stage was attempted
    files_analyzed: int
    files_partial: int
    files_failed: int
    files_unsupported: int
    files_skipped: int
    file_coverage_percent: float
    stage_counts: dict[str, dict[str, int]] = Field(default_factory=dict)
    unsupported_extensions: dict[str, int] = Field(default_factory=dict)
    files: list[FileRecord] = Field(default_factory=list)
    metric_note: str = COVERAGE_METRIC_NOTE

    @classmethod
    def from_records(cls, records: list[FileRecord]) -> "CoverageReport":
        outcomes = Counter(r.outcome for r in records)
        discovered = len(records)

        stage_counts: dict[str, dict[str, int]] = {}
        for r in records:
            for stage, status in r.stages.items():
                bucket = stage_counts.setdefault(stage, {"success": 0, "failed": 0})
                bucket[status.value] += 1

        ext_counts: Counter[str] = Counter()
        for r in records:
            if r.outcome == FileOutcome.UNSUPPORTED:
                ext_counts[
                    PurePosixPath(r.path).suffix.lower() or "(no extension)"
                ] += 1

        analyzed = outcomes[FileOutcome.ANALYZED]
        return cls(
            files_discovered=discovered,
            files_eligible=analyzed
            + outcomes[FileOutcome.PARTIAL]
            + outcomes[FileOutcome.FAILED],
            files_analyzed=analyzed,
            files_partial=outcomes[FileOutcome.PARTIAL],
            files_failed=outcomes[FileOutcome.FAILED],
            files_unsupported=outcomes[FileOutcome.UNSUPPORTED],
            files_skipped=outcomes[FileOutcome.SKIPPED],
            file_coverage_percent=(
                round(analyzed / discovered * 100, 1) if discovered else 0.0
            ),
            stage_counts=stage_counts,
            unsupported_extensions=dict(ext_counts),
            files=records,
        )

    @model_validator(mode="after")
    def _everything_accounted_for(self):
        total = (
            self.files_analyzed
            + self.files_partial
            + self.files_failed
            + self.files_unsupported
            + self.files_skipped
        )
        if total != self.files_discovered:
            raise ValueError(
                f"outcome counts ({total}) do not add up to files_discovered "
                f"({self.files_discovered})"
            )
        return self


class ScanResult(_Strict):
    """Output of the discovery pipeline: findings plus the coverage behind them."""

    findings: list[CryptoFinding]
    coverage: CoverageReport


# --------------------------------------------------------------------------
# Project context (organisation-supplied, never inferred by the scanner)
# --------------------------------------------------------------------------

_CONTEXT_REQUIRED = (
    "data_sensitivity",
    "confidentiality_years",
    "exposure",
    "system_criticality",
)


class AssetContext(_Strict):
    """Context override for a specific asset, component, or finding.
    
    Takes precedence over project-level context. Use asset_id to match against
    a finding's primary_location or a specific finding_id. All fields are optional
    since this is an override - unset values fall through to project context.
    """
    asset_id: str  # finding_id, file path, component name, or other asset identifier
    data_sensitivity: int | None = Field(default=None, ge=0, le=5)
    confidentiality_years: float | None = Field(default=None, ge=0)
    exposure: int | None = Field(default=None, ge=0, le=5)
    system_criticality: int | None = Field(default=None, ge=0, le=5)
    migration_years: float | None = Field(default=None, ge=0)
    threat_horizon_year: int | None = Field(default=None, ge=2000, le=2100)
    # Optional compliance context; CNSA rules only apply when scope is affirmatively confirmed.
    system_category: Literal["web", "networking", "os", "firmware-signing", "other"] | None = None
    cnsa_scope_confirmed: bool | None = None


class ProjectContext(_Strict):
    project_name: str = "unnamed-project"
    data_sensitivity: int | None = Field(default=None, ge=0, le=5)
    confidentiality_years: float | None = Field(default=None, ge=0)
    exposure: int | None = Field(default=None, ge=0, le=5)
    system_criticality: int | None = Field(default=None, ge=0, le=5)
    # Mosca inputs; the policy supplies documented defaults when these are unset.
    migration_years: float | None = Field(default=None, ge=0)
    threat_horizon_year: int | None = Field(default=None, ge=2000, le=2100)
    # Optional compliance context; CNSA rules only apply when scope is affirmatively confirmed.
    system_category: Literal["web", "networking", "os", "firmware-signing", "other"] | None = None
    cnsa_scope_confirmed: bool | None = None
    # Asset-level context overrides with explicit precedence
    asset_contexts: list[AssetContext] = Field(default_factory=list)

    def missing_inputs(self) -> list[str]:
        return [name for name in _CONTEXT_REQUIRED if getattr(self, name) is None]
    
    def get_asset_context(self, finding: CryptoFinding) -> AssetContext | None:
        """Find the most specific asset context for a finding.

        Precedence (highest to lowest):
        1. Exact finding_id match (with warning - positional IDs are unstable across scans)
        2. Most specific file path match using segment-aware globs (*, **, ?)
           - Longest literal prefix wins when multiple globs match
        3. Project-level context
        4. Policy defaults

        AssetContext.asset_id can be:
        - A finding_id (e.g., "CRYPTO-001")
        - A file path with glob patterns (e.g., "src/payment/**", "tests/*.py")
        - A component name
        """
        if not self.asset_contexts:
            return None

        # Try exact finding_id match first (highest precedence)
        if finding.finding_id:
            for ac in self.asset_contexts:
                if ac.asset_id == finding.finding_id:
                    warnings.warn(
                        f"Asset context matched by finding_id '{finding.finding_id}'. "
                        "Positional finding IDs are unstable across scans; "
                        "prefer path-based asset_id with glob patterns.",
                        UserWarning,
                        stacklevel=2,
                    )
                    return ac

        # Try file path match with segment-aware glob patterns
        location = finding.primary_location
        if location:
            # Extract file path from location (remove line number if present)
            file_path = location.split(":")[0] if ":" in location else location

            # Normalize path for matching (use POSIX style)
            normalized_path = PurePosixPath(file_path).as_posix()

            # Find all matching asset contexts with glob patterns
            matches: list[tuple[int, AssetContext]] = []  # (specificity_score, asset_context)

            for ac in self.asset_contexts:
                # Skip finding_id matches (already handled above)
                if finding.finding_id and ac.asset_id == finding.finding_id:
                    continue

                pattern = ac.asset_id

                # Check if it's a glob pattern (contains *, **, or ?)
                is_glob = any(c in pattern for c in "*?")

                if is_glob:
                    # Use fnmatch with segment-aware matching
                    # fnmatch treats ** as literal **, so we need custom handling
                    if fnmatch.fnmatch(normalized_path, pattern):
                        # Calculate specificity: count of literal path segments before first wildcard
                        specificity = self._glob_specificity(pattern)
                        matches.append((specificity, ac))
                else:
                    # Exact path or prefix match
                    # Check if pattern is a directory prefix of the file path
                    if normalized_path == pattern or normalized_path.startswith(pattern + "/"):
                        # Specificity = number of path segments in the pattern
                        specificity = len(PurePosixPath(pattern).parts)
                        matches.append((specificity, ac))

            # Return the most specific match (highest specificity score)
            if matches:
                matches.sort(key=lambda x: x[0], reverse=True)
                return matches[0][1]

        return None

    @staticmethod
    def _glob_specificity(pattern: str) -> int:
        """Calculate specificity of a glob pattern.

        Higher = more specific. Based on literal path segments before first wildcard.
        """
        # Split into segments
        parts = PurePosixPath(pattern).parts
        specificity = 0

        for part in parts:
            if any(c in part for c in "*?"):
                # First wildcard segment - stop counting
                break
            specificity += 1

        return specificity


# --------------------------------------------------------------------------
# Risk
# --------------------------------------------------------------------------


class FactorScore(_Strict):
    factor: str
    score: float = Field(ge=0, le=5)
    weight: float = Field(ge=0, le=1)
    contribution: float = Field(ge=0)
    basis: str  # why this score: observed, supplied, or assumed
    assumed: bool = False
    # Provenance: where the value came from in the context hierarchy
    context_source: str | None = None  # "finding_override", "asset_context", "project_context", "policy_default"


class RiskAssessment(_Strict):
    finding_id: str
    risk_kind: RiskKind
    risk_score: float | None = Field(default=None, ge=0, le=100)
    risk_level: RiskLevel | None = None
    factors: list[FactorScore] = Field(default_factory=list)
    escalations: list[str] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)
    missing_inputs: list[str] = Field(default_factory=list)
    provisional: bool = False
    confidence: Confidence  # reported beside the score, never inside it
    policy_version: str
    # Context provenance: track which context layer was used
    context_provenance: dict[str, str] = Field(default_factory=dict)  # factor_name -> source

    @model_validator(mode="after")
    def _kind_matches_score(self):
        scored = self.risk_kind in (
            RiskKind.HNDL_CONFIDENTIALITY,
            RiskKind.SIGNATURE_TRANSITION,
            RiskKind.CLASSICAL_WEAKNESS,
        )
        if scored and (self.risk_score is None or self.risk_level is None):
            raise ValueError(
                f"{self.risk_kind.value} requires risk_score and risk_level"
            )
        if not scored and (self.risk_score is not None or self.risk_level is not None):
            raise ValueError(f"{self.risk_kind.value} must not carry a score or level")
        return self


class AssessmentResult(_Strict):
    """Top-level report: coverage + findings + risk, tied to a policy version."""

    assessment_id: str
    scan_timestamp: datetime
    target: str
    policy_version: str
    project_context: ProjectContext
    coverage: CoverageReport
    findings: list[CryptoFinding]
    risks: list[RiskAssessment] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _references_resolve(self):
        ids = [f.finding_id for f in self.findings]
        if None in ids:
            raise ValueError("all findings need a finding_id (run assign_ids)")
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate finding_id")
        unknown = {r.finding_id for r in self.risks} - set(ids)
        if unknown:
            raise ValueError(f"risk refers to unknown findings: {sorted(unknown)}")
        return self
