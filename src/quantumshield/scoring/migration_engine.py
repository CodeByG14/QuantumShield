"""Migration recommendation engine for QuantumShield Week 6 Track 2.

This engine generates role-aware, versioned migration recommendations based
on cryptographic findings. Recommendations are advisory only and include
explicit caveats, effort estimates, and verification steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
)


@dataclass
class MigrationRecommendation:
    """A single migration recommendation for a finding."""

    recommendation_id: str  # e.g., REC-001
    finding_id: str | None
    source_algorithm: str
    source_role: str

    target_algorithm: str | None
    target_standard: str | None
    rationale: str

    compatibility_notes: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)

    effort_band: str | None = None  # small, medium, large, null for review
    confidence: str = "high"  # high, medium, low
    action_type: str = "migrate"  # migrate, review, urgent-classical, no-action-needed, manual-review

    # Phase 2 additions
    category: str = "PQC_MIGRATION"  # PQC_MIGRATION, CLASSICAL_HYGIENE, INVESTIGATION, DEPENDENCY
    wave: int | None = None  # W1..W4 (None for non-PQC)
    timeline_months: int | None = None  # 0-3, 3-6, 6-12, 12-24
    depends_on: list[str] = field(default_factory=list)  # other REC-IDs this depends on
    strategy_rule: str | None = None  # e.g., "hybrid-first", "deprecate-legacy", "immediate-replace"
    kb_sources: list[dict] = field(default_factory=list)  # [{type, url, verified_on}]

    # Provenance
    policy_version: str = "1.0"
    registry_version: str = "1.0"


@dataclass
class MigrationTask:
    """A concrete migration task in the migration plan."""

    task_id: str  # TASK-001, TASK-002, etc.
    finding_id: str | None
    affected_component: str | None

    source_algorithm: str
    source_role: str
    source_location: str | None

    recommended_algorithm: str | None
    recommendation_standard: str | None

    rationale: str
    compatibility_notes: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    verification_steps: list[str] = field(default_factory=list)

    effort_band: str | None = None
    priority: int = 999  # Lower number = higher priority
    confidence: str = "high"
    status: str = "pending"  # pending, in-progress, completed, blocked, deferred
    action_type: str = "migrate"  # migrate, urgent-classical, review, manual-review, no-action-needed

    # For ordering
    depends_on: list[str] = field(default_factory=list)  # Task IDs this depends on

    # Phase 2 additions
    category: str = "PQC_MIGRATION"  # PQC_MIGRATION, CLASSICAL_HYGIENE, INVESTIGATION, DEPENDENCY
    wave: int | None = None  # W1..W4 (None for non-PQC)
    timeline_months: int | None = None  # 0-3, 3-6, 6-12, 12-24
    strategy_rule: str | None = None  # e.g., "hybrid-first", "deprecate-legacy", "immediate-replace"
    kb_sources: list[dict] = field(default_factory=list)  # [{type, url, verified_on}]


class MigrationRecommendationRegistry:
    """Registry of migration recommendations loaded from YAML."""

    def __init__(self, registry_path: str | Path | None = None):
        if registry_path is None:
            # Default to registry in scoring directory
            registry_path = Path(__file__).parent / "migration_recommendations.yaml"

        self.registry_path = Path(registry_path)
        self.data: dict[str, Any] = {}
        self.recommendations: list[dict[str, Any]] = []
        self.version: str = "unknown"

        self._load_registry()

    def _load_registry(self):
        """Load the YAML registry file."""
        if not self.registry_path.exists():
            raise FileNotFoundError(f"Migration recommendation registry not found: {self.registry_path}")

        with open(self.registry_path, "r", encoding="utf-8") as f:
            self.data = yaml.safe_load(f)

        self.version = self.data.get("version", "unknown")
        self.recommendations = self.data.get("recommendations", [])
        self._validate_registry()

    def _validate_registry(self) -> None:
        """Fail early on duplicate IDs, invalid references, or dependency cycles."""
        ids = [rec.get("id") for rec in self.recommendations]
        if any(not item for item in ids):
            raise ValueError("Migration registry contains a recommendation without an id")
        if len(ids) != len(set(ids)):
            raise ValueError("Migration registry contains duplicate recommendation IDs")
        known = set(ids)
        graph: dict[str, list[str]] = {}
        for rec in self.recommendations:
            rec_id = rec["id"]
            deps = rec.get("depends_on", []) or []
            missing = sorted(set(deps) - known)
            if missing:
                raise ValueError(f"Recommendation {rec_id} references unknown dependencies: {', '.join(missing)}")
            graph[rec_id] = list(deps)

        visiting: set[str] = set()
        visited: set[str] = set()
        def visit(node: str) -> None:
            if node in visiting:
                raise ValueError(f"Migration recommendation dependency cycle detected at {node}")
            if node in visited:
                return
            visiting.add(node)
            for dependency in graph[node]:
                visit(dependency)
            visiting.remove(node)
            visited.add(node)
        for node in graph:
            visit(node)

    def find_recommendation(
        self,
        algorithm: str,
        role: CryptoRole,
    ) -> MigrationRecommendation | None:
        """Find the best matching recommendation for an algorithm and role."""
        algorithm_norm = algorithm.strip().upper().replace("_", "-")
        role_str = role.value

        # Try exact match first
        for rec in self.recommendations:
            source_algs = [a.upper().replace("_", "-") for a in rec.get("source_algorithms", [])]
            source_roles = rec.get("source_roles", [])

            if algorithm_norm in source_algs and role_str in source_roles:
                return self._build_recommendation(rec, algorithm, role_str)

        # Try wildcard match for undetermined roles
        if role == CryptoRole.UNDETERMINED:
            for rec in self.recommendations:
                if "*" in rec.get("source_algorithms", []) and "undetermined" in rec.get("source_roles", []):
                    return self._build_recommendation(rec, algorithm, role_str)

        return None

    def _build_recommendation(
        self,
        rec_data: dict[str, Any],
        algorithm: str,
        role: str,
    ) -> MigrationRecommendation:
        """Build a MigrationRecommendation from registry data."""
        return MigrationRecommendation(
            recommendation_id=rec_data.get("id", "REC-UNKNOWN"),
            finding_id=None,  # Will be set by caller
            source_algorithm=algorithm,
            source_role=role,
            target_algorithm=rec_data.get("target_algorithm"),
            target_standard=rec_data.get("target_standard"),
            rationale=rec_data.get("rationale", ""),
            compatibility_notes=rec_data.get("compatibility_notes", []),
            prerequisites=rec_data.get("prerequisites", []),
            verification_steps=rec_data.get("verification_steps", []),
            effort_band=rec_data.get("effort_band"),
            confidence=rec_data.get("confidence", "high"),
            action_type=rec_data.get("action_type", "migrate"),
            # Phase 2 fields
            category=rec_data.get("category", "PQC_MIGRATION"),
            wave=rec_data.get("wave"),
            timeline_months=rec_data.get("timeline_months"),
            depends_on=rec_data.get("depends_on", []),
            strategy_rule=rec_data.get("strategy_rule"),
            kb_sources=rec_data.get("kb_sources", []),
            registry_version=self.version,
        )


def generate_migration_recommendation(
    finding: CryptoFinding,
    registry: MigrationRecommendationRegistry | None = None,
) -> MigrationRecommendation | None:
    """Generate a migration recommendation for a single finding.

    Args:
        finding: The cryptographic finding to assess
        registry: Optional registry (loads default if not provided)

    Returns:
        MigrationRecommendation or None if no recommendation available
    """
    if registry is None:
        registry = MigrationRecommendationRegistry()

    # Skip library findings - not direct usage
    if finding.algorithm.upper().startswith("LIBRARY:"):
        return None

    # Skip unable-to-analyze findings
    if finding.status.value == "unable-to-analyze":
        return None

    rec = registry.find_recommendation(finding.algorithm, finding.role)

    if rec:
        rec.finding_id = finding.finding_id
        # Detection uncertainty must constrain the action. Do not turn a
        # potential/low-evidence finding into an automatic migration task.
        if finding.status.value == "potential" or finding.confidence in (Confidence.LOW, Confidence.UNKNOWN):
            rec.confidence = "low"
            if rec.action_type != "no-action-needed":
                rec.action_type = "manual-review"
            rec.rationale = (
                rec.rationale.rstrip()
                + " Evidence confidence is limited; validate the finding before changing production cryptography."
            )

    return rec


def generate_migration_tasks(
    findings: list[CryptoFinding],
    *,
    registry: MigrationRecommendationRegistry | None = None,
) -> list[MigrationTask]:
    """Generate ordered migration tasks from findings.

    Args:
        findings: List of cryptographic findings
        registry: Optional registry

    Returns:
        List of MigrationTask objects with priority ordering
    """
    if registry is None:
        registry = MigrationRecommendationRegistry()

    tasks: list[MigrationTask] = []
    task_counter = 1

    for finding in findings:
        rec = generate_migration_recommendation(finding, registry)

        if rec is None:
            continue

        # Determine priority based on action type and confidence
        priority = _calculate_priority(rec, finding)

        # Build task
        task = MigrationTask(
            task_id=f"TASK-{task_counter:03d}",
            finding_id=finding.finding_id,
            affected_component=finding.primary_location,
            source_algorithm=finding.algorithm,
            source_role=finding.role.value,
            source_location=finding.primary_location,
            recommended_algorithm=rec.target_algorithm,
            recommendation_standard=rec.target_standard,
            rationale=rec.rationale,
            compatibility_notes=rec.compatibility_notes,
            prerequisites=rec.prerequisites,
            verification_steps=rec.verification_steps,
            effort_band=rec.effort_band,
            priority=priority,
            confidence=rec.confidence,
            action_type=rec.action_type,
            status="pending",
            # Phase 2 fields
            category=rec.category,
            wave=rec.wave,
            timeline_months=rec.timeline_months,
            strategy_rule=rec.strategy_rule,
            kb_sources=rec.kb_sources,
            depends_on=[],  # Will be populated after all tasks created
        )

        tasks.append(task)
        task_counter += 1

    # Build mapping from recommendation_id to task
    rec_id_to_task = {}
    for task in tasks:
        finding = next((f for f in findings if f.finding_id == task.finding_id), None)
        if finding:
            rec = generate_migration_recommendation(finding, registry)
            if rec:
                rec_id_to_task[rec.recommendation_id] = task

    # Populate depends_on based on recommendation's depends_on
    for task in tasks:
        finding = next((f for f in findings if f.finding_id == task.finding_id), None)
        if finding:
            rec = generate_migration_recommendation(finding, registry)
            if rec and rec.depends_on:
                for dep_rec_id in rec.depends_on:
                    if dep_rec_id in rec_id_to_task:
                        dep_task = rec_id_to_task[dep_rec_id]
                        if dep_task.task_id not in task.depends_on:
                            task.depends_on.append(dep_task.task_id)

    # Sort by priority (lower number = higher priority)
    tasks.sort(key=lambda t: (t.priority, t.task_id))

    return tasks


def _calculate_priority(rec: MigrationRecommendation, finding: CryptoFinding) -> int:
    """Calculate task priority based on recommendation and finding properties.

    Lower number = higher priority.

    Priority rules:
    1. Urgent classical weaknesses (MD5, SHA-1): priority 10
    2. High-confidence quantum-vulnerable signatures: priority 20
    3. High-confidence quantum-vulnerable key-establishment: priority 30
    4. Review/unknown with confirmed findings: priority 50
    5. Potential/low-confidence findings: priority 70
    6. No-action-needed: priority 100
    """

    # Urgent classical weaknesses
    if rec.action_type == "urgent-classical":
        return 10

    # Manual review or low confidence
    if rec.action_type == "manual-review" or rec.confidence == "low":
        base_priority = 50
    # No action needed
    elif rec.action_type == "no-action-needed":
        return 100
    # Signatures
    elif rec.source_role == "signature":
        base_priority = 20
    # Key establishment
    elif rec.source_role == "key-establishment":
        base_priority = 30
    else:
        base_priority = 40

    # Adjust for finding confidence and status
    if finding.status.value == "potential" or finding.confidence == Confidence.LOW:
        base_priority += 20

    return base_priority
