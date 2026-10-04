import json
import uuid
from datetime import datetime, timezone
from collections import defaultdict

from discovery.scanner import load_patterns, scan_directory
from discovery.manifest_scanner import scan_manifests
from discovery.artifact_scanner import scan_artifacts


def dedup_findings(findings):
    groups = defaultdict(list)
    for f in findings:
        key = (f.algorithm, f.variant, f.file)
        groups[key].append(f)
    return groups


def findings_to_cbom(findings, coverage_stats, output_file="cbom.json"):
    components = []
    groups = dedup_findings(findings)

    for (algorithm, variant, file), group in groups.items():
        occurrences = [
            {
                "location": f.file,
                "line": f.line,
                "additionalContext": f.evidence,
                "confidence": f.confidence,
            }
            for f in group
        ]
        detection_methods = sorted(
            set(
                (
                    f.detection_method.value
                    if hasattr(f.detection_method, "value")
                    else f.detection_method
                )
                for f in group
            )
        )

        components.append(
            {
                "type": "cryptographic-asset",
                "name": variant or algorithm,
                "bom-ref": f"crypto/{detection_methods[0]}/{algorithm.lower()}-{uuid.uuid4().hex[:8]}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "unknown",
                        "parameterSetIdentifier": variant or algorithm,
                    },
                },
                "evidence": {
                    "occurrences": occurrences,
                    "detection_methods": detection_methods,
                },
            }
        )

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": "quantumshield-test-repo"},
            "properties": [
                {
                    "name": "quantumshield:files_discovered",
                    "value": str(coverage_stats["files_discovered"]),
                },
                {
                    "name": "quantumshield:files_analyzed",
                    "value": str(coverage_stats["files_analyzed"]),
                },
                {
                    "name": "quantumshield:files_skipped",
                    "value": str(coverage_stats["files_skipped"]),
                },
            ],
        },
        "components": components,
    }

    with open(output_file, "w") as f:
        json.dump(cbom, f, indent=2)
    return cbom


if __name__ == "__main__":
    patterns = load_patterns()

    source_result = scan_directory("samples/test-repo", patterns)
    manifest_result = scan_manifests("samples/test-repo")
    artifact_result = scan_artifacts("samples/test-repo")

    all_findings = (
        source_result.findings + manifest_result.findings + artifact_result.findings
    )
    coverage_stats = source_result.coverage.model_dump()

    cbom = findings_to_cbom(all_findings, coverage_stats, "cbom.json")

    print(
        f"Generated cbom.json with {len(cbom['components'])} components "
        f"(deduplicated from {len(all_findings)} raw findings: "
        f"{len(source_result.findings)} source, {len(manifest_result.findings)} manifest, {len(artifact_result.findings)} artifact)"
    )
    print(f"Coverage: {coverage_stats}")
