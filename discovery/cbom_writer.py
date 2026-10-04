import json
import uuid
from datetime import datetime, timezone

from discovery.scanner import load_patterns, scan_directory
from discovery.manifest_scanner import scan_manifests
from discovery.artifact_scanner import scan_artifacts


def findings_to_cbom(findings, output_file="cbom.json"):
    components = []
    for f in findings:
        components.append(
            {
                "type": "cryptographic-asset",
                "name": f.variant or f.algorithm,
                "bom-ref": f"crypto/{f.detection_method.value if hasattr(f.detection_method, 'value') else f.detection_method}/{f.algorithm.lower()}-{uuid.uuid4().hex[:8]}",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "unknown",  # not carried on CryptoFinding currently — see note below
                        "parameterSetIdentifier": f.variant or f.algorithm,
                    },
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": f.file,
                            "line": f.line,
                            "additionalContext": f.evidence,
                            "confidence": f.confidence,
                        }
                    ],
                    "detection_method": (
                        f.detection_method.value
                        if hasattr(f.detection_method, "value")
                        else f.detection_method
                    ),
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
        },
        "components": components,
    }

    with open(output_file, "w") as f:
        json.dump(cbom, f, indent=2)
    return cbom


if __name__ == "__main__":
    patterns = load_patterns()
    source_findings = scan_directory("samples/test-repo", patterns)
    manifest_findings = scan_manifests("samples/test-repo")
    artifact_findings = scan_artifacts("samples/test-repo")

    all_findings = source_findings + manifest_findings + artifact_findings
    findings_to_cbom(all_findings, "cbom.json")
    print(
        f"Generated cbom.json with {len(all_findings)} findings "
        f"({len(source_findings)} source, {len(manifest_findings)} manifest, {len(artifact_findings)} artifact)"
    )
