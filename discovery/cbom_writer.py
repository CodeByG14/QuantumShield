import json
import uuid
from datetime import datetime, timezone
from scanner import load_patterns, scan_directory

def findings_to_cbom(findings, output_file="cbom.json"):
    components = []
    for f in findings:
        components.append({
            "type": "cryptographic-asset",
            "name": f["variant"],
            "bom-ref": f"crypto/algorithm/{f['name'].lower()}-{uuid.uuid4().hex[:8]}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": f["primitive"],
                    "parameterSetIdentifier": f["variant"],
                }
            },
            "evidence": {
                "occurrences": [
                    {
                        "location": f["file"],
                        "line": f["line"],
                        "additionalContext": f["matched_text"],
                    }
                ]
            }
        })

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "quantumshield-test-repo"
            }
        },
        "components": components
    }

    with open(output_file, "w") as f:
        json.dump(cbom, f, indent=2)
    return cbom

if __name__ == "__main__":
    patterns = load_patterns()
    findings = scan_directory("samples/test-repo", patterns)
    findings_to_cbom(findings, "cbom.json")
    print(f"Generated cbom.json with {len(findings)} findings")
