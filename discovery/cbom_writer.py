"""
CycloneDX 1.6 CBOM writer.

Standard fields carry the inventory (algorithm / certificate / key material /
library components, with evidence occurrences). Everything QuantumShield-
specific -- status, confidence, role, rule ids, assumptions, coverage -- goes in
`properties`, the schema's extension point, so the document stays valid.
"""

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from common.models import (
    CryptoFinding,
    CryptoRole,
    EvidenceType,
    FindingStatus,
    ScanResult,
)

_SYMMETRIC_PRIMITIVE = "block-cipher"


def _primitive(f: CryptoFinding) -> str:
    if f.role == CryptoRole.KEY_ESTABLISHMENT:
        return "pke" if f.algorithm == "RSA" else "key-agree"
    return {
        CryptoRole.SIGNATURE: "signature",
        CryptoRole.SYMMETRIC_ENCRYPTION: _SYMMETRIC_PRIMITIVE,
        CryptoRole.HASH: "hash",
        CryptoRole.MAC: "mac",
    }.get(f.role, "unknown")


def _properties(f: CryptoFinding) -> list[dict]:
    props = [
        {"name": "quantumshield:finding-id", "value": f.finding_id or ""},
        {"name": "quantumshield:status", "value": f.status.value},
        {"name": "quantumshield:confidence", "value": f.confidence.value},
        {"name": "quantumshield:role", "value": f.role.value},
        {"name": "quantumshield:rules", "value": ",".join(sorted({e.rule_id for e in f.evidence}))},
    ]
    if f.purpose:
        props.append({"name": "quantumshield:purpose", "value": f.purpose})
    if f.evidence_gap_reason:
        props.append({"name": "quantumshield:evidence-gap", "value": f.evidence_gap_reason})
    props += [{"name": "quantumshield:assumption", "value": a} for a in f.assumptions]
    if f.evidence:
        props += [
            {"name": f"quantumshield:{k.replace('_', '-')}", "value": v}
            for k, v in f.evidence[0].metadata.items()
        ]
    return props


def _occurrences(f: CryptoFinding) -> dict:
    occ = []
    for e in f.evidence:
        item = {"location": e.file_path}
        if e.line_start is not None:
            item["line"] = e.line_start
        if e.excerpt:
            item["additionalContext"] = e.excerpt
        occ.append(item)
    return {"occurrences": occ}


def _component(f: CryptoFinding) -> dict:
    first = f.evidence[0] if f.evidence else None
    base = {"bom-ref": f"component/{f.finding_id}", "properties": _properties(f)}
    if f.evidence:
        base["evidence"] = _occurrences(f)

    if f.algorithm.lower().startswith("library:") and any(
        e.metadata.get("inventory_source") == "rootfs" for e in f.evidence
    ):
        # System libraries are not PyPI packages; use the generic package type.
        pkg = f.algorithm.split(":", 1)[1].lower()
        return {"type": "library", "name": pkg, "purl": f"pkg:generic/{pkg}", **base}

    if first and first.evidence_type == EvidenceType.DEPENDENCY:
        pkg = f.algorithm.removeprefix("library:")
        return {"type": "library", "name": pkg, "purl": f"pkg:pypi/{pkg}", **base}

    name = f.variant or f.algorithm

    if first and first.evidence_type == EvidenceType.CERTIFICATE:
        meta = first.metadata
        cert = {"certificateFormat": "X.509"}
        for src, dst in (
            ("subject", "subjectName"),
            ("issuer", "issuerName"),
            ("not_valid_before", "notValidBefore"),
            ("not_valid_after", "notValidAfter"),
        ):
            if src in meta:
                cert[dst] = meta[src]
        return {
            "type": "cryptographic-asset",
            "name": f"certificate ({name})",
            "cryptoProperties": {"assetType": "certificate", "certificateProperties": cert},
            **base,
        }

    algorithm_known = f.algorithm != "unknown" and f.status != FindingStatus.UNABLE_TO_ANALYZE
    if first and first.evidence_type == EvidenceType.KEY_FILE and algorithm_known:
        material = first.metadata.get("key_material", "unknown")
        related = {"type": f"{material}-key" if material in ("public", "private") else "unknown"}
        if f.key_size:
            related["size"] = f.key_size
        return {
            "type": "cryptographic-asset",
            "name": f"{material} key ({name})",
            "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": related},
            **base,
        }

    if not algorithm_known:
        return {
            "type": "cryptographic-asset",
            "name": "unidentified cryptographic material",
            "cryptoProperties": {
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": {"type": "unknown"},
            },
            **base,
        }

    algo_props = {"primitive": _primitive(f)}
    if f.key_size and not f.curve:
        algo_props["parameterSetIdentifier"] = str(f.key_size)
    if f.curve:
        algo_props["curve"] = f.curve
    return {
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo_props},
        **base,
    }


def scan_result_to_cbom(result: ScanResult, target_name: str) -> dict:
    cov = result.coverage
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": target_name},
            "properties": [
                {"name": "quantumshield:files-discovered", "value": str(cov.files_discovered)},
                {"name": "quantumshield:files-analyzed", "value": str(cov.files_analyzed)},
                {"name": "quantumshield:files-partial", "value": str(cov.files_partial)},
                {"name": "quantumshield:files-failed", "value": str(cov.files_failed)},
                {"name": "quantumshield:files-unsupported", "value": str(cov.files_unsupported)},
                {"name": "quantumshield:files-skipped", "value": str(cov.files_skipped)},
                {"name": "quantumshield:file-coverage-percent", "value": str(cov.file_coverage_percent)},
            ],
        },
        "components": [_component(f) for f in result.findings],
    }


def write_cbom(result: ScanResult, target_name: str, output_file: str | Path = "cbom.json") -> dict:
    cbom = scan_result_to_cbom(result, target_name)
    Path(output_file).write_text(json.dumps(cbom, indent=2), encoding="utf-8")
    return cbom


def main(argv: list[str] | None = None) -> None:
    from discovery.pipeline import run_scan

    parser = argparse.ArgumentParser(description="Scan a project and write a CBOM.")
    parser.add_argument("target", nargs="?", default="samples/test-repo")
    parser.add_argument("-o", "--output", default="cbom.json")
    args = parser.parse_args(argv)

    result = run_scan(args.target)
    write_cbom(result, Path(args.target).resolve().name, args.output)

    cov = result.coverage
    print(f"Wrote {args.output}: {len(result.findings)} findings")
    by_status: dict[str, int] = {}
    for f in result.findings:
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
    print("  status:", ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    print(
        f"  coverage: {cov.file_coverage_percent}% of {cov.files_discovered} files fully analyzed "
        f"(analyzed={cov.files_analyzed}, partial={cov.files_partial}, failed={cov.files_failed}, "
        f"unsupported={cov.files_unsupported}, skipped={cov.files_skipped})"
    )
    for r in cov.files:
        if r.outcome.value in ("failed", "partial"):
            print(f"  ! {r.outcome.value}: {r.path} -- {r.reason}")


if __name__ == "__main__":
    main()
