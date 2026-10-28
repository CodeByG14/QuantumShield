from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from quantumshield.common.models import (
    Confidence,
    CoverageReport,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FileRecord,
    FindingStatus,
    ScanResult,
    assign_ids,
)

KNOWN_CRYPTO_PACKAGES = {
    "crypto-js",
    "openssl",
    "libcrypto",
    "libssl",
    "boringssl",
    "bouncycastle",
    "nss",
    "libgcrypt",
    "gnutls",
    "wolfssl",
    "matrixssl",
    "mbedtls",
    "tlslite",
    "cryptography",
    "pycryptodome",
    "pycryptodomex",
    "pynacl",
    "pyopenssl",
    "rsa",
    "ecdsa",
    "paramiko",
}


def _canonical_name(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _package_kind(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    kind = purl[4:].split("/", 1)[0]
    return kind.strip() or None


def _is_known_crypto_package(name: str | None, purl: str | None = None) -> bool:
    canonical = _canonical_name(name)
    if not canonical:
        return False
    purl_name = _canonical_name(purl.rsplit("@", 1)[0].split("/", 1)[-1] if purl and "@" in purl else "") if purl else ""
    if canonical in KNOWN_CRYPTO_PACKAGES or purl_name in KNOWN_CRYPTO_PACKAGES:
        return True
    needles = ("crypto", "openssl", "gnutls", "gcrypt", "nss", "tls", "ssl", "bouncycastle")
    return any(needle in canonical for needle in needles) and "log" not in canonical and "logger" not in canonical


def _relationship_label(component_ref: str | None, dependencies: list[dict[str, Any]], component_map: dict[str, Any]) -> str:
    if not dependencies:
        return "unknown"
    ref = str(component_ref or "").strip()
    if not ref:
        return "unknown"
    direct_dependents = [d for d in dependencies if ref in (d.get("dependsOn") or [])]
    if direct_dependents:
        return "direct"
    if any(ref in (d.get("dependsOn") or []) for d in dependencies):
        return "transitive"
    if ref in component_map:
        return "unknown"
    return "unknown"


def _load_schema(schema_path: Path) -> Draft7Validator:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return Draft7Validator(schema)


def _validate_cyclonedx(payload: dict[str, Any]) -> None:
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "bom-1.6.schema.json"
    if not schema_path.exists():
        # The repo includes the schema file for local validation, but this project
        # is intentionally conservative: if that local schema is unavailable we
        # still accept a structurally valid subset and fail closed on malformed data.
        if not isinstance(payload.get("bomFormat"), str) or payload.get("bomFormat") != "CycloneDX":
            raise ValueError("CycloneDX SBOM must include a bomFormat of 'CycloneDX'.")
        if not isinstance(payload.get("specVersion"), str) or not payload["specVersion"].startswith("1."):
            raise ValueError("CycloneDX SBOM must include a valid specVersion string.")
        if "components" in payload and not isinstance(payload.get("components"), list):
            raise ValueError("CycloneDX SBOM components must be a list when present.")
        return

    validator = _load_schema(schema_path)
    errors = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
    if errors:
        message = errors[0].message
        raise ValueError(f"invalid CycloneDX SBOM: {message}")


def _iter_cyclonedx_components(components: Any):
    if not isinstance(components, list):
        return []
    stack = list(reversed(components))
    visited: list[dict[str, Any]] = []
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        visited.append(component)
        nested = component.get("components")
        if isinstance(nested, list):
            stack.extend(reversed(nested))
    return visited


def _iter_spdx_packages(packages: Any):
    if isinstance(packages, list):
        return [p for p in packages if isinstance(p, dict)]
    return []


def _sbom_finding_for_component(
    *,
    component: dict[str, Any],
    input_name: str,
    format_name: str,
    format_version: str,
    relationship: str,
    package_id: str,
) -> CryptoFinding:
    name = str(component.get("name") or "").strip() or "unknown-package"
    version = str(component.get("version") or component.get("versionInfo") or "").strip()
    purl = str(component.get("purl") or component.get("referenceLocator") or "").strip() or None
    ecosystem = _package_kind(purl) or str(component.get("type") or "package").strip() or "unknown"
    metadata = {
        "import_source": "sbom",
        "package": name,
        "version": version or "unknown",
        "package_id": package_id,
        "ecosystem": ecosystem,
        "relationship": relationship,
        "document_format": format_name,
        "document_version": format_version,
        "catalogue_rule": "SBOM-CRYPTO-LIBRARY-001",
    }
    if purl:
        metadata["purl"] = purl[:2048]
    if component.get("supplier"):
        metadata["supplier"] = str(component["supplier"])[:2048]
    if component.get("author"):
        metadata["author"] = str(component["author"])[:2048]
    if component.get("licenses"):
        metadata["licenses"] = json.dumps(component["licenses"], ensure_ascii=False)[:2048]
    if component.get("hashes"):
        metadata["hashes"] = json.dumps(component["hashes"], ensure_ascii=False)[:2048]
    evidence = [
        Evidence(
            file_path=input_name,
            evidence_type=EvidenceType.DEPENDENCY,
            detection_method=DetectionMethod.SBOM,
            rule_id="SBOM-CRYPTO-LIBRARY-001",
            excerpt=f"SBOM declared {name} {version} ({ecosystem})",
            confidence=Confidence.MEDIUM,
            metadata=metadata,
        )
    ]
    return CryptoFinding(
        algorithm=f"library:{_canonical_name(name)}",
        variant=(f"{name} {version}".strip())[:255],
        role=CryptoRole.UNDETERMINED,
        status=FindingStatus.POTENTIAL,
        evidence=evidence,
        evidence_gap_reason=(
            "SBOM package declaration is not proof of active application use, specific algorithm invocation, or cryptographic role. "
            "This finding requires code review or direct runtime evidence before it can be treated as a confirmed usage claim."
        ),
        assumptions=[
            "Package presence in the SBOM does not prove the library is used by the shipped application or that a specific algorithm is invoked.",
            "The imported inventory may be incomplete, stale, or lack runtime context.",
        ],
    )


def parse_sbom_file(path: str | Path) -> ScanResult:
    """Parse validated CycloneDX or SPDX JSON SBOM data into a QuantumShield ScanResult."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"SBOM file not found: {file_path}")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"SBOM file is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("SBOM JSON document must be an object at the top level.")

    findings: list[CryptoFinding] = []
    recognized: list[str] = []
    component_map: dict[str, dict[str, Any]] = {}
    dependencies: list[dict[str, Any]] = []

    if payload.get("bomFormat") == "CycloneDX":
        spec_version = str(payload.get("specVersion", "")).strip()
        if not spec_version:
            raise ValueError("CycloneDX SBOM is missing specVersion.")
        if spec_version != "1.6":
            raise ValueError(f"Unsupported CycloneDX specVersion {spec_version!r}; supported subset is CycloneDX 1.6.")
        if not isinstance(payload.get("components"), list):
            raise ValueError("CycloneDX SBOM must include a components array.")
        _validate_cyclonedx(payload)
        deps = payload.get("dependencies") if isinstance(payload.get("dependencies"), list) else []
        dependencies = [d for d in deps if isinstance(d, dict)]
        for component in _iter_cyclonedx_components(payload.get("components")):
            if not isinstance(component, dict):
                continue
            ref = str(component.get("bom-ref") or component.get("name") or "").strip()
            if ref:
                component_map[ref] = component
            name = str(component.get("name") or "").strip()
            purl = str(component.get("purl") or "").strip() or None
            if not name or not _is_known_crypto_package(name, purl):
                continue
            relationship = _relationship_label(ref or name, dependencies, component_map)
            package_id = component.get("bom-ref") or f"{name}:{version if (version := str(component.get('version') or '')) else 'unknown'}"
            findings.append(_sbom_finding_for_component(
                component=component,
                input_name=file_path.name,
                format_name="CycloneDX",
                format_version=spec_version,
                relationship=relationship,
                package_id=str(package_id)[:2048],
            ))
            recognized.append(name)

    elif isinstance(payload.get("spdxVersion"), str) and payload["spdxVersion"].startswith("SPDX-2."):
        packages = _iter_spdx_packages(payload.get("packages"))
        if not isinstance(packages, list):
            raise ValueError("SPDX SBOM must include a packages array.")
        for package in packages:
            name = str(package.get("name") or "").strip()
            refs = package.get("externalRefs") if isinstance(package.get("externalRefs"), list) else []
            purl = next((str(ref.get("referenceLocator")) for ref in refs if isinstance(ref, dict) and str(ref.get("referenceLocator", "")).startswith("pkg:")), None)
            if not name or not _is_known_crypto_package(name, purl):
                continue
            relationship = "unknown"
            findings.append(_sbom_finding_for_component(
                component={
                    "name": name,
                    "version": package.get("versionInfo"),
                    "purl": purl,
                    "type": "package",
                    "supplier": package.get("supplier") or package.get("originator"),
                    "licenses": package.get("licenseConcluded"),
                    "hashes": package.get("checksums"),
                },
                input_name=file_path.name,
                format_name="SPDX",
                format_version=str(payload.get("spdxVersion", "unknown")),
                relationship=relationship,
                package_id=str(package.get("SPDXID") or name)[:2048],
            ))
            recognized.append(name)

    else:
        raise ValueError("Unsupported or unrecognized SBOM format; supported inputs are CycloneDX JSON 1.6 and SPDX JSON 2.x.")

    records = [FileRecord(path=file_path.name, outcome="analyzed")]  # type: ignore[arg-type]
    if not findings:
        # The SBOM was valid and parsed, but no recognized crypto libraries were identified.
        records = [FileRecord(path=file_path.name, outcome="analyzed")]  # type: ignore[arg-type]
    return ScanResult(findings=assign_ids(findings), coverage=CoverageReport.from_records(records))


__all__ = [
    "KNOWN_CRYPTO_PACKAGES",
    "parse_sbom_file",
]
