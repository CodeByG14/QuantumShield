"""Safe input preparation and JSON SBOM/CBOM import helpers.

This module never scans remote networks. GitHub input is restricted to a public
HTTPS repository URL on github.com; uploaded archives are size-bounded and
reject path traversal and symlink entries.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from quantumshield.common.models import (
    Confidence,
    CoverageReport,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FileOutcome,
    FileRecord,
    FindingStatus,
    ScanResult,
    assign_ids,
)
from quantumshield.source_contracts import ScanInputKind, ScanSourceMetadata


MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_ZIP_FILES = 10_000
MAX_ZIP_MEMBER_BYTES = 100 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 500 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 120

CRYPTO_PACKAGE_NAMES = {
    "openssl", "libssl", "libressl", "boringssl", "wolfssl", "mbedtls",
    "botan", "libsodium", "cryptography", "pycryptodome", "pycrypto",
    "bouncycastle", "bcprov", "bcpkix", "conscrypt", "netty-tcnative",
    "jose", "jose4j", "jose-jwt", "node-forge", "crypto-js",
    "@noble/curves", "@noble/ciphers", "@noble/hashes", "ring", "rustls",
    "aws-lc-rs", "liboqs", "oqs-provider", "openssl-sys", "ring-core",
}


class SourceInputError(ValueError):
    """A user-provided source is unsupported or unsafe to process."""


def canonical_github_url(raw: str) -> tuple[str, str]:
    """Return a credential-free canonical URL and owner/repository label."""
    if not isinstance(raw, str) or not raw.strip():
        raise SourceInputError("repository_url is required for GitHub input.")
    try:
        parsed = urlsplit(raw.strip())
        port = parsed.port
    except ValueError as exc:
        raise SourceInputError("Repository URL is malformed.") from exc
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise SourceInputError("Only public HTTPS repositories on github.com are supported.")
    if parsed.username or parsed.password or port or parsed.query or parsed.fragment:
        raise SourceInputError("Repository URLs must not contain credentials, ports, query strings, or fragments.")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise SourceInputError("Use a repository URL in the form https://github.com/owner/repository.")
    owner, repository = parts
    repository = repository.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repository):
        raise SourceInputError("GitHub owner or repository name contains unsupported characters.")
    if owner in {".", ".."} or repository in {".", ".."}:
        raise SourceInputError("GitHub owner or repository name is invalid.")
    canonical = urlunsplit(("https", "github.com", f"/{owner}/{repository}.git", "", ""))
    return canonical, f"{owner}/{repository}"


def safe_upload_name(filename: str | None, fallback: str = "upload.json") -> str:
    """Strip directories and control characters from a user-provided filename."""
    value = (filename or fallback).replace("\\", "/").split("/")[-1]
    value = "".join(ch for ch in value if ch.isprintable() and ch not in "\x00")
    value = value.strip().strip(".")
    if not value or value in {".", ".."}:
        value = fallback
    return value[:255]


def prepare_github_repository(repository_url: str, workspace: Path) -> tuple[Path, str, str]:
    """Clone a public GitHub repository, return scan root, label, resolved commit."""
    canonical, label = canonical_github_url(repository_url)
    destination = workspace / "source"
    env = os.environ.copy()
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
    })
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "http.followRedirects=false", "clone", "--depth", "1", "--no-tags", "--", canonical, str(destination)],
            check=False,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )
    except FileNotFoundError as exc:
        raise SourceInputError("Git is not installed on the API host.") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceInputError("Repository download exceeded the allowed time limit.") from exc
    if result.returncode != 0:
        # Do not return Git's raw stderr: it can include local paths or remote details.
        raise SourceInputError("GitHub repository could not be cloned. Check that it is public and the URL is correct.")

    try:
        revision = subprocess.run(
            ["git", "-C", str(destination), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError) as exc:
        raise SourceInputError("Could not resolve the repository commit.") from exc

    # The engine's own scanner skips .git, but removing it also bounds unrelated data.
    shutil.rmtree(destination / ".git", ignore_errors=True)
    return destination, label, revision


def _checked_member_path(root: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or "\x00" in normalized
        or any(part in {"..", ""} for part in pure.parts)
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise SourceInputError("ZIP contains an absolute or traversal path.")
    target = root.joinpath(*pure.parts)
    resolved_parent = target.parent.resolve()
    resolved_root = root.resolve()
    if resolved_parent != resolved_root and resolved_root not in resolved_parent.parents:
        raise SourceInputError("ZIP member escapes the extraction directory.")
    return target


def extract_zip_safely(archive_path: Path, workspace: Path) -> Path:
    """Safely extract a bounded ZIP without links, traversal, or unbounded expansion."""
    output_root = workspace / "source"
    output_root.mkdir(parents=True, exist_ok=True)
    total_declared = 0
    total_written = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_FILES:
                raise SourceInputError(f"ZIP has more than {MAX_ZIP_FILES} entries.")
            validated: list[tuple[zipfile.ZipInfo, Path]] = []
            seen_paths: set[str] = set()
            for member in members:
                if member.is_dir():
                    target = _checked_member_path(output_root, member.filename.rstrip("/")) if member.filename.rstrip("/") else output_root
                else:
                    target = _checked_member_path(output_root, member.filename)
                mode = (member.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise SourceInputError("ZIP contains a symbolic link, which is not supported.")
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise SourceInputError("ZIP contains a special filesystem entry, which is not supported.")
                normalized_member = member.filename.replace("\\", "/").rstrip("/")
                if normalized_member in seen_paths and normalized_member:
                    raise SourceInputError("ZIP contains duplicate file paths.")
                if normalized_member:
                    seen_paths.add(normalized_member)
                if member.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise SourceInputError("ZIP contains a file larger than the allowed limit.")
                total_declared += member.file_size
                if total_declared > MAX_ZIP_TOTAL_BYTES:
                    raise SourceInputError("ZIP expands beyond the allowed total size.")
                validated.append((member, target))
            for member, target in validated:
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(member, "r") as source, target.open("xb") as destination:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        total_written += len(chunk)
                        if written > MAX_ZIP_MEMBER_BYTES:
                            raise SourceInputError("ZIP member expanded beyond the allowed limit.")
                        if total_written > MAX_ZIP_TOTAL_BYTES:
                            raise SourceInputError("ZIP expanded beyond the allowed total size.")
                        destination.write(chunk)
                if written != member.file_size:
                    raise SourceInputError("ZIP member size did not match its directory metadata.")
    except zipfile.BadZipFile as exc:
        raise SourceInputError("Uploaded file is not a valid ZIP archive.") from exc
    except (OSError, RuntimeError) as exc:
        raise SourceInputError("ZIP could not be extracted safely.") from exc

    children = list(output_root.iterdir())
    if len(children) == 1 and children[0].is_dir() and not children[0].is_symlink():
        return children[0]
    return output_root


def _property_map(component: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        return result
    for item in properties:
        if isinstance(item, dict) and isinstance(item.get("name"), str) and "value" in item:
            result[item["name"]] = str(item["value"])
    return result


def _crypto_role(value: str | None, primitive: str | None = None) -> CryptoRole:
    role = (value or "").casefold().replace("_", "-")
    aliases = {
        "key-establishment": CryptoRole.KEY_ESTABLISHMENT,
        "key-establishment-and-agreement": CryptoRole.KEY_ESTABLISHMENT,
        "signature": CryptoRole.SIGNATURE,
        "symmetric-encryption": CryptoRole.SYMMETRIC_ENCRYPTION,
        "hash": CryptoRole.HASH,
        "mac": CryptoRole.MAC,
        "undetermined": CryptoRole.UNDETERMINED,
    }
    if role in aliases:
        return aliases[role]
    return {
        "pke": CryptoRole.KEY_ESTABLISHMENT,
        "key-agree": CryptoRole.KEY_ESTABLISHMENT,
        "signature": CryptoRole.SIGNATURE,
        "block-cipher": CryptoRole.SYMMETRIC_ENCRYPTION,
        "hash": CryptoRole.HASH,
        "mac": CryptoRole.MAC,
    }.get((primitive or "").casefold(), CryptoRole.UNDETERMINED)


def _confidence(value: str | None) -> Confidence:
    try:
        return Confidence((value or "").casefold())
    except ValueError:
        return Confidence.MEDIUM


def _status(value: str | None, confidence: Confidence, evidence_gap: str | None = None) -> FindingStatus:
    raw = (value or "").casefold()
    if raw == FindingStatus.UNABLE_TO_ANALYZE.value:
        return FindingStatus.UNABLE_TO_ANALYZE
    if raw == FindingStatus.CONFIRMED.value and confidence == Confidence.HIGH:
        return FindingStatus.CONFIRMED
    return FindingStatus.POTENTIAL


def _algorithm_from_name(name: str) -> tuple[str, str | None, int | None, str | None]:
    """Conservatively normalize common CBOM names without guessing unsupported parameters."""
    text = name.strip()
    upper = text.upper()
    if "P-256" in upper or "P-384" in upper or "P-521" in upper or "SECP" in upper:
        curve_match = re.search(r"(P-\d{3}|secp\d+[rR]?\d*)", text, re.IGNORECASE)
        return "EC", text, None, curve_match.group(1) if curve_match else None
    candidates = (
        "SLH-DSA", "ML-DSA", "ML-KEM", "ECDH", "ECDSA", "Ed25519", "Ed448",
        "X25519", "X448", "RSA", "AES", "ChaCha20", "SHA-512", "SHA-384",
        "SHA-256", "SHA-1", "SHA-224", "MD5", "DH", "DSA", "EC",
    )
    for algorithm in candidates:
        if upper.startswith(algorithm.upper()):
            size_match = re.search(r"(?:-|_|\s)(\d{2,5})(?:\b|$)", text[len(algorithm):])
            return algorithm, text, int(size_match.group(1)) if size_match else None, None
    return (text or "unknown"), (text or None), None, None


def _is_crypto_package(name: str, purl: str | None = None) -> bool:
    normalized = name.casefold().strip()
    package_tail = (purl or "").casefold().split("/")[-1].split("@")[0]
    candidates = {normalized, package_tail}
    for candidate in candidates:
        candidate = re.sub(r"[^a-z0-9@.+/-]", "", candidate)
        if candidate in CRYPTO_PACKAGE_NAMES:
            return True
        if any(candidate == marker or candidate.startswith(marker + "-") for marker in ("openssl", "libssl", "bouncycastle", "pycryptodome", "mbedtls", "wolfssl", "libsodium", "liboqs")):
            return True
    return False


def _iter_cyclonedx_components(components: Any):
    if not isinstance(components, list):
        return
    stack = list(reversed(components))
    visited = 0
    while stack:
        component = stack.pop()
        if not isinstance(component, dict):
            continue
        visited += 1
        if visited > 100_000:
            raise SourceInputError("BOM contains too many components to import safely.")
        yield component
        nested = component.get("components")
        if isinstance(nested, list):
            stack.extend(reversed(nested))


def _iter_spdx_packages(packages: Any):
    if isinstance(packages, list):
        for package in packages:
            if isinstance(package, dict):
                yield package


def parse_bom_scan_result(
    payload: dict[str, Any],
    *,
    kind: ScanInputKind,
    input_name: str,
) -> tuple[ScanResult, list[str]]:
    """Convert supported CycloneDX/SPDX SBOM or CycloneDX CBOM to engine models.

    SBOM imports emit findings only for an allowlisted set of known crypto
    libraries. General dependencies are not mislabeled as cryptographic assets.
    Imported findings are marked POTENTIAL unless a QuantumShield CBOM explicitly
    carries adequate high-confidence confirmed evidence.
    """
    findings: list[CryptoFinding] = []
    limitations: list[str] = []

    if kind == ScanInputKind.CBOM:
        if payload.get("bomFormat") != "CycloneDX":
            raise SourceInputError("CBOM import currently supports CycloneDX JSON only.")
        if not isinstance(payload.get("specVersion"), str) or not isinstance(payload.get("version"), int) or not isinstance(payload.get("components"), list):
            raise SourceInputError("CycloneDX CBOM must include specVersion, integer version, and a components array.")
        components = list(_iter_cyclonedx_components(payload.get("components")))
        assets = [c for c in components if c.get("type") == "cryptographic-asset"]
        for component in assets:
            props = _property_map(component)
            crypto = component.get("cryptoProperties") if isinstance(component.get("cryptoProperties"), dict) else {}
            asset_type = str(crypto.get("assetType", ""))
            algo_props = crypto.get("algorithmProperties") if isinstance(crypto.get("algorithmProperties"), dict) else {}
            primitive = algo_props.get("primitive") if isinstance(algo_props, dict) else None
            display_name = str(component.get("name") or "unknown cryptographic asset")[:255]
            algorithm, variant, inferred_size, inferred_curve = _algorithm_from_name(display_name)
            if asset_type == "certificate" and display_name.lower().startswith("certificate ("):
                inner = re.sub(r"^certificate\s*\((.*)\)$", r"\1", display_name, flags=re.IGNORECASE)
                algorithm, variant, inferred_size, inferred_curve = _algorithm_from_name(inner)
            if isinstance(algo_props, dict):
                parameter = algo_props.get("parameterSetIdentifier")
                if parameter is not None and str(parameter).isdigit():
                    inferred_size = int(str(parameter))
                if isinstance(algo_props.get("curve"), str):
                    inferred_curve = algo_props["curve"]
            role = _crypto_role(props.get("quantumshield:role"), str(primitive) if primitive else None)
            confidence = _confidence(props.get("quantumshield:confidence"))
            original_status = props.get("quantumshield:status")
            evidence_gap = props.get("quantumshield:evidence-gap")
            status = _status(original_status, confidence, evidence_gap)
            if status == FindingStatus.UNABLE_TO_ANALYZE and not evidence_gap:
                evidence_gap = "The imported CBOM reports that this asset could not be analyzed."
            metadata = {"import_source": "cbom", "asset_type": asset_type or "unknown"}
            for key in ("purl",):
                if component.get(key):
                    metadata[key] = str(component[key])[:2048]
            for key, prop in (("primitive", primitive), ("parameter_set", algo_props.get("parameterSetIdentifier") if isinstance(algo_props, dict) else None)):
                if prop is not None:
                    metadata[key] = str(prop)[:255]
            finding_evidence = Evidence(
                file_path=input_name,
                evidence_type=EvidenceType.CERTIFICATE if asset_type == "certificate" else EvidenceType.KEY_FILE if asset_type == "related-crypto-material" else EvidenceType.KEYWORD,
                detection_method=DetectionMethod.SBOM,
                rule_id=(props.get("quantumshield:rules", "").split(",")[0].strip() or "IMPORT-CBOM-ASSET"),
                excerpt=f"Imported from CBOM: {display_name}",
                confidence=confidence,
                metadata=metadata,
            )
            findings.append(CryptoFinding(
                algorithm=algorithm or "unknown",
                variant=variant,
                key_size=inferred_size,
                curve=inferred_curve,
                role=role,
                purpose=props.get("quantumshield:purpose"),
                status=status,
                evidence=[finding_evidence],
                evidence_gap_reason=evidence_gap,
                assumptions=["Imported from a BOM; source code was not rescanned."],
            ))
        if not findings:
            limitations.append("The CBOM contained no supported components with type 'cryptographic-asset'.")

    elif kind == ScanInputKind.SBOM:
        if payload.get("bomFormat") == "CycloneDX":
            if not isinstance(payload.get("specVersion"), str) or not isinstance(payload.get("version"), int) or not isinstance(payload.get("components"), list):
                raise SourceInputError("CycloneDX SBOM must include specVersion, integer version, and a components array.")
            components = list(_iter_cyclonedx_components(payload.get("components")))
            for component in components:
                if component.get("type") not in {"library", "framework", "application"}:
                    continue
                name = str(component.get("name") or "").strip()
                purl = component.get("purl") if isinstance(component.get("purl"), str) else None
                if not name or not _is_crypto_package(name, purl):
                    continue
                version = str(component.get("version") or "").strip()
                label = f"{name} {version}".strip()
                findings.append(CryptoFinding(
                    algorithm=f"library:{name.casefold()}",
                    variant=label[:255],
                    role=CryptoRole.UNDETERMINED,
                    status=FindingStatus.POTENTIAL,
                    evidence=[Evidence(
                        file_path=input_name,
                        evidence_type=EvidenceType.DEPENDENCY,
                        detection_method=DetectionMethod.SBOM,
                        rule_id="IMPORT-SBOM-CRYPTO-LIBRARY",
                        excerpt=f"Crypto-library package listed in SBOM: {label}",
                        confidence=Confidence.MEDIUM,
                        metadata={"import_source": "sbom", **({"purl": purl[:2048]} if purl else {})},
                    )],
                    evidence_gap_reason="SBOM package declaration is not proof of active application use, specific algorithm invocation, or cryptographic role.",
                    assumptions=["Package presence does not prove the library is used by a running application."],
                ))
        elif isinstance(payload.get("spdxVersion"), str) and payload["spdxVersion"].startswith("SPDX-2."):
            if not isinstance(payload.get("packages"), list):
                raise SourceInputError("SPDX SBOM must include a packages array.")
            for package in _iter_spdx_packages(payload.get("packages")):
                name = str(package.get("name") or "").strip()
                refs = package.get("externalRefs") if isinstance(package.get("externalRefs"), list) else []
                purl = next((str(ref.get("referenceLocator")) for ref in refs if isinstance(ref, dict) and str(ref.get("referenceLocator", "")).startswith("pkg:")), None)
                if not name or not _is_crypto_package(name, purl):
                    continue
                version = str(package.get("versionInfo") or "").strip()
                label = f"{name} {version}".strip()
                findings.append(CryptoFinding(
                    algorithm=f"library:{name.casefold()}",
                    variant=label[:255],
                    role=CryptoRole.UNDETERMINED,
                    status=FindingStatus.POTENTIAL,
                    evidence=[Evidence(
                        file_path=input_name,
                        evidence_type=EvidenceType.DEPENDENCY,
                        detection_method=DetectionMethod.SBOM,
                        rule_id="IMPORT-SBOM-CRYPTO-LIBRARY",
                        excerpt=f"Crypto-library package listed in SBOM: {label}",
                        confidence=Confidence.MEDIUM,
                        metadata={"import_source": "sbom", **({"purl": purl[:2048]} if purl else {})},
                    )],
                    evidence_gap_reason="SBOM package declaration is not proof of active application use, specific algorithm invocation, or cryptographic role.",
                    assumptions=["Package presence does not prove the library is used by a running application."],
                ))
        else:
            raise SourceInputError("SBOM import supports CycloneDX JSON and SPDX JSON documents.")
        if not findings:
            limitations.append("No supported cryptographic-library packages were identified in the imported SBOM. This does not prove that the source contains no cryptography.")
    else:
        raise SourceInputError("This source kind is not a BOM import.")

    if not findings:
        # Keep the import visible in coverage even when no recognized crypto asset exists.
        records = [FileRecord(path=input_name, outcome=FileOutcome.ANALYZED)]
    else:
        records = [FileRecord(path=input_name, outcome=FileOutcome.ANALYZED)]
    return ScanResult(findings=assign_ids(findings), coverage=CoverageReport.from_records(records)), limitations


def load_bom_json(upload_path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(upload_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SourceInputError("BOM upload must be a valid UTF-8 JSON document.") from exc
    if not isinstance(raw, dict):
        raise SourceInputError("BOM JSON document must be an object.")
    return raw
