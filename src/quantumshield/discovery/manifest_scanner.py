"""
Manifest stage: crypto-capable libraries declared in requirements.txt / pyproject.toml.

A declared dependency shows capability, not use, so findings are POTENTIAL with
MEDIUM confidence and no algorithm: the manifest alone cannot say which
algorithms the code actually calls.
"""

import re
import tomllib

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)
from quantumshield.discovery.stage import StageOutput

KNOWN_CRYPTO_LIBS = {
    "cryptography": "RSA, ECC, DH, AES, SHA-2 and X.509 support",
    "pycryptodome": "RSA, ECC, DH, AES, DES, hashing",
    "pycryptodomex": "RSA, ECC, DH, AES, DES, hashing",
    "pyopenssl": "TLS and X.509 via OpenSSL",
    "pynacl": "X25519, Ed25519, libsodium primitives",
    "rsa": "RSA encryption and signatures",
    "ecdsa": "ECDSA signatures",
    "paramiko": "SSH (RSA, ECDSA, Ed25519 host and user keys)",
}

_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _package_name(spec: str) -> str | None:
    m = _NAME.match(spec)
    return _canonical(m.group(1)) if m else None


def _requirements(text: str) -> list[tuple[str, int, str]]:
    found = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        name = _package_name(line)
        if name:
            found.append((name, lineno, line))
    return found


def _pyproject(text: str) -> list[tuple[str, int, str]]:
    data = tomllib.loads(text)  # raises tomllib.TOMLDecodeError on invalid TOML
    specs: list[str] = []
    project = data.get("project", {})
    specs += [s for s in project.get("dependencies", []) if isinstance(s, str)]
    for group in project.get("optional-dependencies", {}).values():
        specs += [s for s in group if isinstance(s, str)]
    for group in data.get("dependency-groups", {}).values():
        specs += [s for s in group if isinstance(s, str)]  # PEP 735; include-group dicts skipped
    specs += list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}))

    lines = text.splitlines()
    found = []
    for spec in specs:
        name = _package_name(spec)
        if not name:
            continue
        lineno = next(
            (
                i
                for i, ln in enumerate(lines, start=1)
                if not ln.lstrip().startswith("#")
                and re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", _canonical_line(ln))
            ),
            None,
        )
        found.append((name, lineno, spec))
    return found


def _canonical_line(line: str) -> str:
    return re.sub(r"[-_.]+", "-", line).lower()


def scan_manifest(text: str, rel_path: str, file_name: str) -> StageOutput:
    try:
        deps = _pyproject(text) if file_name == "pyproject.toml" else _requirements(text)
    except tomllib.TOMLDecodeError as exc:
        return StageOutput(ok=False, reason=f"invalid TOML: {exc}")

    by_lib: dict[str, list[tuple[int | None, str]]] = {}
    for name, lineno, spec in deps:
        if name in KNOWN_CRYPTO_LIBS:
            by_lib.setdefault(name, []).append((lineno, spec))

    findings = []
    for lib, entries in sorted(by_lib.items()):
        evidence = [
            Evidence(
                file_path=rel_path,
                line_start=lineno,
                evidence_type=EvidenceType.DEPENDENCY,
                detection_method=DetectionMethod.MANIFEST,
                rule_id="MANIFEST-001",
                excerpt=spec,
                confidence=Confidence.MEDIUM,
                metadata={"package": lib, "capability": KNOWN_CRYPTO_LIBS[lib]},
            )
            for lineno, spec in entries
        ]
        findings.append(
            CryptoFinding(
                algorithm=f"library:{lib}",
                status=FindingStatus.POTENTIAL,
                evidence=evidence,
            )
        )
    return StageOutput(findings=findings)
