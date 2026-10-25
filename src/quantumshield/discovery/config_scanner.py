"""Conservative static discovery of cryptographic settings in common config files.

This scanner reads configuration text only. It does not load or validate the
configuration in its target service, and a configured algorithm is not proof
that a running service negotiates or uses it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)
from quantumshield.discovery.stage import StageOutput


_CONFIG_NAMES = {
    "nginx.conf",
    "httpd.conf",
    "apache2.conf",
    "sshd_config",
    "openssl.cnf",
    "openssl.conf",
    "java.security",
}
_CONFIG_SUFFIXES = {".conf", ".cnf"}


def is_config_candidate(name: str) -> bool:
    """Return whether the filename is one Phase 6A can inspect."""
    lower = PurePosixPath(name).name.lower()
    return lower in _CONFIG_NAMES or PurePosixPath(lower).suffix in _CONFIG_SUFFIXES


@dataclass(frozen=True)
class _Directive:
    family: str
    kind: str


_DIRECTIVES: dict[str, _Directive] = {
    # Nginx
    "ssl_protocols": _Directive("nginx", "protocol"),
    "ssl_ciphers": _Directive("nginx", "cipher"),
    "ssl_ecdh_curve": _Directive("nginx", "group"),
    # Apache HTTP Server
    "sslprotocol": _Directive("apache", "protocol"),
    "sslciphersuite": _Directive("apache", "cipher"),
    # OpenSSH server
    "kexalgorithms": _Directive("openssh", "kex"),
    "hostkeyalgorithms": _Directive("openssh", "signature"),
    "pubkeyacceptedalgorithms": _Directive("openssh", "signature"),
    "ciphers": _Directive("openssh", "cipher"),
    # OpenSSL configuration
    "minprotocol": _Directive("openssl", "minimum-protocol"),
    "cipherstring": _Directive("openssl", "cipher"),
    "groups": _Directive("openssl", "group"),
    # Java security properties
    "jdk.tls.disabledalgorithms": _Directive("java-security", "disabled"),
}

_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_.-]*)\s*(?:=|\s)\s*(.*?)\s*;?\s*$")
_TOKEN_SPLIT_RE = re.compile(r"[\s,:;]+")
_PROTOCOL_RE = re.compile(r"^(?:SSLv3|TLSv1(?:\.[0-3])?)$", re.IGNORECASE)
_VARIABLE_RE = re.compile(
    r"(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%)"
)

# These expressions are intentionally narrow: configuration values contain
# many aliases and modifiers that are not themselves algorithms.
_HYBRID_RULES = (
    (re.compile(r"sntrup761x25519-sha512", re.IGNORECASE), "SNTRUP", "key-establishment"),
    (re.compile(r"(?:mlkem|ml-kem)[-_]?(512|768|1024)x25519(?:-sha256)?", re.IGNORECASE), "ML-KEM", "key-establishment"),
    (re.compile(r"x25519[-_]kyber[-_]?(512|768|1024)", re.IGNORECASE), "ML-KEM", "key-establishment"),
    (re.compile(r"(?:p256|secp256r1)[-_]kyber[-_]?(512|768|1024)", re.IGNORECASE), "ML-KEM", "key-establishment"),
    (re.compile(r"(?:x25519[-_]?)?mlkem[-_]?(512|768|1024)(?:[-_]x25519)?(?:-sha256)?", re.IGNORECASE), "ML-KEM", "key-establishment"),
)

_PQC_RULES = (
    (re.compile(r"(?:ml[-_]?kem|kyber)[-_]?(512|768|1024)", re.IGNORECASE), "ML-KEM", "kem"),
    (re.compile(r"(?:ml[-_]?dsa|dilithium)[-_]?(44|65|87)", re.IGNORECASE), "ML-DSA", "signature"),
    (re.compile(r"(?:slh[-_]?dsa|sphincs\+?)[-_]?(?:sha2|shake)?[-_]?(128|192|256)(?:[-_]?(?:s|f))?", re.IGNORECASE), "SLH-DSA", "signature"),
    (re.compile(r"falcon[-_]?(512|1024)", re.IGNORECASE), "Falcon", "signature"),
    (re.compile(r"frodo[-_]?kem(?:[-_]?(640|976|1344))?", re.IGNORECASE), "FrodoKEM", "kem"),
    (re.compile(r"bike[-_]?(?:l)?(1|3|5)", re.IGNORECASE), "BIKE", "kem"),
    (re.compile(r"hqc[-_]?(128|192|256)", re.IGNORECASE), "HQC", "kem"),
)

@dataclass(frozen=True)
class _Algorithm:
    algorithm: str
    variant: str | None
    role: CryptoRole
    curve: str | None = None


def _strip_comment(line: str) -> str:
    """Strip # or ! comments, respecting quotes and escaped comment markers."""
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        elif char == "!" and not line[:index].strip():
            # Java properties allow a leading ! comment. Do not treat OpenSSL's
            # in-value !cipher exclusion operator as a comment.
            return ""
    return line


def _split_value(value: str) -> list[str]:
    return [token.strip().strip(";") for token in _TOKEN_SPLIT_RE.split(value) if token.strip().strip(";")]


def _role_from_kind(kind: str, suggested: str | None = None) -> CryptoRole:
    # A recognized post-quantum primitive's function takes precedence over the
    # broad directive category (for example, ML-DSA remains a signature).
    if suggested == "signature":
        return CryptoRole.SIGNATURE
    if suggested in {"kem", "key-establishment"}:
        return CryptoRole.KEY_ESTABLISHMENT
    if kind in {"group", "kex"}:
        return CryptoRole.KEY_ESTABLISHMENT
    if kind == "minimum-protocol":
        return CryptoRole.UNDETERMINED
    if kind == "signature":
        return CryptoRole.SIGNATURE
    if kind == "cipher":
        return CryptoRole.SYMMETRIC_ENCRYPTION
    return CryptoRole.UNDETERMINED


def _normalise_pqc_variant(token: str, family: str, match: re.Match[str]) -> str:
    # Keep the recognized standardized parameter set readable; the exact source
    # spelling is preserved independently in evidence metadata.
    try:
        level = next(group for group in match.groups() if group is not None)
    except StopIteration:
        return token
    if family == "ML-KEM":
        return f"ML-KEM-{level}"
    if family == "ML-DSA":
        return f"ML-DSA-{level}"
    if family == "SLH-DSA":
        return token.upper()
    if family == "Falcon":
        return f"Falcon-{level}"
    if family == "FrodoKEM":
        return f"FrodoKEM-{level}" if level else "FrodoKEM"
    if family == "BIKE":
        return f"BIKE-{level}"
    if family == "HQC":
        return f"HQC-{level}"
    return token


def _classify_token(token: str, kind: str) -> list[_Algorithm]:
    """Map a single configured token to zero or more inventory descriptions."""
    # OpenSSL/Apache cipher expressions can prefix names with !, +, - or @.
    core = token.lstrip("!+-@")
    if not core:
        return []

    # Hybrid names are recognized as complete source tokens first. Do not split
    # them into their classical and post-quantum components: the exact hybrid
    # name is important evidence.
    for pattern, family, suggested_role in _HYBRID_RULES:
        match = pattern.search(core)
        if match:
            role = _role_from_kind(kind, suggested_role)
            return [_Algorithm(family, core, role)]

    for pattern, family, suggested_role in _PQC_RULES:
        match = pattern.search(core)
        if match:
            role = _role_from_kind(kind, suggested_role)
            return [_Algorithm(family, _normalise_pqc_variant(core, family, match), role)]

    if _PROTOCOL_RE.fullmatch(core):
        # Preserve protocol version as a variant so consumers can distinguish
        # TLSv1.0 / SSLv3 from modern TLS without implying runtime negotiation.
        return [_Algorithm("TLS", core, CryptoRole.UNDETERMINED)]

    lower = core.lower()
    results: list[_Algorithm] = []

    if kind in {"group", "kex"}:
        # SSH group/Key Exchange names have algorithm suffixes (usually hashes).
        curve_name = re.search(
            r"(x25519|curve25519|x448|(?:nistp|secp|prime)(?:192|224|256|384|521)|p-(?:192|224|256|384|521))",
            lower,
        )
        if curve_name or "ecdh" in lower:
            curve = None
            if "x25519" in lower or "curve25519" in lower:
                curve = "X25519"
            elif "x448" in lower:
                curve = "X448"
            else:
                curve_match = re.search(r"(?:nistp|secp|prime|p-)(192|224|256|384|521)", lower)
                if curve_match:
                    curve = f"P-{curve_match.group(1)}"
            results.append(_Algorithm("ECDH", core, CryptoRole.KEY_ESTABLISHMENT, curve))
            return results
        if "diffie-hellman" in lower or re.search(r"\bdh[-_]?(?:group|modp)", lower):
            return [_Algorithm("DH", core, CryptoRole.KEY_ESTABLISHMENT)]
        if "mlkem" in lower or "kyber" in lower:
            return [_Algorithm("ML-KEM", core, CryptoRole.KEY_ESTABLISHMENT)]

    if kind == "signature":
        if "ed25519" in lower:
            return [_Algorithm("Ed25519", core, CryptoRole.SIGNATURE)]
        if "ed448" in lower:
            return [_Algorithm("Ed448", core, CryptoRole.SIGNATURE)]
        if "ecdsa" in lower:
            curve = None
            curve_match = re.search(r"(?:nistp|secp|prime)(256|384|521|224|192)", lower)
            if curve_match:
                curve = f"P-{curve_match.group(1)}"
            return [_Algorithm("ECDSA", core, CryptoRole.SIGNATURE, curve)]
        if "rsa" in lower:
            return [_Algorithm("RSA", core, CryptoRole.SIGNATURE)]

    if kind == "cipher":
        # Composite suites are decomposed into useful inventory components.
        if "ecdhe" in lower or "ecdh" in lower:
            results.append(_Algorithm("ECDH", "ECDHE" if "ecdhe" in lower else "ECDH", CryptoRole.KEY_ESTABLISHMENT))
        if "diffie-hellman" in lower or re.search(r"(^|[-_])dhe($|[-_])", lower):
            results.append(_Algorithm("DH", core, CryptoRole.KEY_ESTABLISHMENT))
        if "ecdsa" in lower:
            results.append(_Algorithm("ECDSA", core, CryptoRole.SIGNATURE))
        elif re.search(r"(^|[-_])rsa($|[-_])", lower) or lower.startswith("rsa-"):
            results.append(_Algorithm("RSA", core, CryptoRole.SIGNATURE))
        if re.search(r"aes[-_]?(128|192|256)", lower):
            aes_match = re.search(r"aes[-_]?(128|192|256)", lower)
            results.append(_Algorithm("AES", f"AES-{aes_match.group(1)}", CryptoRole.SYMMETRIC_ENCRYPTION))
        elif "chacha20" in lower:
            results.append(_Algorithm("ChaCha20", "ChaCha20-Poly1305" if "poly1305" in lower else "ChaCha20", CryptoRole.SYMMETRIC_ENCRYPTION))
        elif "3des" in lower or "des-ede" in lower:
            results.append(_Algorithm("3DES", "3DES", CryptoRole.SYMMETRIC_ENCRYPTION))
        elif "rc4" in lower or "arcfour" in lower:
            results.append(_Algorithm("RC4", "RC4", CryptoRole.SYMMETRIC_ENCRYPTION))
        elif re.search(r"(?<![a-z0-9])des(?![a-z0-9])", lower):
            results.append(_Algorithm("DES", "DES", CryptoRole.SYMMETRIC_ENCRYPTION))
        elif "camellia" in lower:
            results.append(_Algorithm("Camellia", core, CryptoRole.SYMMETRIC_ENCRYPTION))
        elif "aria" in lower:
            results.append(_Algorithm("ARIA", core, CryptoRole.SYMMETRIC_ENCRYPTION))
        if "sha512" in lower or "sha-512" in lower:
            results.append(_Algorithm("SHA-512", "SHA-512", CryptoRole.HASH))
        elif "sha384" in lower or "sha-384" in lower:
            results.append(_Algorithm("SHA-384", "SHA-384", CryptoRole.HASH))
        elif "sha256" in lower or "sha-256" in lower:
            results.append(_Algorithm("SHA-256", "SHA-256", CryptoRole.HASH))
        elif "sha1" in lower or "sha-1" in lower:
            results.append(_Algorithm("SHA-1", "SHA-1", CryptoRole.HASH))
        elif "md5" in lower:
            results.append(_Algorithm("MD5", "MD5", CryptoRole.HASH))
        # Some SSH cipher tokens are just one cipher name rather than suites.
        if not results:
            if "aes" in lower:
                results.append(_Algorithm("AES", core, CryptoRole.SYMMETRIC_ENCRYPTION))
            elif "chacha20" in lower:
                results.append(_Algorithm("ChaCha20", core, CryptoRole.SYMMETRIC_ENCRYPTION))
            elif "3des" in lower:
                results.append(_Algorithm("3DES", core, CryptoRole.SYMMETRIC_ENCRYPTION))
            elif "rc4" in lower or "arcfour" in lower:
                results.append(_Algorithm("RC4", core, CryptoRole.SYMMETRIC_ENCRYPTION))

    if kind == "disabled":
        # Java's jdk.tls.disabledAlgorithms expresses exclusions/constraints.
        # Recognize algorithms, but keep their disabled state explicit.
        if "ed25519" in lower:
            results.append(_Algorithm("Ed25519", core, CryptoRole.SIGNATURE))
        if "ecdsa" in lower:
            results.append(_Algorithm("ECDSA", core, CryptoRole.SIGNATURE))
        if "rsa" in lower:
            results.append(_Algorithm("RSA", core, CryptoRole.SIGNATURE))
        if "md5" in lower:
            results.append(_Algorithm("MD5", "MD5", CryptoRole.HASH))
        if "sha1" in lower or "sha-1" in lower:
            results.append(_Algorithm("SHA-1", "SHA-1", CryptoRole.HASH))
        if "rc4" in lower:
            results.append(_Algorithm("RC4", "RC4", CryptoRole.SYMMETRIC_ENCRYPTION))
        if "3des" in lower or re.search(r"(?<![a-z0-9])des(?![a-z0-9])", lower):
            results.append(_Algorithm("3DES" if "3des" in lower else "DES", core, CryptoRole.SYMMETRIC_ENCRYPTION))
        if "dh" in lower:
            results.append(_Algorithm("DH", core, CryptoRole.KEY_ESTABLISHMENT))

    return results


def _setting_state(directive: str, raw_token: str, kind: str) -> str:
    token = raw_token.strip()
    if kind == "disabled":
        return "disabled-or-constrained"
    if kind == "minimum-protocol":
        return "minimum-protocol-boundary"
    if directive.lower() == "sslprotocol":
        if token.startswith("-"):
            return "excluded-by-protocol-policy"
        if token.startswith("+"):
            return "explicitly-enabled-by-protocol-policy"
        return "included-by-protocol-policy"
    if token.startswith("!"):
        return "excluded-by-cipher-policy"
    if token.startswith("-"):
        return "removed-by-cipher-policy"
    if token.startswith("+"):
        return "added-by-cipher-policy"
    if kind == "protocol":
        return "configured-protocol-policy"
    if kind in {"group", "kex", "signature", "cipher"}:
        return "configured-allow-list-or-policy"
    return "configured"


def _dynamic_finding(rel_path: str, line_number: int, line: str, family: str, directive: str) -> CryptoFinding:
    evidence = Evidence(
        file_path=rel_path,
        line_start=line_number,
        line_end=line_number,
        evidence_type=EvidenceType.DYNAMIC_SELECTION,
        detection_method=DetectionMethod.REGEX,
        rule_id="CONFIG-DYNAMIC-SELECTION",
        excerpt=line[:200],
        confidence=Confidence.MEDIUM,
        metadata={
            "config_family": family,
            "directive": directive,
            "selection_source": "variable-or-placeholder",
            "static_analysis_only": "true",
        },
    )
    return CryptoFinding(
        algorithm="unknown",
        role=CryptoRole.UNDETERMINED,
        purpose="dynamic-algorithm-selection",
        status=FindingStatus.POTENTIAL,
        evidence=[evidence],
        assumptions=[
            "Configuration value references a variable or placeholder; resolve it before determining the effective algorithms."
        ],
    )


def scan_config(text: str, rel_path: str) -> StageOutput:
    """Scan supported directives in a configuration-like text file."""
    findings: list[CryptoFinding] = []
    lines = text.splitlines()

    for line_number, original_line in enumerate(lines, start=1):
        uncommented = _strip_comment(original_line).strip()
        if not uncommented:
            continue
        match = _LINE_RE.match(uncommented)
        if not match:
            continue

        directive_name, value = match.group(1), match.group(2).strip()
        spec = _DIRECTIVES.get(directive_name.lower())
        if spec is None or not value:
            continue
        value = value.rstrip(";").strip()
        if not value:
            continue

        # If this line yields neither a recognized token nor a variable signal,
        # still record the supported directive as an unresolved policy setting.
        line_findings_start = len(findings)

        # Repeated variable-based values can influence the effective crypto
        # policy. Preserve that uncertainty as an agility signal for downstream
        # assessment rather than guessing the resolved algorithm.
        if _VARIABLE_RE.search(value):
            findings.append(_dynamic_finding(rel_path, line_number, original_line, spec.family, directive_name))

        seen: set[tuple[str, str | None, CryptoRole, str | None]] = set()
        for raw_token in _split_value(value):
            for descriptor in _classify_token(raw_token, spec.kind):
                dedupe_key = (descriptor.algorithm, descriptor.variant, descriptor.role, descriptor.curve)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                token_core = raw_token.lstrip("!+-@")
                rule_suffix = re.sub(r"[^A-Za-z0-9]+", "-", directive_name).strip("-").upper()
                evidence = Evidence(
                    file_path=rel_path,
                    line_start=line_number,
                    line_end=line_number,
                    evidence_type=EvidenceType.KEYWORD,
                    detection_method=DetectionMethod.REGEX,
                    rule_id=f"CONFIG-{spec.family.upper()}-{rule_suffix}",
                    excerpt=original_line[:200],
                    confidence=Confidence.HIGH,
                    metadata={
                        "config_family": spec.family,
                        "directive": directive_name,
                        "algorithm_token": token_core,
                        "source_token": raw_token,
                        "setting_state": _setting_state(directive_name, raw_token, spec.kind),
                        "static_analysis_only": "true",
                    },
                )
                findings.append(
                    CryptoFinding(
                        algorithm=descriptor.algorithm,
                        variant=descriptor.variant,
                        curve=descriptor.curve,
                        role=descriptor.role,
                        purpose="static-configuration-setting",
                        status=FindingStatus.POTENTIAL,
                        evidence=[evidence],
                        assumptions=[
                            "Static configuration evidence does not establish runtime negotiation or use."
                        ],
                    )
                )

        if len(findings) == line_findings_start:
            evidence = Evidence(
                file_path=rel_path,
                line_start=line_number,
                line_end=line_number,
                evidence_type=EvidenceType.KEYWORD,
                detection_method=DetectionMethod.REGEX,
                rule_id="CONFIG-UNRESOLVED-POLICY",
                excerpt=original_line[:200],
                confidence=Confidence.MEDIUM,
                metadata={
                    "config_family": spec.family,
                    "directive": directive_name,
                    "setting_state": "unresolved-alias-or-policy",
                    "static_analysis_only": "true",
                },
            )
            findings.append(
                CryptoFinding(
                    algorithm="unknown",
                    role=CryptoRole.UNDETERMINED,
                    purpose="static-configuration-setting",
                    status=FindingStatus.POTENTIAL,
                    evidence=[evidence],
                    assumptions=[
                        "The directive was recognized but its alias, variable, or policy value did not resolve to a specific algorithm."
                    ],
                )
            )

    return StageOutput(findings=findings, ok=True)
