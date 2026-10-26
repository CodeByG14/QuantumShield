"""Inventory cryptographic libraries in an already-extracted root filesystem.

This scanner inspects filenames and supported package-manager metadata only. It
never executes binaries, loads shared libraries, follows symbolic links, or
scans a live host. PQC capability is an upstream version-level indicator; it is
not proof that an application enables or uses those algorithms.
"""

from __future__ import annotations

import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

from quantumshield.common.models import (
    Confidence,
    CoverageReport,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FileRecord,
    FileStageResult,
    FindingStatus,
    StageStatus,
)

# The cap is applied to files whose contents are read (package metadata). Shared
# libraries and JARs are inventoried from their names and are never opened.
DEFAULT_MAX_METADATA_BYTES = 2_000_000
EXCLUDED_ROOT_DIRS = {"proc", "sys", "dev"}
DPKG_STATUS_PATH = "var/lib/dpkg/status"
APK_DATABASE_PATHS = {"lib/apk/db/installed", "var/lib/apk/db/installed"}

# Capability evidence is intentionally conservative. "yes" means that an
# upstream release provides standardized PQC APIs; it does not verify build
# flags, providers, policy, application use, or a vendor's backports.
_CAPABILITY_SOURCES = {
    "openssl": "https://openssl-library.org/post-2025-04-08-openssl-35-final-release/",
    "gnutls": "https://lists.gnutls.org/pipermail/gnutls-help/2024-November/004865.html",
    "libgcrypt": "https://lists.gnupg.org/pipermail/gnupg-announce/2026q1/000502.html",
    "nss": "https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_118.html",
    "bouncycastle": "https://www.bouncycastle.org/resources/latest-nist-pqc-standards-and-more-bouncy-castle-java-1-79/",
}
_CAPABILITY_SOURCES_EXTRA = {
    "gnutls": "https://lists.gnutls.org/pipermail/gnutls-help/2025-February/004875.html",
    "libgcrypt": "https://lists.gnupg.org/pipermail/gnupg-devel/2024-June/035585.html",
    "bouncycastle_lts": "https://www.bouncycastle.org/resources/new-release-bouncy-castle-java-lts-2-73-8/",
}

# Filename patterns are deliberately limited to recognizable runtime library
# names. Broad substring matches would mistake unrelated files for libraries.
_FILE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "openssl",
        re.compile(
            r"^(?:libssl|libcrypto)\.so(?:\.\d+)*$|^(?:libssl|libcrypto)(?:-\d[^/]*)?\.dll$|^(?:libssl|libcrypto)(?:-[^/]*)?\.dylib$",
            re.I,
        ),
    ),
    (
        "gnutls",
        re.compile(
            r"^libgnutls\.so(?:\.\d+)*$|^libgnutls(?:-[^/]*)?\.dll$|^libgnutls\.dylib$",
            re.I,
        ),
    ),
    (
        "libgcrypt",
        re.compile(
            r"^libgcrypt\.so(?:\.\d+)*$|^libgcrypt(?:-[^/]*)?\.dll$|^libgcrypt\.dylib$",
            re.I,
        ),
    ),
    (
        "nss",
        re.compile(
            r"^(?:libnss3\.so(?:\.\d+)*|libnss3\.dylib|libnss3\.dll|nss3\.dll)$", re.I
        ),
    ),
    (
        "bouncycastle",
        re.compile(r"^bcprov(?:-[A-Za-z0-9]+)*-[0-9][A-Za-z0-9.+_-]*\.jar$", re.I),
    ),
)
_BC_VERSION = re.compile(r"-(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?)\.jar$", re.I)
_VERSION_PREFIX = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?")


class RootFSScanError(ValueError):
    """Root filesystem input is invalid or violates the scan boundary."""


def _numeric_version(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    # Debian versions may have an epoch prefix, e.g. 2:3.0.11-1.
    value = value.rsplit(":", 1)[-1]
    match = _VERSION_PREFIX.match(value.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _filename_library(name: str) -> tuple[str, str | None, str]:
    """Return (canonical family, version from filename, release track)."""
    lower = name.lower()
    if lower.endswith(("-sources.jar", "-javadoc.jar", "-tests.jar")):
        return "", None, "regular"
    for family, pattern in _FILE_PATTERNS:
        if pattern.match(name):
            if family == "bouncycastle":
                match = _BC_VERSION.search(name)
                version = match.group(1) if match else None
                track = "lts" if lower.startswith("bcprov-lts") else "regular"
                return family, version, track
            # A SONAME such as libssl.so.3 is not the full upstream release.
            # Keep the version unknown unless package metadata resolves it.
            return family, None, "regular"
    return "", None, "regular"


def _package_library(name: str) -> tuple[str, str]:
    """Map a Debian/APK package name to a supported library family."""
    package = name.lower()
    if package in {"openssl", "openssl-libs"} or package.startswith(
        ("libssl", "libcrypto")
    ):
        return "openssl", "regular"
    if package == "gnutls" or package.startswith("libgnutls"):
        return "gnutls", "regular"
    if package == "libgcrypt" or package.startswith("libgcrypt"):
        return "libgcrypt", "regular"
    if package in {"nss", "nss-tools"} or package.startswith("libnss3"):
        return "nss", "regular"
    if package in {"libbcprov-java", "libbouncycastle-java"} or package.startswith(
        "bouncycastle"
    ):
        return "bouncycastle", "regular"
    return "", "regular"


def _capability(
    family: str, version: str | None, track: str = "regular"
) -> tuple[str, str, str]:
    """Return (yes/no/unknown, explanation, source URL(s))."""
    parsed = _numeric_version(version)
    sources = [_CAPABILITY_SOURCES[family]]
    if family == "bouncycastle" and track == "lts":
        sources = [_CAPABILITY_SOURCES_EXTRA["bouncycastle_lts"]]
    elif family in _CAPABILITY_SOURCES_EXTRA:
        sources.append(_CAPABILITY_SOURCES_EXTRA[family])
    source = ";".join(sources)
    if parsed is None:
        return (
            "unknown",
            "A complete upstream version could not be established from the available filename/package metadata.",
            source,
        )

    if family == "openssl":
        if parsed >= (3, 5, 0):
            return (
                "yes",
                "OpenSSL 3.5 and later include ML-KEM, ML-DSA, and SLH-DSA support; provider/build and application use remain unverified.",
                source,
            )
        return (
            "no",
            "The detected upstream version predates the OpenSSL 3.5 release that added standardized ML-KEM, ML-DSA, and SLH-DSA support; vendor backports are not assessed.",
            source,
        )

    if family == "gnutls":
        if parsed < (3, 8, 8):
            return (
                "no",
                "The detected upstream version predates GnuTLS 3.8.8's reported experimental ML-KEM hybrid TLS key-exchange support; downstream patches are not assessed.",
                source,
            )
        return (
            "unknown",
            "GnuTLS 3.8.8 and later have reported experimental hybrid ML-KEM support, but it is build-dependent (for example, liboqs/leancrypto) and this inventory cannot verify compile-time options.",
            source,
        )

    if family == "libgcrypt":
        if parsed < (1, 11, 0):
            return (
                "no",
                "The detected upstream version predates Libgcrypt 1.11.0's reported Kyber/ML-KEM-era KEM support; vendor backports are not assessed.",
                source,
            )
        if parsed < (1, 12, 0):
            return (
                "unknown",
                "Libgcrypt 1.11.x introduced a pre-final-standard Kyber implementation; compatibility with the final standardized algorithms cannot be inferred from this version alone.",
                source,
            )
        return (
            "yes",
            "Libgcrypt 1.12 and later document ML-KEM/KEM API support and ML-DSA support; build configuration and application use remain unverified.",
            source,
        )

    if family == "nss":
        if parsed >= (3, 128, 0):
            return (
                "yes",
                (
                    "NSS 3.128 release notes document ML-KEM and ML-DSA "
                    "implementation/test work; actual API exposure, build "
                    "configuration, and application use remain unverified."
                ),
                source,
            )
        return (
            "unknown",
            (
                "The available source baseline does not establish a safe "
                "negative PQC-capability conclusion for this older NSS version."
            ),
            source,
        )

    if family == "bouncycastle":
        if track == "lts":
            if parsed >= (2, 73, 8):
                return (
                    "yes",
                    "Bouncy Castle Java LTS 2.73.8 and later documents ML-KEM and ML-DSA support; provider selection and application use remain unverified.",
                    source,
                )
            return (
                "no",
                "The detected Bouncy Castle Java LTS version predates the documented 2.73.8 PQC-capability release; vendor modifications are not assessed.",
                source,
            )
        if parsed >= (1, 79, 0):
            return (
                "yes",
                "Bouncy Castle Java 1.79 and later documents standardized ML-KEM, ML-DSA, and SLH-DSA support; provider selection and application use remain unverified.",
                source,
            )
        return (
            "no",
            "The detected Bouncy Castle Java release predates the 1.79 release that documented support for standardized NIST PQC algorithms; vendor modifications are not assessed.",
            source,
        )

    return "unknown", "No capability rule is defined for this library family.", source


def _read_bounded_text(path: Path, max_bytes: int) -> str:
    """Read a regular metadata file without following a symlink or exceeding a cap."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("package metadata is not a regular file")
        if file_stat.st_size > max_bytes:
            raise OverflowError(f"package metadata larger than {max_bytes} bytes")
        chunks = bytearray()
        while len(chunks) <= max_bytes:
            chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > max_bytes:
            raise OverflowError(f"package metadata larger than {max_bytes} bytes")
        return bytes(chunks).decode("utf-8")
    finally:
        os.close(fd)


def _blocks(text: str):
    """Yield (starting line, [(line number, line text), ...]) for blank-line blocks."""
    block: list[tuple[int, str]] = []
    block_start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            if block:
                yield block_start, block
                block = []
            block_start = number + 1
            continue
        block.append((number, line))
    if block:
        yield block_start, block


def _parse_dpkg_status(text: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for _, block in _blocks(text):
        fields: dict[str, tuple[str, int]] = {}
        for number, line in block:
            if ":" not in line or line[:1].isspace():
                continue
            key, value = line.split(":", 1)
            fields[key] = (value.strip(), number)
        package = fields.get("Package", (None, None))[0]
        if not package:
            continue
        if fields.get("Status", ("", 0))[0] != "install ok installed":
            continue
        family, track = _package_library(package)
        if not family:
            continue
        version = fields.get("Version", (None, None))[0]
        line_no = fields.get("Package", (None, None))[1]
        packages.append(
            {
                "family": family,
                "version": version,
                "track": track,
                "package": package,
                "line": line_no,
                "excerpt": f"Package: {package}; Version: {version or 'unknown'}",
            }
        )
    return packages


def _parse_apk_database(text: str) -> list[dict[str, Any]]:
    packages: list[dict[str, Any]] = []
    for _, block in _blocks(text):
        fields: dict[str, tuple[str, int]] = {}
        for number, line in block:
            if len(line) >= 2 and line[1] == ":":
                fields[line[0]] = (line[2:].strip(), number)
        package = fields.get("P", (None, None))[0]
        if not package:
            continue
        family, track = _package_library(package)
        if not family:
            continue
        version = fields.get("V", (None, None))[0]
        line_no = fields.get("P", (None, None))[1]
        packages.append(
            {
                "family": family,
                "version": version,
                "track": track,
                "package": package,
                "line": line_no,
                "excerpt": f"Package: {package}; Version: {version or 'unknown'}",
            }
        )
    return packages


def _metadata_kind(relative_path: str) -> str | None:
    normalized = relative_path.strip("/")
    if normalized == DPKG_STATUS_PATH:
        return "dpkg"
    if normalized in APK_DATABASE_PATHS:
        return "apk"
    return None


def _record(
    path: str,
    stage: str,
    status: StageStatus = StageStatus.SUCCESS,
    reason: str | None = None,
) -> FileRecord:
    return FileRecord.from_stage_results(
        path,
        [FileStageResult(path=path, stage=stage, status=status, reason=reason)],
    )


def scan_rootfs(
    rootfs: str | Path,
    *,
    max_metadata_bytes: int = DEFAULT_MAX_METADATA_BYTES,
) -> tuple[list[CryptoFinding], CoverageReport]:
    """Inventory supported crypto libraries from an extracted root filesystem.

    Returns findings and a separate coverage report so a large root filesystem
    does not distort project-source coverage percentages. All inventory paths
    are normalized as ``rootfs/<relative-path>``. Symlinks are skipped, not
    followed, so links cannot escape the selected root.
    """
    supplied_root = Path(rootfs).expanduser()
    if supplied_root.is_symlink():
        raise RootFSScanError(
            "rootfs must be a real extracted directory, not a symlink"
        )
    if not supplied_root.exists():
        raise RootFSScanError(f"rootfs is not a directory: {supplied_root}")
    try:
        root = supplied_root.resolve(strict=True)
    except OSError as exc:
        raise RootFSScanError(f"cannot resolve rootfs directory: {exc}") from exc
    if not root.is_dir():
        raise RootFSScanError(f"rootfs is not a directory: {root}")
    if max_metadata_bytes < 1:
        raise ValueError("max_metadata_bytes must be greater than zero")

    records: list[FileRecord] = []
    raw_artifacts: list[dict[str, Any]] = []
    package_records: list[dict[str, Any]] = []

    def _record_walk_error(exc: OSError) -> None:
        """Include inaccessible directories in coverage instead of silently omitting them."""
        error_path = Path(exc.filename) if exc.filename else root
        try:
            relative = error_path.relative_to(root).as_posix()
        except ValueError:
            relative = "."
        reported_path = "rootfs" if relative == "." else f"rootfs/{relative}"
        reason = f"cannot traverse directory: {exc.strerror or type(exc).__name__}"
        records.append(
            _record(reported_path, "rootfs-inventory", StageStatus.FAILED, reason)
        )

    # Single top-down walk. Symlinked directories are pruned before descent;
    # /proc, /sys, and /dev at the root of the extracted tree are never walked.
    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, onerror=_record_walk_error, followlinks=False
    ):
        current = Path(dirpath)
        kept_dirs: list[str] = []
        for directory in sorted(dirnames):
            directory_path = current / directory
            relative = directory_path.relative_to(root).as_posix()
            record_path = f"rootfs/{relative}"
            if current == root and directory in EXCLUDED_ROOT_DIRS:
                records.append(
                    FileRecord.from_stage_results(
                        record_path,
                        [],
                        skip_reason="excluded virtual filesystem directory by policy",
                    )
                )
            elif directory_path.is_symlink():
                records.append(
                    FileRecord.from_stage_results(
                        record_path,
                        [],
                        skip_reason="symbolic-link directory not followed",
                    )
                )
            else:
                kept_dirs.append(directory)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            path = current / filename
            relative = path.relative_to(root).as_posix()
            record_path = f"rootfs/{relative}"
            if path.is_symlink():
                records.append(
                    FileRecord.from_stage_results(
                        record_path, [], skip_reason="symbolic link not followed"
                    )
                )
                continue
            try:
                file_stat = path.lstat()
            except OSError as exc:
                records.append(
                    _record(
                        record_path,
                        "rootfs-inventory",
                        StageStatus.FAILED,
                        f"cannot stat file: {exc.strerror or type(exc).__name__}",
                    )
                )
                continue
            if not stat.S_ISREG(file_stat.st_mode):
                records.append(
                    FileRecord.from_stage_results(
                        record_path,
                        [],
                        skip_reason="non-regular filesystem entry not read",
                    )
                )
                continue

            metadata_kind = _metadata_kind(relative)
            family, filename_version, track = _filename_library(path.name)
            if metadata_kind:
                try:
                    text = _read_bounded_text(path, max_metadata_bytes)
                    if metadata_kind == "dpkg":
                        parsed_packages = _parse_dpkg_status(text)
                    else:
                        parsed_packages = _parse_apk_database(text)
                    for item in parsed_packages:
                        item.update(
                            {"path": record_path, "metadata_kind": metadata_kind}
                        )
                    package_records.extend(parsed_packages)
                    records.append(_record(record_path, "rootfs-package-metadata"))
                except OverflowError as exc:
                    records.append(
                        FileRecord.from_stage_results(
                            record_path, [], skip_reason=str(exc)
                        )
                    )
                except (OSError, UnicodeDecodeError) as exc:
                    reason = f"cannot parse package metadata: {exc}"
                    records.append(
                        _record(
                            record_path,
                            "rootfs-package-metadata",
                            StageStatus.FAILED,
                            reason,
                        )
                    )
                continue

            records.append(_record(record_path, "rootfs-library-inventory"))
            if family:
                raw_artifacts.append(
                    {
                        "family": family,
                        "version": filename_version,
                        "track": track,
                        "path": record_path,
                        "filename": path.name,
                        "kind": "filename",
                        "version_source": "filename" if filename_version else "unknown",
                        "line": None,
                        "excerpt": f"Recognized cryptographic library filename: {path.name}",
                    }
                )

    # Package metadata may resolve the full release version for native SONAMEs
    # (for example, libssl.so.3). Apply it only when exactly one version exists
    # for that family; never guess when multiple installed versions are visible.
    versions_by_family: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for item in package_records:
        version = item.get("version")
        if version:
            versions_by_family[item["family"]].add(
                (version, item.get("track", "regular"))
            )
    for item in raw_artifacts:
        if item["version"] is None:
            versions = versions_by_family.get(item["family"], set())
            if len(versions) == 1:
                item["version"], item["track"] = next(iter(versions))
                item["version_source"] = "package-metadata-cross-reference"

    entries: list[dict[str, Any]] = list(raw_artifacts)
    for package in package_records:
        entries.append(
            {
                "family": package["family"],
                "version": package.get("version"),
                "track": package.get("track", "regular"),
                "path": package["path"],
                "filename": package.get("package", "package metadata"),
                "kind": "package-metadata",
                "version_source": "package-metadata",
                "line": package.get("line"),
                "excerpt": package.get("excerpt", "cryptographic package metadata"),
                "package": package.get("package", ""),
                "metadata_kind": package.get("metadata_kind", ""),
            }
        )

    grouped: dict[tuple[str, str | None, str], list[dict[str, Any]]] = defaultdict(list)
    for item in entries:
        grouped[
            (item["family"], item.get("version"), item.get("track", "regular"))
        ].append(item)

    findings: list[CryptoFinding] = []
    for (family, version, track), members in sorted(
        grouped.items(), key=lambda pair: (pair[0][0], pair[0][1] or "", pair[0][2])
    ):
        capability, explanation, sources = _capability(family, version, track)
        evidence: list[Evidence] = []
        seen: set[tuple[str, int | None, str]] = set()
        for item in sorted(
            members,
            key=lambda value: (value["path"], value.get("line") or 0, value["kind"]),
        ):
            dedupe = (item["path"], item.get("line"), item["kind"])
            if dedupe in seen:
                continue
            seen.add(dedupe)
            is_package = item["kind"] == "package-metadata"
            metadata = {
                "inventory_source": "rootfs",
                "library_name": family,
                "library_version": version or "unknown",
                "version_source": item.get("version_source", "not-resolved"),
                "pqc_capability": capability,
                "pqc_capability_reason": explanation,
                "pqc_capability_source": sources,
                "release_track": track,
            }
            if is_package:
                metadata["package_name"] = str(item.get("package") or "")
                metadata["package_metadata_format"] = str(
                    item.get("metadata_kind") or ""
                )
            evidence.append(
                Evidence(
                    file_path=item["path"],
                    line_start=item.get("line"),
                    evidence_type=(
                        EvidenceType.DEPENDENCY
                        if is_package
                        else EvidenceType.FILE_EXTENSION
                    ),
                    detection_method=(
                        DetectionMethod.MANIFEST
                        if is_package
                        else DetectionMethod.FILE_EXTENSION
                    ),
                    rule_id=(
                        "ROOTFS-PACKAGE-METADATA"
                        if is_package
                        else f"ROOTFS-{family.upper()}-FILENAME"
                    ),
                    excerpt=item["excerpt"],
                    confidence=Confidence.HIGH if is_package else Confidence.MEDIUM,
                    metadata=metadata,
                )
            )
        if not evidence:
            continue
        if family == "bouncycastle" and track == "lts":
            label = f"Bouncy Castle Java LTS {version or 'unknown version'}"
        else:
            label_map = {
                "openssl": "OpenSSL",
                "gnutls": "GnuTLS",
                "libgcrypt": "Libgcrypt",
                "nss": "NSS",
                "bouncycastle": "Bouncy Castle Java",
            }
            label = f"{label_map[family]} {version or 'unknown version'}"
        assumption = (
            "Version-level PQC support is indicated by the sourced capability table; this does not prove that the installed build, provider, policy, or application enables or uses PQC."
            if capability == "yes"
            else (
                "The detected upstream version is not known to provide the required standardized PQC capability; vendor backports and custom builds are not assessed."
                if capability == "no"
                else "Available version or build metadata is insufficient to determine PQC capability. Verify support in the deployed build before relying on it."
            )
        )
        findings.append(
            CryptoFinding(
                algorithm=f"library:{family}",
                variant=label,
                role=CryptoRole.UNDETERMINED,
                status=FindingStatus.POTENTIAL,
                evidence=evidence,
                assumptions=[assumption],
            )
        )

    records.sort(key=lambda item: item.path)
    return findings, CoverageReport.from_records(records)
