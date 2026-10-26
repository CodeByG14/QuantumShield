# Phase 6B — Extracted Root Filesystem Library Inventory

## Purpose and usage

Phase 6B inventories selected cryptographic libraries in a root filesystem that has already been extracted to a directory. It does not mount images, execute binaries, load libraries, scan a live machine, or perform network/runtime scanning.

```bash
quantumshield scan ./application-repository \
  --rootfs ./extracted-rootfs \
  --output assessment.json

quantumshield plan assessment.json --output migration_plan.json
```

`--rootfs` is optional for both `scan` and `assess`. If omitted, project scanning behaves as before. The root filesystem must be a real directory; a root path that is itself a symlink is rejected. Findings and evidence paths use the normalized `rootfs/<relative-path>` prefix.

## Library families detected

| Family | Filename examples | Version sources |
| --- | --- | --- |
| OpenSSL | `libssl.so.3`, `libcrypto.so.3`, Windows/macOS shared-library names | Shared-library names and supported package metadata |
| GnuTLS | `libgnutls.so.30` | Shared-library names and supported package metadata |
| Libgcrypt | `libgcrypt.so.20` | Shared-library names and supported package metadata |
| Mozilla Network Security Services (NSS) | `libnss3.so` | Shared-library names and supported package metadata |
| Bouncy Castle Java | `bcprov-jdk18on-1.79.jar`, `bcprov-lts8on-2.73.8.jar` | JAR filenames and supported package metadata |

The scanner reads version data from Debian package status metadata (`var/lib/dpkg/status`) and Alpine package metadata (`lib/apk/db/installed` or `var/lib/apk/db/installed`). Other package-manager formats, vendor backports, ELF metadata, and arbitrary binary/JAR contents are not parsed. A SONAME such as `libssl.so.3` is not treated as a complete upstream version. If package metadata cannot safely and unambiguously supply a full version, the version and resulting capability may remain `unknown`.

## PQC capability labels

Every library finding uses one of three labels in evidence metadata: `yes`, `no`, or `unknown`. The capability rules are version-based and intentionally conservative:

| Library | Rule | Source basis |
| --- | --- | --- |
| OpenSSL | `3.5.0+` → `yes`; earlier versions → `no` in the upstream built-in capability table | [OpenSSL 3.5 release announcement](https://openssl-library.org/post-2025-04-08-openssl-35-final-release/) documents ML-KEM, ML-DSA, and SLH-DSA support |
| GnuTLS | Earlier than `3.8.8` → `no` in this table; `3.8.8+` → `unknown` | [GnuTLS 3.8.8](https://lists.gnutls.org/pipermail/gnutls-help/2024-November/004865.html) reports experimental hybrid ML-KEM TLS key exchange; [3.8.9](https://lists.gnutls.org/pipermail/gnutls-help/2025-February/004875.html) describes further support. Build options such as liboqs/leancrypto affect availability, which cannot be inferred from a version string. |
| Libgcrypt | Earlier than `1.11.0` → `no`; `1.11.x` → `unknown`; `1.12.0+` → `yes` | [Libgcrypt 1.11.0](https://lists.gnupg.org/pipermail/gnupg-devel/2024-June/035585.html) included a Kyber implementation based on a draft standard; [1.12.0](https://lists.gnupg.org/pipermail/gnupg-announce/2026q1/000502.html) documents ML-DSA support and KEM API updates. |
| NSS | `3.128.0+` → `yes`; older or unresolved versions → `unknown` | [NSS 3.128 release notes](https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_128.html) document ML-KEM and ML-DSA implementation/test work. This is a conservative positive baseline, not a claim about the first supported version. |
| Bouncy Castle Java regular release | `1.79+` → `yes`; earlier versions → `no` in this table | [Bouncy Castle Java 1.79](https://www.bouncycastle.org/resources/latest-nist-pqc-standards-and-more-bouncy-castle-java-1-79/) documents standardized ML-KEM, ML-DSA, and SLH-DSA support. |
| Bouncy Castle Java LTS | `2.73.8+` → `yes`; earlier LTS versions → `no` in this table | [Bouncy Castle Java LTS 2.73.8](https://www.bouncycastle.org/resources/new-release-bouncy-castle-java-lts-2-73-8/) documents ML-KEM and ML-DSA support. |

A `no` label means the sourced upstream version rule did not identify the relevant built-in standardized support; custom builds, vendor patches/backports, optional providers, and downstream modifications are not checked. `yes` means an upstream release documents relevant PQC API capability, not that the deployed binary exposes it or that an application uses it. For build-dependent or insufficiently resolved cases, the result remains `unknown`.

Each finding records its version, capability label, explanation, source URL, artifact paths, and relevant package metadata in evidence. These are `potential` inventory findings, not confirmed application-use findings. The scanner does not infer which application loads a detected library.

## Safety and coverage

- The root-level `/proc`, `/sys`, and `/dev` directories inside the extracted filesystem are excluded.
- Symbolic links are not followed at all. This is stricter than merely checking whether a link appears to remain inside the root, and prevents traversal out of the selected filesystem.
- Shared libraries and JARs are inspected by filename only; their contents are not read or executed.
- Only recognized package-manager metadata files are read. Their UTF-8 content is bounded by the configured file-size limit; oversized files are skipped and unreadable or malformed metadata is counted as failed.
- `rootfs_coverage` is reported separately from project-source `coverage`, so a large filesystem does not distort source coverage. This percentage describes inventory traversal and supported metadata handling, not the completeness of all cryptographic discovery.

## Migration-plan integration

When rootfs findings are present in the assessment, the migration plan adds a version-specific library prerequisite to each cryptographic migration task:

- `yes`: verify that the application uses this deployed build and that its required providers, algorithms, and protocol settings are enabled.
- `no`: assess upgrading or replacing the library before integrating PQC APIs.
- `unknown`: verify capability in the deployed build before selecting target APIs/providers.

These prerequisites are environment-level because QuantumShield does not yet map source-code findings to a specific loaded runtime library. The planner intentionally does not claim that a particular application component uses any inventoried library. The rootfs library list and capability summary are also included in plan metadata.

## Limitations

This inventory is static and does not identify loaded shared objects, language runtime classpaths, dynamic module selection, vendor patch levels, provider activation, FIPS mode, effective TLS negotiation, or actual application use. The capability table is a sourced triage aid, not an attestation or compliance result. Confirm library versions and capabilities against the actual deployed package/build and application configuration before making migration decisions.
