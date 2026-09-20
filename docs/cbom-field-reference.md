# QuantumShield — CBOM Field Reference (for `cbom_writer.py`)

**Source standards:** CycloneDX 1.6+ (official CBOM) + original IBM CBOM extension (now upstreamed).  
**Primary references:**  
- https://github.com/IBM/CBOM  
- https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf  
- CycloneDX schema (bom-1.6 / 1.7)

This document is the **authoritative mapping** that Person B’s `cbom_writer.py` must follow.  
All generated components that represent detected crypto **must** be of type `cryptographic-asset` (CycloneDX) / historically `crypto-asset` (IBM).

---

## Core Component Fields

| Field | What it means | Required? | Example value for QuantumShield scanner |
|---|---|---|---|
| `type` | Component type. Must be `"cryptographic-asset"` (CycloneDX 1.6+) | Yes | `"cryptographic-asset"` |
| `name` | Human-readable name of the asset | Yes | `"RSA-2048"`, `"AES-128-GCM"`, `"MD5"` |
| `bom-ref` | Unique identifier inside the BOM (used by dependencies) | Strongly recommended | `"crypto/algorithm/rsa-2048@<hash-or-uuid>"` |
| `cryptoProperties` | Container for all crypto-specific metadata | Yes | see below |

---

## `cryptoProperties` Object

| Field | What it means | Required? | Example |
|---|---|---|---|
| `assetType` | One of the four CBOM categories | Yes | `"algorithm"` (most common for our scanner) |
| `algorithmProperties` | Present when `assetType = "algorithm"` | Conditional | see next table |
| `certificateProperties` | Present when `assetType = "certificate"` | Conditional | (out of scope for v1 regex scanner) |
| `relatedCryptoMaterialProperties` | Present when `assetType = "related-crypto-material"` | Conditional | (keys, secrets — future) |
| `protocolProperties` | Present when `assetType = "protocol"` | Conditional | (TLS etc. — future) |
| `oid` | Object Identifier if known | Optional | `"1.2.840.113549.1.1.1"` (RSA) |
| `classicalSecurityLevel` | Classical bit strength | Optional | `128`, `256` |
| `nistQuantumSecurityLevel` | NIST PQC security category (0–6) | Optional | `0` for classical-only algos |

### `algorithmProperties` (when assetType = algorithm)

| Field | What it means | Example values |
|---|---|---|
| `primitive` | Cryptographic building block | `"signature"`, `"pke"`, `"blockcipher"` / `"ae"`, `"hash"`, `"key-agree"` |
| `variant` / `parameterSetIdentifier` | Specific instantiation | `"RSA-2048"`, `"AES-128-GCM"`, `"256"` |
| `mode` | Mode of operation (block ciphers) | `"gcm"`, `"cbc"`, `"ecb"` |
| `padding` | Padding scheme if relevant | `"oaep"`, `"pkcs1"`, `"none"` |
| `cryptoFunctions` | Operations observed or supported | `["encrypt", "decrypt"]`, `["sign", "verify"]`, `["digest"]` |
| `executionEnvironment` | Where it runs | `"software-plain-ram"` (default for source scan) |
| `implementationPlatform` | CPU / platform if known | `"x86_64"`, omit if unknown |
| `certificationLevel` | FIPS etc. | `["none"]` or omit |

**Recommended mapping for QuantumShield v1 detections:**

| Detected keyword / family | primitive | variant / parameterSetIdentifier | notes |
|---|---|---|---|
| RSA | `pke` or `signature` | `RSA-2048` (or detected key size) | Default to 2048 if size unknown |
| ECDSA | `signature` | `ECDSA` + curve if known | |
| DH / ECDH | `key-agree` | `DH` / `ECDH` | |
| AES | `ae` or `blockcipher` | `AES-128-GCM` / `AES-256` | Prefer mode if visible |
| MD5 | `hash` | `MD5` | Mark as weak |

---

## Detection Context & Evidence (Critical for scanner)

CycloneDX attaches location evidence under the component’s `evidence` object (preferred modern form).  
IBM CBOM originally used a dedicated `detectionContext` array; both styles are accepted by tooling, but **prefer the standard `evidence.occurrences`** form.

| Field path | What it means | Example |
|---|---|---|
| `evidence.occurrences[].location` | File path where the match occurred | `"src/auth.py"` |
| `evidence.occurrences[].line` | Line number (integer) | `42` |
| `evidence.occurrences[].additionalContext` | Optional snippet or keyword that triggered detection | `"RSA.generate"` or `"MessageDigest.getInstance(\"MD5\")"` |
| confidence (0.0–1.0) | How sure the detector is | `0.85` for pure regex, higher for AST |

**QuantumShield v1 rule:**  
- Always populate at least one occurrence with `location` + `line`.  
- Set confidence ≈ 0.7–0.9 for regex matches (lower if the match is only a string constant).

---

## Dependencies: `implements` vs `uses`

CBOM explicitly distinguishes two dependency semantics:

| dependencyType | Meaning | When to use |
|---|---|---|
| `implements` | A library / component **provides** the algorithm (i.e. the code that contains the implementation) | Scanning a crypto library itself |
| `uses` | Application code **calls / consumes** the algorithm | Scanning application source (our case) |

**QuantumShield scanner policy (locked):**  
Because we scan application / sample source code, **default every dependency edge from the scanned component to a crypto-asset to `uses`**.  
Do **not** emit `implements` unless the scanned file is clearly part of a crypto library implementation.

In CycloneDX 1.6+ the relationship is expressed via the top-level `dependencies` array (ref → dependsOn) plus optional richer semantics; for the PoC it is sufficient to list the crypto-assets and record the evidence locations. Full dependency graph enrichment can come later.

---

## Minimal Valid Component Skeleton (copy-paste for writer)

```json
{
  "type": "cryptographic-asset",
  "name": "RSA-2048",
  "bom-ref": "crypto/algorithm/rsa-2048@example",
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": {
      "primitive": "pke",
      "parameterSetIdentifier": "2048",
      "cryptoFunctions": ["keygen", "encrypt", "decrypt"]
    }
  },
  "evidence": {
    "occurrences": [
      {
        "location": "src/crypto_utils.py",
        "line": 17,
        "additionalContext": "RSA"
      }
    ]
  }
}
```

---

## Notes for Person B

1. Always set `bomFormat: "CycloneDX"` and `specVersion: "1.6"` (or `"1.7"`).
2. Put the scanned project itself under `metadata.component` (type `application` or `library`).
3. Every crypto finding becomes a separate component of type `cryptographic-asset`.
4. Prefer `evidence.occurrences` over any custom detectionContext field for maximum tool compatibility.
5. Confidence is optional but useful; start with a constant 0.8 for regex hits.
6. Do **not** invent OIDs; only include them when you have a reliable mapping.

This reference is intentionally concise. Expand only when the scanner starts emitting certificates, keys or protocols.
