from pathlib import Path
import tomllib  # Python 3.11+; use `import tomli as tomllib` if on older Python

from common.models import CryptoFinding, DetectionMethod

KNOWN_CRYPTO_LIBS = {
    "pycryptodome": "Capable of RSA, AES, DES, ECDSA, hashing — specific algorithm usage not determined from manifest alone",
    "cryptography": "Capable of RSA, AES, ECDSA, ECDH, SHA-2 family — specific algorithm usage not determined from manifest alone",
    "pyca": "Capable of various crypto primitives via the pyca ecosystem — specific algorithm usage not determined from manifest alone",
    "pynacl": "Capable of NaCl/libsodium primitives (Ed25519, X25519, Salsa20) — specific algorithm usage not determined from manifest alone",
}


def parse_requirements_txt(filepath: Path) -> list[str]:
    packages = []
    for line in filepath.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # strip version specifiers: package==1.2.3, package>=1.0, etc.
        pkg_name = (
            line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
        )
        packages.append(pkg_name.lower())
    return packages


def parse_pyproject_toml(filepath: Path) -> list[str]:
    with open(filepath, "rb") as f:
        data = tomllib.load(f)
    deps = []
    # PEP 621 style
    deps.extend(data.get("project", {}).get("dependencies", []))
    # Poetry style
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    deps.extend(poetry_deps.keys())
    # normalize: strip version specifiers from PEP 621 strings like "cryptography>=41.0"
    cleaned = []
    for d in deps:
        name = (
            d.split("==")[0]
            .split(">=")[0]
            .split("<=")[0]
            .split("~=")[0]
            .split(" ")[0]
            .strip()
        )
        cleaned.append(name.lower())
    return cleaned


def scan_manifests(target_dir: str) -> list[CryptoFinding]:
    findings = []
    target = Path(target_dir)

    req_file = target / "requirements.txt"
    if req_file.exists():
        packages = parse_requirements_txt(req_file)
        for pkg in packages:
            if pkg in KNOWN_CRYPTO_LIBS:
                findings.append(
                    CryptoFinding(
                        algorithm="unknown",
                        variant=None,
                        purpose=None,
                        file=str(req_file),
                        line=None,
                        evidence=f"Dependency '{pkg}' declared — {KNOWN_CRYPTO_LIBS[pkg]}",
                        detection_method=DetectionMethod.MANIFEST,
                        confidence=0.5,
                        source="manifest_scanner.py",
                    )
                )

    pyproject_file = target / "pyproject.toml"
    if pyproject_file.exists():
        packages = parse_pyproject_toml(pyproject_file)
        for pkg in packages:
            if pkg in KNOWN_CRYPTO_LIBS:
                findings.append(
                    CryptoFinding(
                        algorithm="unknown",
                        variant=None,
                        purpose=None,
                        file=str(pyproject_file),
                        line=None,
                        evidence=f"Dependency '{pkg}' declared — {KNOWN_CRYPTO_LIBS[pkg]}",
                        detection_method=DetectionMethod.MANIFEST,
                        confidence=0.5,
                        source="manifest_scanner.py",
                    )
                )

    return findings


if __name__ == "__main__":
    results = scan_manifests("samples/test-repo")
    for r in results:
        print(r.model_dump())
