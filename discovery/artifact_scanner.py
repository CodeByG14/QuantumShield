from pathlib import Path

from common.models import CryptoFinding, DetectionMethod

CERT_KEY_EXTENSIONS = {".pem", ".crt", ".cer", ".key", ".der", ".p12", ".pfx", ".jks"}


def scan_artifacts(target_dir: str) -> list[CryptoFinding]:
    findings = []
    target = Path(target_dir)

    for filepath in target.rglob("*"):
        if filepath.is_file() and filepath.suffix.lower() in CERT_KEY_EXTENSIONS:
            findings.append(
                CryptoFinding(
                    algorithm="unknown",
                    variant=None,
                    purpose=None,
                    file=str(filepath),
                    line=None,
                    evidence=f"{filepath.name} matched known cert/key extension ({filepath.suffix})",
                    detection_method=DetectionMethod.FILE_EXTENSION,
                    confidence=0.5,
                    source="artifact_scanner.py",
                )
            )

    return findings


if __name__ == "__main__":
    results = scan_artifacts("samples/test-repo")
    for r in results:
        print(r.model_dump())
