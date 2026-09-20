import re
import yaml
from pathlib import Path

def load_patterns(patterns_file="discovery/patterns.yaml"):
    with open(patterns_file) as f:
        return yaml.safe_load(f)["patterns"]

def scan_file(filepath, patterns):
    findings = []
    content = filepath.read_text(errors="ignore")
    for pattern in patterns:
        for match in re.finditer(pattern["regex"], content):
            line_num = content[:match.start()].count("\n") + 1
            matched_text = match.group(0)
            context_after = content[match.end():match.end()+5]
            confidence = 0.85 if "(" in matched_text or "(" in context_after else 0.70
            findings.append({
                "file": str(filepath),
                "line": line_num,
                "name": pattern["name"],
                "primitive": pattern["primitive"],
                "variant": pattern["variant"],
                "matched_text": matched_text,
                "confidence": confidence,
            })
    return findings

def scan_directory(target_dir, patterns):
    all_findings = []
    for ext in ("*.py", "*.java"):
        for filepath in Path(target_dir).rglob(ext):
            all_findings.extend(scan_file(filepath, patterns))
    return all_findings

if __name__ == "__main__":
    patterns = load_patterns()
    findings = scan_directory("samples/test-repo", patterns)
    for f in findings:
        print(f)
