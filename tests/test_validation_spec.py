from pathlib import Path

from validation.metrics import extract_actual_findings
from validation.run import _DEFAULT_SPEC, _check_corpus_labels, _check_rootfs_labels, _load_spec


def test_ground_truth_covers_every_source_and_rootfs_corpus_file():
    spec = _load_spec(_DEFAULT_SPEC)
    corpus = (_DEFAULT_SPEC.parent / spec["corpus"]["target"]).resolve()
    assert _check_corpus_labels(corpus, spec["cases"]) == []
    rootfs_value = spec["corpus"].get("rootfs")
    rootfs = (_DEFAULT_SPEC.parent / rootfs_value).resolve() if rootfs_value else None
    assert _check_rootfs_labels(rootfs, spec.get("rootfs_cases", [])) == []


def test_actual_finding_path_and_algorithm_are_stable_for_matching():
    assessment = {
        "findings": [
            {
                "finding_id": "CRYPTO-001",
                "algorithm": "MD-5",
                "status": "potential",
                "evidence": [
                    {"file_path": "a.py"},
                    {"file_path": "a.py"},
                ],
            }
        ]
    }
    actual = extract_actual_findings(assessment)
    assert len(actual) == 1
    assert actual[0]["path"] == "a.py"
    assert actual[0]["algorithm_key"] == "md5"
    assert actual[0]["status"] == "potential"


def test_absolute_evidence_path_is_normalized_to_project_relative(tmp_path: Path):
    source = tmp_path / "src" / "main.py"
    source.parent.mkdir()
    source.write_text("x = 1\n", encoding="utf-8")
    assessment = {
        "findings": [
            {
                "algorithm": "unknown",
                "status": "potential",
                "evidence": [{"file_path": str(source)}],
            }
        ]
    }
    actual = extract_actual_findings(assessment, project_root=tmp_path)
    assert actual[0]["path"] == "src/main.py"


def test_rootfs_cases_are_not_mistaken_for_project_files():
    spec = _load_spec(_DEFAULT_SPEC)
    assert all(not case["path"].startswith("rootfs/") for case in spec["cases"])
    assert all(case["path"].startswith("rootfs/") for case in spec.get("rootfs_cases", []))
