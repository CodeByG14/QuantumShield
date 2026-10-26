from validation.metrics import evaluate_findings, inspect_coverage, inspect_migration_plan, normalize_algorithm


def test_algorithm_normalization_only_removes_punctuation_and_case():
    assert normalize_algorithm("SHA-1") == "sha1"
    assert normalize_algorithm("sha1") == "sha1"
    assert normalize_algorithm("RSA-2048") == "rsa2048"
    assert normalize_algorithm("RSA") != normalize_algorithm("RSA-2048")


def test_evaluation_counts_true_false_positive_and_false_negative():
    cases = [
        {"path": "a.py", "expected_findings": [{"algorithm": "md5", "status": "potential"}, {"algorithm": "sha1"}]},
        {"path": "clean.py", "expected_findings": []},
    ]
    actual = [
        {"path": "a.py", "algorithm": "MD-5", "status": "potential"},
        {"path": "clean.py", "algorithm": "rsa", "status": "potential"},
    ]
    report = evaluate_findings(cases, actual)
    assert report["true_positives"] == 1
    assert report["false_positives"] == 1
    assert report["false_negatives"] == 1
    assert report["precision"] == 0.5
    assert report["recall"] == 0.5
    assert report["f1"] == 0.5


def test_inconclusive_findings_are_not_scored_as_false_positives():
    cases = [{"path": "unreadable.pem", "expected_findings": []}]
    actual = [{"path": "unreadable.pem", "algorithm": "unknown", "status": "unable_to_analyze", "inconclusive": True}]
    report = evaluate_findings(cases, actual)
    assert report["true_positives"] == 0
    assert report["false_positives"] == 0
    assert report["false_negatives"] == 0
    assert report["inconclusive_count"] == 1


def test_unlabelled_findings_are_reported_and_count_as_false_positives():
    cases = [{"path": "clean.py", "expected_findings": []}]
    actual = [{"path": "new-file.py", "algorithm": "rsa", "status": "potential"}]
    report = evaluate_findings(cases, actual)
    assert report["false_positives"] == 1
    assert len(report["unlabelled_findings"]) == 1


def test_empty_expected_and_actual_is_defined_but_not_a_accuracy_certificate():
    report = evaluate_findings([{"path": "clean.py", "expected_findings": []}], [])
    assert report["precision"] == 1.0
    assert report["recall"] == 1.0
    assert report["f1"] == 1.0
    assert report["metrics_meaningful"] is False


def test_coverage_reconciles_counts_and_requires_reasons_for_unanalyzed_files():
    assessment = {
        "coverage": {
            "files_discovered": 2,
            "files_analyzed": 1,
            "files_failed": 0,
            "files_unsupported": 1,
            "files_skipped": 0,
            "file_coverage_percent": 50.0,
            "files": [
                {"path": "clean.py", "outcome": "analyzed", "reason": None},
                {"path": "store.p12", "outcome": "unsupported", "reason": "unsupported container"},
            ],
        }
    }
    report = inspect_coverage(assessment)
    assert report["available"] is True
    assert report["issues"] == []


def test_coverage_flags_inconsistent_counters_and_missing_reason():
    assessment = {
        "coverage": {
            "files_discovered": 2,
            "files_analyzed": 1,
            "files_failed": 0,
            "files_unsupported": 0,
            "files_skipped": 0,
            "files": [{"path": "broken.pem", "outcome": "failed"}],
        }
    }
    report = inspect_coverage(assessment)
    assert any("do not reconcile" in issue for issue in report["issues"])
    assert any("has no explanation" in issue for issue in report["issues"])


def test_migration_plan_checks_task_counts_and_action_summary():
    plan = {
        "summary": {"by_action": {"migrate": 1, "review": 1}},
        "tasks": [
            {"task_id": "T-1", "action_type": "migrate"},
            {"task_id": "T-2", "action_type": "review"},
        ],
    }
    report = inspect_migration_plan(plan)
    assert report["valid"] is True
    assert report["task_count"] == 2
    assert report["summary_action_counts_consistent"] is True


def test_migration_plan_flags_action_summary_disagreement():
    plan = {
        "summary": {"by_action": {"migrate": 2}},
        "tasks": [{"task_id": "T-1", "action_type": "migrate"}],
    }
    report = inspect_migration_plan(plan)
    assert report["valid"] is False
    assert any("differs from task-derived counts" in issue for issue in report["issues"])


def test_variant_is_part_of_identity_when_ground_truth_specifies_it():
    cases = [{"path": "key.py", "expected_findings": [{"algorithm": "RSA", "variant": "RSA-2048", "status": "confirmed"}]}]
    actual = [{"path": "key.py", "algorithm": "RSA", "variant": "RSA-4096", "status": "confirmed"}]
    report = evaluate_findings(cases, actual)
    assert report["true_positives"] == 0
    assert report["false_positives"] == 1
    assert report["false_negatives"] == 1


def test_coverage_checks_project_and_rootfs_sections_separately():
    assessment = {
        "coverage": {
            "files_discovered": 1, "files_analyzed": 1, "files_failed": 0,
            "files_unsupported": 0, "files_skipped": 0,
            "files": [{"path": "app.py", "outcome": "analyzed"}],
        },
        "rootfs_coverage": {
            "files_discovered": 1, "files_analyzed": 0, "files_failed": 1,
            "files_unsupported": 0, "files_skipped": 0,
            "files": [{"path": "rootfs/broken", "outcome": "failed", "reason": "permission denied"}],
        },
    }
    report = inspect_coverage(assessment)
    assert report["available"] is True
    assert len(report["sections"]) == 2
    assert report["issues"] == []
