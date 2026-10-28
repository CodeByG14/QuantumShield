from uuid import UUID

import pytest

from quantumshield.api.service import load_dashboard_summary


class FakeResult:
    def __init__(self, *, row=None, rows=None):
        self.row = row
        self.rows = rows or []

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, results):
        self.results = iter(results)
        self.queries = []

    def execute(self, query, params):
        self.queries.append((query, params))
        return next(self.results)


class FakePool:
    def __init__(self, connection):
        self._connection = connection

    def connection(self):
        return self

    def __enter__(self):
        return self._connection

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_dashboard_summary_aggregates_scan_status_and_latest_assessments_per_project():
    session_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    connection = FakeConnection(
        [
            FakeResult(row={"count": 3}),
            FakeResult(
                rows=[
                    {"status": "completed", "count": 3},
                    {"status": "queued", "count": 1},
                    {"status": "running", "count": 2},
                    {"status": "failed", "count": 4},
                    {"status": "cancelled", "count": 1},
                ]
            ),
            FakeResult(
                rows=[
                    {"summary_json": {"risk_levels": {"low": 4, "high": 2, "very-high": 1}}},
                    {"summary_json": {"risk_levels": {"critical": 1, "high": 1}}},
                ]
            ),
        ]
    )

    summary = load_dashboard_summary(FakePool(connection), session_id)

    assert summary == {
        "project_count": 3,
        "scan_count": 11,
        "scans_by_status": {
            "completed": 3,
            "queued": 1,
            "running": 2,
            "failed": 4,
            "cancelled": 1,
        },
        "active_scan_count": 3,
        "latest_assessment_count": 2,
        "latest_assessment_risk_levels": {
            "critical": 1,
            "high": 3,
            "low": 4,
            "very-high": 1,
        },
        "high_priority_risk_count": 5,
    }
    assert all(params == (session_id,) for _, params in connection.queries)
    assert "row_number()" in connection.queries[2][0]
    assert "PARTITION BY p.project_id" in connection.queries[2][0]
    assert "sr.status = 'completed'" in connection.queries[2][0]


def test_dashboard_summary_returns_zero_counts_for_empty_session():
    session_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    connection = FakeConnection(
        [
            FakeResult(row={"count": 0}),
            FakeResult(rows=[]),
            FakeResult(rows=[]),
        ]
    )

    summary = load_dashboard_summary(FakePool(connection), session_id)

    assert summary == {
        "project_count": 0,
        "scan_count": 0,
        "scans_by_status": {},
        "active_scan_count": 0,
        "latest_assessment_count": 0,
        "latest_assessment_risk_levels": {},
        "high_priority_risk_count": 0,
    }


def test_dashboard_summary_rejects_malformed_assessment_risk_counts():
    session_id = UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
    connection = FakeConnection(
        [
            FakeResult(row={"count": 1}),
            FakeResult(rows=[]),
            FakeResult(rows=[{"summary_json": {"risk_levels": {"critical": -1}}}]),
        ]
    )

    with pytest.raises(ValueError, match="invalid risk-level counts"):
        load_dashboard_summary(FakePool(connection), session_id)
