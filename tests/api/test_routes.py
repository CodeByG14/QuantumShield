from uuid import UUID

import pytest
from fastapi import HTTPException

from quantumshield.api.app import create_app


class FakeResult:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, results):
        self.results = iter(results)
        self.queries = []

    def execute(self, query, params):
        self.queries.append((query, params))
        return next(self.results)


class FakePool:
    def __init__(self, connection):
        self.connection_result = connection

    def connection(self):
        return self

    def __enter__(self):
        return self.connection_result

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def _delete_project_endpoint():
    app = create_app()
    return next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", None) == "/projects/{project_id}"
        and "DELETE" in getattr(route, "methods", set())
    )


def test_root_level_api_routes_are_present_without_version_prefix():
    schema = create_app().openapi()
    paths = set(schema["paths"])
    expected = {
        "/health",
        "/dashboard/summary",
        "/session",
        "/projects",
        "/projects/{project_id}",
        "/projects/{project_id}/scans",
        "/scan",
        "/scans/{scan_run_id}",
        "/scans/{scan_run_id}/assessment",
        "/assessments/{assessment_id}",
        "/assessments/{assessment_id}/findings",
        "/plan",
        "/plans/{plan_id}",
        "/compliance",
        "/compliance/{report_id}",
        "/diff",
        "/diffs/{diff_id}",
    }
    assert expected <= paths
    assert "delete" in schema["paths"]["/projects/{project_id}"]
    assert not any(path.startswith("/api/v1/") for path in paths)

    summary_response = (
        schema["paths"]["/dashboard/summary"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]["$ref"]
    )
    response_schema = schema["components"]["schemas"][summary_response.rsplit("/", 1)[-1]]
    assert {
        "project_count",
        "scan_count",
        "scans_by_status",
        "active_scan_count",
        "latest_assessment_count",
        "latest_assessment_risk_levels",
        "high_priority_risk_count",
    } <= set(response_schema["properties"])


def test_public_scan_schema_exposes_only_four_supported_input_kinds():
    schema = create_app().openapi()
    scan_operation = schema["paths"]["/scan"]["post"]
    body_ref = scan_operation["requestBody"]["content"]["multipart/form-data"]["schema"]["$ref"]
    name = body_ref.rsplit("/", 1)[-1]
    fields = schema["components"]["schemas"][name]["properties"]
    source_type = fields["source_type"]
    assert source_type["enum"] == ["github_repository", "zip_archive", "sbom", "cbom"]


def test_delete_project_removes_owned_project_when_it_has_no_active_scans():
    project_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    session_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    connection = FakeConnection(
        [
            FakeResult(row={"project_id": project_id}),
            FakeResult(row={"exists": False}),
            FakeResult(),
        ]
    )

    result = _delete_project_endpoint()(
        project_id,
        FakePool(connection),
        {"session_id": session_id},
    )

    assert result is None
    assert len(connection.queries) == 3
    assert "FOR UPDATE" in connection.queries[0][0]
    assert connection.queries[0][1] == (project_id, session_id)
    assert "status IN ('queued', 'running')" in connection.queries[1][0]
    assert "DELETE FROM projects" in connection.queries[2][0]
    assert connection.queries[2][1] == (project_id, session_id)


def test_delete_project_rejects_projects_with_active_scans():
    project_id = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    connection = FakeConnection(
        [
            FakeResult(row={"project_id": project_id}),
            FakeResult(row={"exists": True}),
        ]
    )

    with pytest.raises(HTTPException) as exc_info:
        _delete_project_endpoint()(
            project_id,
            FakePool(connection),
            {"session_id": UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")},
        )

    assert exc_info.value.status_code == 409
    assert len(connection.queries) == 2


def test_delete_project_does_not_remove_project_from_another_session():
    connection = FakeConnection([FakeResult()])

    with pytest.raises(HTTPException) as exc_info:
        _delete_project_endpoint()(
            UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            FakePool(connection),
            {"session_id": UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")},
        )

    assert exc_info.value.status_code == 404
    assert len(connection.queries) == 1
    assert "session_id = %s" in connection.queries[0][0]
