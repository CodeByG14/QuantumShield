from quantumshield.api.app import create_app


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
