import json

from discovery.cbom_writer import scan_result_to_cbom, write_cbom
from discovery.pipeline import run_scan


def cbom_for(project):
    return scan_result_to_cbom(run_scan(project), "proj")


def by_finding(cbom):
    return {
        next(
            p["value"]
            for p in c["properties"]
            if p["name"] == "quantumshield:finding-id"
        ): c
        for c in cbom["components"]
    }


def prop(component, name):
    return [
        p["value"]
        for p in component["properties"]
        if p["name"] == f"quantumshield:{name}"
    ]


def test_one_component_per_finding_with_unique_refs(sample_project):
    res = run_scan(sample_project)
    cbom = scan_result_to_cbom(res, "proj")
    assert len(cbom["components"]) == len(res.findings)
    refs = [c["bom-ref"] for c in cbom["components"]]
    assert len(refs) == len(set(refs))


def test_component_kinds(sample_project):
    comps = by_finding(cbom_for(sample_project)).values()
    kinds = {(c["type"], c.get("cryptoProperties", {}).get("assetType")) for c in comps}
    assert ("library", None) in kinds  # dependency, not a fake crypto asset
    assert ("cryptographic-asset", "algorithm") in kinds
    assert ("cryptographic-asset", "certificate") in kinds
    assert (
        "cryptographic-asset",
        "related-crypto-material",
    ) in kinds  # unreadable / unparsed


def test_certificate_component_carries_certificate_fields(sample_project):
    cert = next(
        c
        for c in cbom_for(sample_project)["components"]
        if c.get("cryptoProperties", {}).get("assetType") == "certificate"
    )
    props = cert["cryptoProperties"]["certificateProperties"]
    assert (
        props["subjectName"] == "CN=test.local"
        and props["certificateFormat"] == "X.509"
    )
    assert "notValidAfter" in props


def test_algorithm_component_fields(sample_project):
    rsa = next(
        c
        for c in cbom_for(sample_project)["components"]
        if c["type"] == "cryptographic-asset"
        and c["name"] == "RSA-2048"
        and "app.py" in json.dumps(c["evidence"])
    )
    algo = rsa["cryptoProperties"]["algorithmProperties"]
    assert algo["parameterSetIdentifier"] == "2048"
    assert prop(rsa, "status") == ["confirmed"] and prop(rsa, "confidence") == ["high"]
    assert prop(rsa, "rules") == ["PY-RSA-002"]
    assert rsa["evidence"]["occurrences"][0] == {
        "location": "app.py",
        "line": 2,
        "additionalContext": "RSA.generate(2048)",
    }


def test_non_standard_data_lives_in_properties_only(sample_project):
    """Confidence/status must never be placed inside standard objects (the Week 4 mistake)."""
    for c in cbom_for(sample_project)["components"]:
        for occ in c.get("evidence", {}).get("occurrences", []):
            assert set(occ) <= {
                "location",
                "line",
                "offset",
                "symbol",
                "additionalContext",
                "bom-ref",
            }
        assert set(c.get("evidence", {})) <= {"occurrences"}


def test_unable_to_analyze_is_visible_with_its_reason(sample_project):
    comps = cbom_for(sample_project)["components"]
    gaps = [prop(c, "evidence-gap") for c in comps if prop(c, "evidence-gap")]
    assert any("passphrase" in g[0] for g in gaps) and any(
        "empty" in g[0] for g in gaps
    )
    assert all(
        prop(c, "status") == ["unable-to-analyze"]
        for c in comps
        if prop(c, "evidence-gap")
    )


def test_assumptions_are_exported(sample_project):
    cert = next(
        c
        for c in cbom_for(sample_project)["components"]
        if c.get("cryptoProperties", {}).get("assetType") == "certificate"
    )
    assert (
        prop(cert, "assumption") == []
    )  # server.pem declares keyUsage in this fixture


def test_coverage_is_in_metadata(sample_project):
    meta = {
        p["name"]: p["value"]
        for p in cbom_for(sample_project)["metadata"]["properties"]
    }
    assert meta["quantumshield:files-discovered"] == "10"
    assert meta["quantumshield:files-failed"] == "3"
    assert meta["quantumshield:file-coverage-percent"] == "40.0"


def test_write_cbom_round_trips(sample_project, tmp_path):
    out = tmp_path / "cbom.json"
    written = write_cbom(run_scan(sample_project), "proj", out)
    assert json.loads(out.read_text()) == written


def test_curve_parameter_component_keeps_ec_as_algorithm_and_curve_as_parameter(
    tmp_path,
):
    source = tmp_path / "CurveConfig.java"
    source.write_text('new ECGenParameterSpec("secp256r1");\n', encoding="utf-8")
    cbom = scan_result_to_cbom(run_scan(tmp_path), "proj")
    component = next(
        c
        for c in cbom["components"]
        if any("JV-EC-002" in rule_ids.split(",") for rule_ids in prop(c, "rules"))
    )
    assert component["name"] == "EC"
    assert component["cryptoProperties"]["algorithmProperties"]["curve"] == "P-256"
    assert prop(component, "role") == ["undetermined"]
    assert prop(component, "status") == ["potential"]
    assert prop(component, "confidence") == ["low"]
