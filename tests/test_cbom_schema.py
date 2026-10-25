"""
Validate generated CBOMs against the official CycloneDX 1.6 JSON schema.

Skipped unless the three schema files are present in ./schemas (one-off download,
see README note). They are not vendored to keep the repository small.
"""

import json
from pathlib import Path

import pytest

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"
NEEDED = ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")

pytestmark = pytest.mark.skipif(
    not all((SCHEMAS / n).exists() for n in NEEDED),
    reason="CycloneDX schema files not downloaded to ./schemas",
)


def _validator():
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource

    registry = Registry()
    for name in NEEDED[1:]:
        doc = json.loads((SCHEMAS / name).read_text())
        resource = Resource.from_contents(doc)
        registry = registry.with_resource(name, resource)
        if "$id" in doc:
            registry = registry.with_resource(doc["$id"], resource)
    return Draft7Validator(json.loads((SCHEMAS / NEEDED[0]).read_text()), registry=registry)


def test_generated_cbom_is_schema_valid(sample_project):
    from quantumshield.discovery.cbom_writer import scan_result_to_cbom
    from quantumshield.discovery.pipeline import run_scan

    cbom = scan_result_to_cbom(run_scan(sample_project), "proj")
    errors = [f"{'/'.join(map(str, e.path))}: {e.message[:120]}" for e in _validator().iter_errors(cbom)]
    assert errors == []


def test_validator_really_rejects_the_week4_shape():
    """Guard: proves the check above would catch non-standard fields."""
    bad = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{
            "type": "cryptographic-asset", "name": "x",
            "evidence": {"occurrences": [{"location": "a.py", "confidence": 0.85}]},
        }],
    }
    assert list(_validator().iter_errors(bad))
