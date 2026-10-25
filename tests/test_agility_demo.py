from quantumshield.agility.demo import run_demo

def test_demo_runs_and_demonstrates_rollback():
    result = run_demo()
    assert result["rollback"]["restored_previous_config"] is True
    assert result["hybrid_combiner"]["secret_material_emitted"] is False
    assert "DEMO ONLY" in result["notice"]


def test_assessment_accepts_configurable_agility_weights(tmp_path):
    from quantumshield.discovery.pipeline import run_scan
    from quantumshield.scoring.assessment_writer import build_assessment
    from quantumshield.common.models import ProjectContext
    from quantumshield.agility.config import get_default_config
    scan = run_scan("samples/test-repo")
    config = get_default_config()
    defaults = dict(config.defaults)
    defaults["agility_scoring"] = {"configurable_weight": 3.0, "static_weight": 1.0}
    from dataclasses import replace
    config = replace(config, defaults=defaults)
    report = build_assessment(scan, target="samples/test-repo", context=ProjectContext(project_name="test"), agility_config=config)
    assert report.agility["weights"] == {"configurable": 3.0, "static": 1.0}
