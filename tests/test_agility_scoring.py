from quantumshield.agility.scoring import score_agility
from quantumshield.common.models import CryptoFinding, Evidence, EvidenceType, DetectionMethod, Confidence, FindingStatus


def finding(path, dynamic):
    evidence = Evidence(file_path=path, evidence_type=EvidenceType.DYNAMIC_SELECTION if dynamic else EvidenceType.API_CALL,
        detection_method=DetectionMethod.REGEX, rule_id="test", confidence=Confidence.MEDIUM,
        excerpt="test")
    return CryptoFinding(algorithm="unknown" if dynamic else "RSA", status=FindingStatus.POTENTIAL, evidence=[evidence])


def test_score_bounds_and_neutral_empty_case():
    assert score_agility([])["score"] == 50
    assert score_agility([finding("a.py", True)])["score"] == 100
    assert score_agility([finding("a.py", False)])["score"] == 0


def test_score_is_monotonic_as_dynamic_findings_increase():
    static = [finding("a.py", False)] * 3
    scores = [score_agility(static + [finding("b.py", True)] * n)["score"] for n in range(5)]
    assert scores == sorted(scores)


def test_per_asset_and_limitations_are_reported():
    report = score_agility([finding("src/a.py", True), finding("src/b.py", False)])
    assert report["per_asset"]["src/a.py"]["score"] == 100
    assert report["per_asset"]["src/b.py"]["score"] == 0
    assert report["limitations"]
