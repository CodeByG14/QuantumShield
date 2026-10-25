from quantumshield.discovery.rules import load_rules
from quantumshield.discovery.scanner import scan_source, LANGUAGE_BY_SUFFIX
from quantumshield.common.models import EvidenceType
from quantumshield.discovery.pipeline import DEFAULT_RULES


def test_python_dynamic_hash_and_env_selection_detected():
    source = "import hashlib, os\nname = os.getenv('CRYPTO_HASH')\ndigest = hashlib.new(name)\n"
    out = scan_source(source, "src/example.py", LANGUAGE_BY_SUFFIX[".py"], load_rules(DEFAULT_RULES))
    dynamic = [e for f in out.findings for e in f.evidence if e.evidence_type == EvidenceType.DYNAMIC_SELECTION]
    assert {e.rule_id for e in dynamic} >= {"dynamic-python-hashlib-new", "dynamic-env-algorithm"}


def test_java_getinstance_variable_detected_but_literal_not_marked_dynamic():
    source = 'Cipher c = Cipher.getInstance(transformation);\nCipher d = Cipher.getInstance("AES/GCM/NoPadding");\n'
    out = scan_source(source, "Example.java", LANGUAGE_BY_SUFFIX[".java"], load_rules(DEFAULT_RULES))
    dynamic = [e for f in out.findings for e in f.evidence if e.evidence_type == EvidenceType.DYNAMIC_SELECTION]
    assert len(dynamic) == 1
    assert dynamic[0].rule_id == "dynamic-java-getinstance"


def test_config_read_is_marked_dynamic_selection():
    source = "algorithm = config.get('hash_algorithm')\n"
    out = scan_source(source, "src/configured.py", LANGUAGE_BY_SUFFIX[".py"], load_rules(DEFAULT_RULES))
    assert any(e.evidence_type == EvidenceType.DYNAMIC_SELECTION and e.rule_id == "dynamic-config-algorithm"
               for f in out.findings for e in f.evidence)
