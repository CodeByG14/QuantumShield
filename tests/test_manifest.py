from common.models import Confidence, FindingStatus
from discovery.manifest_scanner import scan_manifest


def libs(out):
    return {f.algorithm for f in out.findings}


def test_requirements_txt_detects_crypto_libraries_only():
    text = "# deps\nCryptography>=41.0\nrequests==2.31.0\npycryptodome ; python_version>'3'\n-r other.txt\n"
    out = scan_manifest(text, "requirements.txt", "requirements.txt")
    assert libs(out) == {"library:cryptography", "library:pycryptodome"}
    f = next(f for f in out.findings if f.algorithm == "library:cryptography")
    assert f.status == FindingStatus.POTENTIAL and f.confidence == Confidence.MEDIUM
    assert f.evidence[0].line_start == 2
    assert f.variant is None  # capability, not a claimed algorithm


def test_name_normalisation():
    out = scan_manifest("PyCryptodome_x==1\npy_crypto.dome\npyOpenSSL\n", "requirements.txt", "requirements.txt")
    assert libs(out) == {"library:pyopenssl"}


def test_pyproject_dependencies_groups_and_poetry():
    text = '''[project]
dependencies = ["cryptography>=41", "requests"]

[project.optional-dependencies]
ssh = ["paramiko"]

[dependency-groups]
dev = ["pytest", {include-group = "x"}, "ecdsa"]

[tool.poetry.dependencies]
pynacl = "^1.5"
'''
    out = scan_manifest(text, "pyproject.toml", "pyproject.toml")
    assert libs(out) == {
        "library:cryptography", "library:paramiko", "library:ecdsa", "library:pynacl",
    }
    crypto = next(f for f in out.findings if f.algorithm == "library:cryptography")
    assert crypto.evidence[0].line_start == 2


def test_same_library_declared_twice_is_one_finding_with_two_evidence():
    out = scan_manifest("cryptography>=1\ncryptography[ssh]>=2\n", "requirements.txt", "requirements.txt")
    (f,) = out.findings
    assert len(f.evidence) == 2


def test_invalid_toml_fails_visibly():
    out = scan_manifest("[project\nbroken", "pyproject.toml", "pyproject.toml")
    assert not out.ok and "invalid TOML" in out.reason


def test_manifest_without_crypto_libs_is_clean_success():
    out = scan_manifest("requests\nflask\n", "requirements.txt", "requirements.txt")
    assert out.ok and out.findings == []
