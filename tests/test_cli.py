from argparse import Namespace
import json

import pytest

from quantumshield.__main__ import _parse_endpoint, benchmark_command


def test_parse_endpoint_host_port():
    assert _parse_endpoint("example.com:443") == ("example.com", 443)


def test_parse_endpoint_ipv6():
    assert _parse_endpoint("[::1]:8443") == ("::1", 8443)


@pytest.mark.parametrize("value", ["example.com", "example.com:0", "example.com:65536", "[::1]443", "host:nope"])
def test_parse_endpoint_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        _parse_endpoint(value)


def test_benchmark_cli_writes_explicit_fake_backend_notice(tmp_path):
    output = tmp_path / "benchmark.json"
    args = Namespace(backend="fake", iterations=1, warmup=0, include_tls=False, output=str(output))
    assert benchmark_command(args) == 0
    data = json.loads(output.read_text())
    assert data["backend"]["name"] == "fake"
    assert data["backend"]["simulated"] is True
    assert "SIMULATED TEST DATA" in data["notice"]
    assert data["results"]
