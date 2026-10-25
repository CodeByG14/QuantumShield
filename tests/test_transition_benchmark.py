"""Tests for quantumshield.transition.benchmark module."""

import pytest

from quantumshield.transition.benchmark import (
    BenchmarkEnvironment,
    BenchmarkResult,
    BenchmarkSuite,
    CLASSICAL_KEM_BASELINES,
    CLASSICAL_SIG_BASELINES,
    KEM_ALGORITHMS,
    SIG_ALGORITHMS,
    SLH_DSA_ALGORITHMS,
    compute_stats,
    measure_operation,
    round_trip_classical_kem,
    round_trip_classical_sig,
    round_trip_kem,
    round_trip_sig,
)
from quantumshield.transition.backend import FakeBackend


class TestBenchmarkHelpers:
    """Tests for benchmark helper functions."""

    def test_measure_operation_success(self):
        """Test measure_operation with successful function."""
        call_count = 0

        def test_func(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        latencies, result = measure_operation(test_func, 5, iterations=10, warmup=2)
        assert call_count == 12  # warmup + iterations
        assert result == 10
        assert len(latencies) == 10
        assert all(l >= 0 for l in latencies)

    def test_measure_operation_with_exception(self):
        """Test measure_operation handles exceptions."""
        def failing_func():
            raise ValueError("test error")

        latencies, result = measure_operation(failing_func, iterations=5, warmup=1)
        assert result is None
        assert len(latencies) == 5
        assert all(l == float("inf") for l in latencies)

    def test_compute_stats(self):
        """Test compute_stats with valid latencies."""
        latencies = [1.0, 2.0, 3.0, 4.0, 5.0]
        stats = compute_stats(latencies)
        assert stats["median"] == 3.0
        assert stats["min"] == 1.0
        assert stats["max"] == 5.0
        assert stats["mean"] == 3.0
        # p95 with n=5: int(5*0.95)=4 -> 5th element (index 4) = 5.0
        assert stats["p95"] == 5.0

    def test_compute_stats_empty(self):
        """Test compute_stats with all failed (inf) latencies."""
        latencies = [float("inf"), float("inf")]
        stats = compute_stats(latencies)
        # All should be inf when no valid measurements
        assert all(v == float("inf") for v in stats.values())

    def test_compute_stats_single(self):
        """Test compute_stats with single value."""
        latencies = [42.0]
        stats = compute_stats(latencies)
        assert stats["median"] == 42.0
        assert stats["p95"] == 42.0
        assert stats["min"] == 42.0
        assert stats["max"] == 42.0
        assert stats["mean"] == 42.0


class TestRoundTripValidation:
    """Tests for round-trip validation functions."""

    @pytest.fixture
    def backend(self):
        return FakeBackend()

    def test_round_trip_kem_all_algorithms(self, backend):
        """Test KEM round-trip for all supported algorithms."""
        for alg in KEM_ALGORITHMS:
            ok = round_trip_kem(backend, alg)
            assert ok is True, f"KEM round-trip failed for {alg}"

    def test_round_trip_sig_all_algorithms(self, backend):
        """Test signature round-trip for all supported algorithms."""
        for alg in SIG_ALGORITHMS + SLH_DSA_ALGORITHMS:
            verify_ok, tamper_ok = round_trip_sig(backend, alg)
            assert verify_ok is True, f"Sig verify failed for {alg}"
            assert tamper_ok is True, f"Sig tamper check failed for {alg}"

    def test_round_trip_classical_kem(self, backend):
        """Test classical KEM (DH) round-trip."""
        for alg in CLASSICAL_KEM_BASELINES:
            ok = round_trip_classical_kem(backend, alg)
            assert ok is True, f"Classical KEM round-trip failed for {alg}"

    def test_round_trip_classical_sig(self, backend):
        """Test classical signature round-trip."""
        for alg in CLASSICAL_SIG_BASELINES:
            verify_ok, tamper_ok = round_trip_classical_sig(backend, alg)
            assert verify_ok is True, f"Classical sig verify failed for {alg}"
            assert tamper_ok is True, f"Classical sig tamper check failed for {alg}"


class TestBenchmarkTypes:
    """Tests for benchmark data types."""

    def test_benchmark_environment(self):
        env = BenchmarkEnvironment(
            cpu_model="Test CPU",
            os="Test OS",
            python_version="3.12",
            openssl_version="OpenSSL 3.0",
            liboqs_version=None,
            iterations=100,
            warmup=10,
        )
        assert env.cpu_model == "Test CPU"
        assert env.iterations == 100

    def test_benchmark_result(self):
        result = BenchmarkResult(
            operation="keygen",
            algorithm="ML-KEM-512",
            iterations=10,
            median_ms=1.5,
            p95_ms=2.0,
            min_ms=1.0,
            max_ms=3.0,
            mean_ms=1.6,
            public_key_bytes=800,
            private_key_bytes=1600,
            ciphertext_bytes=768,
            shared_secret_bytes=32,
            signature_bytes=None,
            round_trip_ok=True,
            tamper_check_ok=None,
        )
        assert result.operation == "keygen"
        assert result.algorithm == "ML-KEM-512"
        assert result.round_trip_ok is True

    def test_benchmark_result_signature(self):
        result = BenchmarkResult(
            operation="sign",
            algorithm="ML-DSA-44",
            iterations=10,
            median_ms=1.5,
            p95_ms=2.0,
            min_ms=1.0,
            max_ms=3.0,
            mean_ms=1.6,
            public_key_bytes=1334,
            private_key_bytes=2626,
            ciphertext_bytes=None,
            shared_secret_bytes=None,
            signature_bytes=2420,
            round_trip_ok=True,
            tamper_check_ok=True,
        )
        assert result.tamper_check_ok is True

    def test_benchmark_suite(self):
        env = BenchmarkEnvironment(
            cpu_model="Test CPU",
            os="Test OS",
            python_version="3.12",
            openssl_version=None,
            liboqs_version=None,
            iterations=10,
            warmup=2,
        )
        suite = BenchmarkSuite(environment=env)
        assert suite.environment == env
        assert suite.results == []

    def test_benchmark_suite_to_json(self):
        env = BenchmarkEnvironment(
            cpu_model="Test CPU",
            os="Test OS",
            python_version="3.12",
            openssl_version=None,
            liboqs_version=None,
            iterations=10,
            warmup=2,
        )
        suite = BenchmarkSuite(environment=env)
        result = BenchmarkResult(
            operation="keygen",
            algorithm="ML-KEM-512",
            iterations=10,
            median_ms=1.5,
            p95_ms=2.0,
            min_ms=1.0,
            max_ms=3.0,
            mean_ms=1.6,
            public_key_bytes=800,
            private_key_bytes=1600,
            ciphertext_bytes=768,
            shared_secret_bytes=32,
            signature_bytes=None,
            round_trip_ok=True,
            tamper_check_ok=None,
        )
        suite.results.append(result)
        json_data = suite.to_json()
        assert json_data["environment"]["cpu_model"] == "Test CPU"
        assert len(json_data["results"]) == 1
        assert json_data["results"][0]["algorithm"] == "ML-KEM-512"


class TestAlgorithmLists:
    """Tests that algorithm lists are correct."""

    def test_kem_algorithms(self):
        assert KEM_ALGORITHMS == ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]

    def test_sig_algorithms(self):
        assert SIG_ALGORITHMS == ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

    def test_slh_dsa_algorithms(self):
        assert SLH_DSA_ALGORITHMS == ["SLH-DSA-SHA2-128s"]

    def test_classical_kem_baselines(self):
        assert CLASSICAL_KEM_BASELINES == ["X25519", "P-256"]

    def test_classical_sig_baselines(self):
        assert CLASSICAL_SIG_BASELINES == ["RSA-2048", "P-256", "Ed25519"]


class TestRunBenchmarks:
    """Integration tests for run_benchmarks function."""

    @pytest.fixture
    def backend(self):
        return FakeBackend()

    def test_run_benchmarks_fake_backend(self, backend):
        """Test run_benchmarks with FakeBackend."""
        from quantumshield.transition.benchmark import run_benchmarks

        results = run_benchmarks(backend=backend, iterations=3, warmup=1)
        assert isinstance(results, BenchmarkSuite)
        assert len(results.results) > 0

        # Check all KEM algorithms were tested
        kem_results = [r for r in results.results if r.algorithm in KEM_ALGORITHMS]
        assert len(kem_results) == 3 * 3  # 3 algs * 3 ops (keygen, encaps, decaps)

        # Check all SIG algorithms were tested
        sig_results = [r for r in results.results if r.algorithm in SIG_ALGORITHMS]
        assert len(sig_results) == 3 * 3  # 3 algs * 3 ops (keygen, sign, verify)

        # Check SLH-DSA
        slh_results = [r for r in results.results if r.algorithm in SLH_DSA_ALGORITHMS]
        assert len(slh_results) == 3  # 1 alg * 3 ops

        # Check classical
        # Note: P-256 appears in both CLASSICAL_KEM_BASELINES and CLASSICAL_SIG_BASELINES
        # So we get keygen for P-256 twice (once as KEM, once as SIG)
        classical_kem = [r for r in results.results if r.algorithm in CLASSICAL_KEM_BASELINES]
        classical_sig = [
            r for r in results.results
            if r.algorithm in CLASSICAL_SIG_BASELINES and r.operation in {"keygen", "sign", "verify"}
            and (r.algorithm != "P-256" or r.round_trip_ok is True)
        ]
        # KEM: X25519 (keygen, encaps), P-256 (keygen, encaps) = 4 + 3 keygen duplicates for P-256 in SIG = 7
        assert len(classical_kem) == 4 + 3  # 2 algs * 2 ops + P-256 keygen repeated from SIG
        assert len(classical_sig) >= 3 * 3  # signature operations are present; P-256 is also a KEM baseline
        for algorithm in CLASSICAL_SIG_BASELINES:
            operations = {r.operation for r in classical_sig if r.algorithm == algorithm}
            assert {"keygen", "sign", "verify"}.issubset(operations)

    def test_run_benchmarks_all_round_trips_ok(self, backend):
        """Test that all round-trip validations pass."""
        from quantumshield.transition.benchmark import run_benchmarks

        results = run_benchmarks(backend=backend, iterations=3, warmup=1)
        for r in results.results:
            assert r.round_trip_ok is True, f"Round-trip failed for {r.operation} {r.algorithm}"

    def test_run_benchmarks_environment_populated(self, backend):
        """Test that environment info is populated."""
        from quantumshield.transition.benchmark import run_benchmarks

        results = run_benchmarks(backend=backend, iterations=3, warmup=1)
        env = results.environment
        assert env.cpu_model is not None
        assert env.os is not None
        assert env.python_version is not None
        assert env.iterations == 3
        assert env.warmup == 1