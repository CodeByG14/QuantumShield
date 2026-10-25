"""Micro-benchmarks for PQC algorithms and TLS handshake benchmarks."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any

from quantumshield.transition.backend import (
    Backend,
    BackendUnavailableError,
    BenchmarkEnvironment,
    BenchmarkResult,
    BenchmarkSuite,
    FakeBackend,
    get_backend,
    list_available_backends,
)


# --------------------------------------------------------------------------
# Algorithm Lists
# --------------------------------------------------------------------------

KEM_ALGORITHMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
SIG_ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
# Use at least one SLH-DSA parameter set
SLH_DSA_ALGORITHMS = ["SLH-DSA-SHA2-128s"]
CLASSICAL_KEM_BASELINES = ["X25519", "P-256"]
CLASSICAL_SIG_BASELINES = ["RSA-2048", "P-256", "Ed25519"]


# --------------------------------------------------------------------------
# Benchmark Helpers
# --------------------------------------------------------------------------


def measure_operation(
    func,
    *args,
    iterations: int = 100,
    warmup: int = 10,
) -> tuple[list[float], Any]:
    """Measure operation latency over multiple iterations.

    Returns:
        Tuple of (latencies_ms, last_result)
    """
    # Warmup
    for _ in range(warmup):
        try:
            func(*args)
        except Exception:
            pass

    latencies = []
    last_result = None

    for _ in range(iterations):
        start = time.perf_counter()
        try:
            last_result = func(*args)
        except Exception:
            # Record failure as very high latency
            latencies.append(float("inf"))
            continue
        end = time.perf_counter()
        latencies.append((end - start) * 1000)  # Convert to ms

    return latencies, last_result


def compute_stats(latencies: list[float]) -> dict[str, float]:
    """Compute statistics from latencies."""
    valid = [l for l in latencies if l != float("inf")]
    if not valid:
        return {
            "median": float("inf"),
            "p95": float("inf"),
            "min": float("inf"),
            "max": float("inf"),
            "mean": float("inf"),
        }

    sorted_latencies = sorted(valid)
    n = len(sorted_latencies)

    return {
        "median": sorted_latencies[n // 2],
        "p95": sorted_latencies[int(n * 0.95)],
        "min": sorted_latencies[0],
        "max": sorted_latencies[-1],
        "mean": sum(sorted_latencies) / n,
    }


def round_trip_kem(backend: Backend, algorithm: str) -> bool:
    """Validate KEM round-trip: encaps/decaps produces same shared secret."""
    try:
        pub, priv = backend.kem_keygen(algorithm)
        ct, ss1 = backend.kem_encaps(algorithm, pub)
        ss2 = backend.kem_decaps(algorithm, priv, ct)
        return ss1 == ss2
    except Exception:
        return False


def round_trip_sig(backend: Backend, algorithm: str) -> tuple[bool, bool]:
    """Validate signature round-trip: sign/verify works, tampered fails."""
    try:
        pub, priv = backend.sig_keygen(algorithm)
        message = b"test message for signature verification"
        sig = backend.sig_sign(algorithm, priv, message)
        verify_ok = backend.sig_verify(algorithm, pub, message, sig)

        # Tamper check
        tampered = message + b"X"
        tamper_ok = not backend.sig_verify(algorithm, pub, tampered, sig)

        return verify_ok, tamper_ok
    except Exception:
        return False, False


def round_trip_classical_kem(backend: Backend, algorithm: str) -> bool:
    """Validate classical KEM (DH) round-trip."""
    try:
        if algorithm in ("X25519", "P-256"):
            # Need two keypairs for DH
            pub1, priv1 = backend.classical_keygen(algorithm)
            pub2, priv2 = backend.classical_keygen(algorithm)
            ss1 = backend.classical_dh(algorithm, priv1, pub2)
            ss2 = backend.classical_dh(algorithm, priv2, pub1)
            return ss1 == ss2
        return False
    except Exception:
        return False


def round_trip_classical_sig(backend: Backend, algorithm: str) -> tuple[bool, bool]:
    """Validate classical signature round-trip."""
    try:
        pub, priv = backend.classical_keygen(algorithm)
        message = b"test message for classical signature"
        sig = backend.classical_sign(algorithm, priv, message)
        verify_ok = backend.classical_verify(algorithm, pub, message, sig)

        tampered = message + b"X"
        tamper_ok = not backend.classical_verify(algorithm, pub, tampered, sig)

        return verify_ok, tamper_ok
    except Exception:
        return False, False


def get_algorithm_sizes(backend: Backend, algorithm: str, is_kem: bool) -> dict[str, int]:
    """Get actual key/ciphertext/signature sizes from backend."""
    sizes = {}

    try:
        if is_kem:
            pub, priv = backend.kem_keygen(algorithm)
            ct, ss = backend.kem_encaps(algorithm, pub)
            sizes["public_key_bytes"] = len(pub)
            sizes["private_key_bytes"] = len(priv)
            sizes["ciphertext_bytes"] = len(ct)
            sizes["shared_secret_bytes"] = len(ss)
        else:
            pub, priv = backend.sig_keygen(algorithm)
            message = b"test"
            sig = backend.sig_sign(algorithm, priv, message)
            sizes["public_key_bytes"] = len(pub)
            sizes["private_key_bytes"] = len(priv)
            sizes["signature_bytes"] = len(sig)
    except Exception:
        pass

    return sizes


def get_classical_sizes(backend: Backend, algorithm: str, is_kem: bool) -> dict[str, int]:
    """Get classical algorithm sizes."""
    sizes = {}

    try:
        if is_kem:
            pub, priv = backend.classical_keygen(algorithm)
            sizes["public_key_bytes"] = len(pub)
            sizes["private_key_bytes"] = len(priv)
        else:
            pub, priv = backend.classical_keygen(algorithm)
            message = b"test"
            sig = backend.classical_sign(algorithm, priv, message)
            sizes["public_key_bytes"] = len(pub)
            sizes["private_key_bytes"] = len(priv)
            sizes["signature_bytes"] = len(sig)
    except Exception:
        pass

    return sizes


# --------------------------------------------------------------------------
# Main Benchmark Function
# --------------------------------------------------------------------------


def run_benchmarks(
    backend: Backend,
    iterations: int = 100,
    warmup: int = 10,
    include_tls: bool = False,
) -> BenchmarkSuite:
    """Run full benchmark suite.

    Args:
        backend: Backend to use
        iterations: Number of iterations per operation
        warmup: Number of warmup iterations
        include_tls: Whether to run TLS handshake benchmarks (requires s_server)

    Returns:
        BenchmarkSuite with all results
    """
    # Environment info
    env = BenchmarkEnvironment(
        cpu_model=platform.processor() or "unknown",
        os=f"{platform.system()} {platform.release()}",
        python_version=platform.python_version(),
        openssl_version=backend.get_version() if backend.name == "openssl" else None,
        liboqs_version=backend.get_version() if backend.name == "oqs" else None,
        iterations=iterations,
        warmup=warmup,
    )

    suite = BenchmarkSuite(environment=env)

    # PQC KEM benchmarks
    for alg in KEM_ALGORITHMS:
        print(f"  Benchmarking {alg} KEM...", file=sys.stderr)

        # Keygen
        latencies, (pub, priv) = measure_operation(
            backend.kem_keygen, alg, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        sizes = get_algorithm_sizes(backend, alg, is_kem=True)
        round_trip = round_trip_kem(backend, alg)
        suite.results.append(BenchmarkResult(
            operation="keygen",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=round_trip,
        ))

        # Encaps
        latencies, (ct, ss) = measure_operation(
            backend.kem_encaps, alg, pub, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="encaps",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=round_trip,
        ))

        # Decaps
        latencies, ss2 = measure_operation(
            backend.kem_decaps, alg, priv, ct, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="decaps",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=round_trip,
        ))

    # PQC Signature benchmarks
    for alg in SIG_ALGORITHMS + SLH_DSA_ALGORITHMS:
        print(f"  Benchmarking {alg} SIG...", file=sys.stderr)

        # Keygen
        latencies, (pub, priv) = measure_operation(
            backend.sig_keygen, alg, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        sizes = get_algorithm_sizes(backend, alg, is_kem=False)
        verify_ok, tamper_ok = round_trip_sig(backend, alg)
        suite.results.append(BenchmarkResult(
            operation="keygen",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=verify_ok,
            tamper_check_ok=tamper_ok,
        ))

        # Sign
        latencies, sig = measure_operation(
            backend.sig_sign, alg, priv, b"test message for signing benchmark",
            iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="sign",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=verify_ok,
            tamper_check_ok=tamper_ok,
        ))

        # Verify
        latencies, verify_result = measure_operation(
            backend.sig_verify, alg, pub, b"test message for signing benchmark", sig,
            iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="verify",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=verify_ok,
            tamper_check_ok=tamper_ok,
        ))

    # Classical KEM baselines
    for alg in CLASSICAL_KEM_BASELINES:
        print(f"  Benchmarking {alg} (classical KEM)...", file=sys.stderr)

        # Keygen
        latencies, (pub, priv) = measure_operation(
            backend.classical_keygen, alg, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        sizes = get_classical_sizes(backend, alg, is_kem=True)
        round_trip = round_trip_classical_kem(backend, alg)
        suite.results.append(BenchmarkResult(
            operation="keygen",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=round_trip,
        ))

        # DH (encaps equivalent)
        # Need two keypairs
        pub2, priv2 = backend.classical_keygen(alg)
        latencies, ss = measure_operation(
            backend.classical_dh, alg, priv, pub2, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="encaps",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            shared_secret_bytes=len(ss) if ss else None,
            round_trip_ok=round_trip,
        ))

    # Classical Signature baselines
    for alg in CLASSICAL_SIG_BASELINES:
        print(f"  Benchmarking {alg} (classical SIG)...", file=sys.stderr)

        # Keygen
        latencies, (pub, priv) = measure_operation(
            backend.classical_keygen, alg, iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        sizes = get_classical_sizes(backend, alg, is_kem=False)
        verify_ok, tamper_ok = round_trip_classical_sig(backend, alg)
        suite.results.append(BenchmarkResult(
            operation="keygen",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=verify_ok,
            tamper_check_ok=tamper_ok,
        ))

        # Sign
        latencies, sig = measure_operation(
            backend.classical_sign, alg, priv, b"test message for classical signing",
            iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="sign",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=verify_ok,
            tamper_check_ok=tamper_ok,
        ))

        # Verify
        latencies, verify_result = measure_operation(
            backend.classical_verify, alg, pub, b"test message for classical signing", sig,
            iterations=iterations, warmup=warmup
        )
        stats = compute_stats(latencies)
        suite.results.append(BenchmarkResult(
            operation="verify",
            algorithm=alg,
            iterations=iterations,
            median_ms=stats["median"],
            p95_ms=stats["p95"],
            min_ms=stats["min"],
            max_ms=stats["max"],
            mean_ms=stats["mean"],
            **sizes,
            round_trip_ok=verify_ok,
            tamper_check_ok=tamper_ok,
        ))

    # TLS handshake benchmarks (Phase 3b)
    if include_tls and backend.name == "openssl":
        tls_groups = ["X25519", "X25519MLKEM768"]
        for group in tls_groups:
            print(f"  Benchmarking TLS 1.3 handshake with {group}...", file=sys.stderr)
            try:
                result = backend.tls_handshake_benchmark(group, iterations=30)
                # Add as a special benchmark result
                suite.results.append(BenchmarkResult(
                    operation="tls_handshake",
                    algorithm=group,
                    iterations=result.get("iterations", 30),
                    median_ms=result.get("median_ms", 0),
                    p95_ms=result.get("p95_ms", 0),
                    min_ms=result.get("min_ms", 0),
                    max_ms=result.get("max_ms", 0),
                    mean_ms=result.get("mean_ms", 0),
                ))
            except NotImplementedError:
                print(f"    TLS handshake benchmark not implemented for {backend.name}", file=sys.stderr)
            except Exception as e:
                print(f"    TLS handshake benchmark failed: {e}", file=sys.stderr)

    return suite


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="QuantumShield PQC Micro-benchmarks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m quantumshield.transition.benchmark --out benchmark_results.json
  python -m quantumshield.transition.benchmark --backend openssl --iterations 200
  python -m quantumshield.transition.benchmark --backend fake --out results.json
        """,
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "openssl", "oqs", "fake"],
        default="auto",
        help="Backend to use (default: auto-detect)",
    )
    parser.add_argument(
        "--out", "-o",
        default="benchmark_results.json",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=100,
        help="Iterations per operation (default: 100)",
    )
    parser.add_argument(
        "--warmup", "-w",
        type=int,
        default=10,
        help="Warmup iterations (default: 10)",
    )
    parser.add_argument(
        "--include-tls",
        action="store_true",
        help="Include TLS handshake benchmarks (requires OpenSSL >= 3.5 and running s_server)",
    )
    parser.add_argument(
        "--list-backends",
        action="store_true",
        help="List available backends and exit",
    )

    args = parser.parse_args(argv)

    if args.list_backends:
        backends = list_available_backends()
        print("Available backends:", ", ".join(backends) if backends else "none (fake always available)")
        return 0

    # Get backend
    try:
        if args.backend == "auto":
            backend = get_backend()
        else:
            backend = get_backend(prefer=args.backend)
    except BackendUnavailableError as e:
        print(f"Error: {e}", file=sys.stderr)
        print("Available backends:", ", ".join(list_available_backends()) or "none", file=sys.stderr)
        return 2

    print(f"Using backend: {backend.name} (version: {backend.get_version() or 'unknown'})", file=sys.stderr)
    print(f"Running benchmarks with {args.iterations} iterations ({args.warmup} warmup)...", file=sys.stderr)

    # Run benchmarks
    suite = run_benchmarks(backend, iterations=args.iterations, warmup=args.warmup, include_tls=args.include_tls)

    # Write output
    output_path = Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(suite.to_json(), f, indent=2)
        f.write("\n")

    print(f"Wrote {output_path} with {len(suite.results)} benchmark results", file=sys.stderr)

    # Print summary
    print("\nSummary:", file=sys.stderr)
    for result in suite.results:
        if result.operation in ("keygen", "encaps", "decaps", "sign", "verify"):
            rt = "✓" if result.round_trip_ok else "✗" if result.round_trip_ok is False else "?"
            tc = "✓" if result.tamper_check_ok else "✗" if result.tamper_check_ok is False else "?"
            print(f"  {result.algorithm} {result.operation:8s}: median={result.median_ms:.2f}ms p95={result.p95_ms:.2f}ms rt={rt} tc={tc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())