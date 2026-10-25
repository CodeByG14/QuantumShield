"""QuantumShield Transition Engine (PQC Lab).

Algorithm transition engine for post-quantum cryptography benchmarking
and validation. Provides backends for OpenSSL, liboqs, and testing.
"""

from quantumshield.transition.backend import (
    Backend,
    BackendUnavailableError,
    FakeBackend,
    OpenSSLBackend,
    OQSBackend,
    BenchmarkResult,
    BenchmarkEnvironment,
    BenchmarkSuite,
    get_backend,
    list_available_backends,
)
from quantumshield.transition.benchmark import (
    run_benchmarks,
    KEM_ALGORITHMS,
    SIG_ALGORITHMS,
    SLH_DSA_ALGORITHMS,
    CLASSICAL_KEM_BASELINES,
    CLASSICAL_SIG_BASELINES,
)

__all__ = [
    # Backend
    "Backend",
    "BackendUnavailableError",
    "FakeBackend",
    "OpenSSLBackend",
    "OQSBackend",
    "get_backend",
    "list_available_backends",
    # Benchmark types
    "BenchmarkResult",
    "BenchmarkEnvironment",
    "BenchmarkSuite",
    # Benchmark functions
    "run_benchmarks",
    # Algorithm lists
    "KEM_ALGORITHMS",
    "SIG_ALGORITHMS",
    "SLH_DSA_ALGORITHMS",
    "CLASSICAL_KEM_BASELINES",
    "CLASSICAL_SIG_BASELINES",
]

__version__ = "0.1.0"