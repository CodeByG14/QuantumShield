"""QuantumShield CLI entry point."""

import argparse
import sys
from pathlib import Path


def _parse_endpoint(value: str) -> tuple[str, int]:
    """Parse host:port, accepting bracketed IPv6 literals."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("endpoint must be a non-empty host:port value")
    value = value.strip()
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
            raise ValueError("IPv6 endpoints must use [address]:port syntax")
        host, port_text = value[1:closing], value[closing + 2:]
    else:
        if ":" not in value:
            raise ValueError("endpoint must use host:port syntax")
        host, port_text = value.rsplit(":", 1)
    if not host:
        raise ValueError("endpoint host must not be empty")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("endpoint port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port must be between 1 and 65535")
    return host, port


def scan_command(args: argparse.Namespace) -> int:
    """Scan a project for cryptographic findings."""
    from quantumshield.discovery.pipeline import run_scan
    from quantumshield.scoring.assessment_writer import write_assessment, build_assessment, load_project_context
    from datetime import datetime, timezone

    target = Path(args.target) if args.target else Path.cwd()
    if not target.is_dir():
        print(f"Error: target is not a directory: {target}", file=sys.stderr)
        return 1

    rootfs = Path(args.rootfs) if getattr(args, "rootfs", None) else None
    if rootfs is not None and not rootfs.is_dir():
        print(f"Error: --rootfs is not a directory: {rootfs}", file=sys.stderr)
        return 1
    if rootfs is not None and rootfs.resolve() == target.resolve():
        print("Error: --rootfs must refer to a separately extracted filesystem directory, not the project target itself", file=sys.stderr)
        return 1

    context, context_loaded = load_project_context(args.context, target_name=target.name)

    # Parse TLS endpoints from host:port strings to (host, port) tuples
    tls_endpoints = None
    if args.tls:
        tls_endpoints = []
        for ep in args.tls:
            try:
                tls_endpoints.append(_parse_endpoint(ep))
            except ValueError as exc:
                print(f"Error: invalid TLS endpoint {ep!r}: {exc}", file=sys.stderr)
                return 1

    try:
        scan_result = run_scan(target, tls_endpoints=tls_endpoints, rootfs=rootfs)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    report = build_assessment(
        scan_result,
        target=target,
        context=context,
        context_loaded=context_loaded,
        assessment_id=args.assessment_id,
        scan_timestamp=datetime.now(timezone.utc),
        assessment_year=args.assessment_year,
    )

    write_assessment(report, args.output)
    return 0


def assess_command(args: argparse.Namespace) -> int:
    """Assess risk from a scan (alias for scan with assessment output)."""
    return scan_command(args)


def plan_command(args: argparse.Namespace) -> int:
    """Generate migration plan from assessment."""
    from quantumshield.scoring.migration_plan_writer import write_migration_plan, build_migration_plan
    import json

    with open(args.assessment) as f:
        assessment_data = json.load(f)

    from quantumshield.common.models import AssessmentResult
    assessment = AssessmentResult.model_validate(assessment_data)

    plan = build_migration_plan(assessment)

    write_migration_plan(plan, args.output)
    return 0


def tls_command(args: argparse.Namespace) -> int:
    """Scan TLS endpoints."""
    from quantumshield.discovery.tls_scanner import scan_tls_endpoint, scan_tls_endpoints
    import json

    if args.endpoints:
        endpoints = []
        for ep in args.endpoints:
            try:
                endpoints.append(_parse_endpoint(ep))
            except ValueError as exc:
                print(f"Error: invalid TLS endpoint {ep!r}: {exc}", file=sys.stderr)
                return 1
        if args.timeout <= 0:
            print("Error: --timeout must be greater than zero", file=sys.stderr)
            return 1
        results = scan_tls_endpoints(endpoints, timeout=args.timeout, verify_cert=args.verify_cert)
    else:
        print("Error: --endpoints required", file=sys.stderr)
        return 1

    output = {
        "results": [
            {
                "host": r.host,
                "port": r.port,
                "connected": r.connected,
                "handshake_successful": r.handshake_successful,
                "tls_version": r.tls_version,
                "cipher_suite": r.cipher_suite,
                "key_exchange_group": r.key_exchange_group,
                "key_exchange_group_source": r.key_exchange_group_source,
                "certificate_verified": r.certificate_verified,
                "verification_bypassed": r.verification_bypassed,
                "error_message": r.error_message,
                "findings": [f.model_dump(mode="json") for f in r.findings],
            }
            for r in results
        ]
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
    else:
        print(json.dumps(output, indent=2))
    return 0


def diff_command(args: argparse.Namespace) -> int:
    """Diff two assessments."""
    from quantumshield.monitor.diff import diff_assessments
    import json

    with open(args.baseline) as f:
        baseline = json.load(f)
    with open(args.current) as f:
        current = json.load(f)

    from quantumshield.common.models import AssessmentResult
    baseline_assessment = AssessmentResult.model_validate(baseline)
    current_assessment = AssessmentResult.model_validate(current)

    diff = diff_assessments(baseline_assessment, current_assessment)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(diff.model_dump(mode="json"), f, indent=2)
    else:
        print(json.dumps(diff.model_dump(mode="json"), indent=2))
    return 0


def compliance_command(args: argparse.Namespace) -> int:
    """Evaluate findings against sourced NIST IR 8547 and CNSA 2.0 rules."""
    import json
    from quantumshield.compliance.checker import ComplianceAssessmentError, check_compliance
    from quantumshield.compliance.report import write_reports
    from quantumshield.compliance.rules import ComplianceRulesError

    try:
        with open(args.assessment, encoding="utf-8") as handle:
            assessment_data = json.load(handle)
        plan_data = None
        if args.plan:
            with open(args.plan, encoding="utf-8") as handle:
                plan_data = json.load(handle)
        elif Path("migration_plan.json").is_file():
            with open("migration_plan.json", encoding="utf-8") as handle:
                plan_data = json.load(handle)

        report = check_compliance(
            assessment_data,
            migration_plan=plan_data,
            as_of=args.as_of,
            rules_path=args.rules,
        )
        json_path, markdown_path = write_reports(report, args.output, args.markdown_output)
        print(
            f"Compliance assessment: {report['summary']['findings']} findings, "
            f"{report['summary']['results']} rule results"
        )
        print(f"Wrote {json_path} and {markdown_path}")
        return 0
    except (OSError, json.JSONDecodeError, ValueError, ComplianceAssessmentError, ComplianceRulesError) as exc:
        print(f"Compliance error: {exc}", file=sys.stderr)
        return 2


def benchmark_command(args: argparse.Namespace) -> int:
    """Run reproducible PQC benchmarks using an explicitly selected backend."""
    import json
    from quantumshield.transition.backend import BackendUnavailableError, get_backend
    from quantumshield.transition.benchmark import run_benchmarks

    try:
        backend = get_backend(prefer=args.backend if args.backend != "auto" else None)
    except BackendUnavailableError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    results = run_benchmarks(
        backend=backend,
        iterations=args.iterations,
        warmup=args.warmup,
        include_tls=args.include_tls,
    )
    payload = results.to_json()
    payload["backend"] = {
        "name": backend.name,
        "version": backend.get_version(),
        "simulated": backend.name == "fake",
    }
    if backend.name == "fake":
        payload["notice"] = "SIMULATED TEST DATA: not a real cryptographic performance measurement."

    rendered = json.dumps(payload, indent=2, allow_nan=False)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="quantumshield",
        description="Post-quantum cryptography migration framework",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan project for crypto findings")
    scan_parser.add_argument("target", nargs="?", default=".", help="Project directory to scan")
    scan_parser.add_argument("--context", default="project-context.yaml", help="Project context YAML")
    scan_parser.add_argument("-o", "--output", default="assessment.json", help="Output assessment file")
    scan_parser.add_argument("--assessment-id", help="Custom assessment ID")
    scan_parser.add_argument("--assessment-year", type=int, help="Assessment year for policy")
    scan_parser.add_argument("--tls", action="append", help="TLS endpoint to scan (host:port), repeatable")
    scan_parser.add_argument("--rootfs", help="Already-extracted root filesystem directory to inventory (never scans a live host)")
    scan_parser.set_defaults(func=scan_command)

    # assess command (alias)
    assess_parser = subparsers.add_parser("assess", help="Assess risk (same as scan)")
    assess_parser.add_argument("target", nargs="?", default=".", help="Project directory to scan")
    assess_parser.add_argument("--context", default="project-context.yaml", help="Project context YAML")
    assess_parser.add_argument("-o", "--output", default="assessment.json", help="Output assessment file")
    assess_parser.add_argument("--assessment-id", help="Custom assessment ID")
    assess_parser.add_argument("--assessment-year", type=int, help="Assessment year for policy")
    assess_parser.add_argument("--tls", action="append", help="TLS endpoint to scan (host:port), repeatable")
    assess_parser.add_argument("--rootfs", help="Already-extracted root filesystem directory to inventory (never scans a live host)")
    assess_parser.set_defaults(func=assess_command)

    # plan command
    plan_parser = subparsers.add_parser("plan", help="Generate migration plan from assessment")
    plan_parser.add_argument("assessment", help="Assessment JSON file")
    plan_parser.add_argument("-o", "--output", default="migration_plan.json", help="Output plan file")
    plan_parser.set_defaults(func=plan_command)

    # tls command
    tls_parser = subparsers.add_parser("tls", help="Scan TLS endpoints")
    tls_parser.add_argument("--endpoints", action="append", help="TLS endpoint (host:port), repeatable")
    tls_parser.add_argument("-o", "--output", help="Output JSON file")
    tls_parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout (seconds)")
    tls_parser.add_argument("--no-verify-cert", action="store_false", dest="verify_cert", default=True, help="Explicitly disable certificate verification (unsafe; inspection only)")
    tls_parser.set_defaults(func=tls_command)

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Diff two assessments")
    diff_parser.add_argument("baseline", help="Baseline assessment JSON")
    diff_parser.add_argument("current", help="Current assessment JSON")
    diff_parser.add_argument("-o", "--output", help="Output diff JSON")
    diff_parser.set_defaults(func=diff_command)

    # compliance command
    compliance_parser = subparsers.add_parser("compliance", help="Assess sourced NIST IR 8547 / CNSA 2.0 guidance")
    compliance_parser.add_argument("assessment", help="Assessment JSON file")
    compliance_parser.add_argument("-o", "--output", default="compliance_report.json", help="Output compliance JSON")
    compliance_parser.add_argument("--markdown-output", default="compliance_report.md", help="Output Markdown report")
    compliance_parser.add_argument("--plan", help="Migration plan JSON; defaults to migration_plan.json when present")
    compliance_parser.add_argument("--rules", help="Optional rules YAML path; defaults to packaged rules.yaml")
    compliance_parser.add_argument("--as-of", help="Evaluation date (YYYY-MM-DD), default today")
    compliance_parser.set_defaults(func=compliance_command)



    # benchmark command
    bench_parser = subparsers.add_parser("benchmark", help="Run PQC benchmarks")
    bench_parser.add_argument("-o", "--output", help="Output benchmark JSON")
    bench_parser.add_argument("--iterations", type=int, default=100, help="Benchmark iterations")
    bench_parser.add_argument("--warmup", type=int, default=10, help="Warmup iterations")
    bench_parser.add_argument("--backend", choices=["auto", "openssl", "oqs", "fake"], default="auto", help="Backend; fake results are simulated")
    bench_parser.add_argument("--include-tls", action="store_true", help="Include TLS handshake benchmarks when supported by the selected backend")
    bench_parser.set_defaults(func=benchmark_command)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())