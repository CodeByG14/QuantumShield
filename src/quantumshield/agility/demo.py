"""Runnable demonstration of config switching, hybrid combining, fallback, and rollback.

Run: python -m quantumshield.agility.demo [path/to/agility.yaml]
This demonstrates policy decisions only; it is not a production protocol.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from quantumshield.agility.config import load_config, get_default_config
from quantumshield.agility.hybrid import combine_two_secrets
from quantumshield.agility.rollback import RollbackManager


def run_demo(config_path: str | Path | None = None) -> dict:
    config = load_config(config_path) if config_path else get_default_config()
    purposes = config.purposes
    purpose_name = next(iter(purposes), None)
    if purpose_name is None: raise ValueError("demo config has no purposes")
    purpose = purposes[purpose_name]
    first = {"purpose": purpose_name, "algorithm": purpose.algorithm, "source": "configured-primary"}
    selected = purpose.fallback[0] if purpose.fallback else purpose.algorithm
    fallback = {"purpose": purpose_name, "algorithm": selected, "source": "configured-fallback-demo"}
    hybrid = combine_two_secrets(b"classical-demo-secret", b"pqc-demo-secret", b"quantumshield-demo-v1")
    manager = RollbackManager({"purpose": purpose_name, "algorithm": purpose.algorithm})
    before = manager.active_config
    manager.switch({"purpose": purpose_name, "algorithm": selected})
    switched = manager.active_config
    manager.rollback()
    restored = manager.active_config
    return {"notice": "DEMO ONLY: selection and hybrid combination are illustrative, not a production protocol.",
            "config_switch": {"before": before, "after": switched}, "fallback_example": fallback,
            "hybrid_combiner": {"output_bytes": len(hybrid), "secret_material_emitted": False},
            "rollback": {"restored_previous_config": restored == before, "active_config": restored},
            "purpose": purpose_name, "primary_selection": first}

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", help="optional agility YAML config")
    args = parser.parse_args(argv)
    print(json.dumps(run_demo(args.config), indent=2))
    return 0
if __name__ == "__main__": raise SystemExit(main())
