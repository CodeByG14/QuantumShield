"""Repository-root entry point for ``python -m monitor.check``.

The implementation lives in the installable ``quantumshield.monitor`` package;
this lightweight wrapper preserves the Phase 5 CLI specified for repository use.
"""

from pathlib import Path
import sys

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if _SOURCE_ROOT.is_dir() and str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from quantumshield.monitor.check import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
