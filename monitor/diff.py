"""Compatibility import for the assessment comparison API."""

from pathlib import Path
import sys

_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if _SOURCE_ROOT.is_dir() and str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from quantumshield.monitor.diff import AssessmentFormatError, diff_assessments  # noqa: E402

__all__ = ["AssessmentFormatError", "diff_assessments"]
