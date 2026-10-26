"""Compatibility imports; canonical implementation lives in quantumshield.compliance."""
from quantumshield.compliance.checker import (  # noqa: F401
    ComplianceAssessmentError,
    check_compliance,
    infer_security_strength_bits,
)
