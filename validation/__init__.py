"""
MITRE-CORE Validation Package
=============================

Unified validation framework for testing accuracy, security, and compliance.

Usage:
    from validation import UnifiedValidationSuite
    
    suite = UnifiedValidationSuite()
    report = suite.run_all_validations()
    
Or via command line:
    python -m validation --all
"""

from .unified_validation import (
    UnifiedValidationSuite,
    ValidationResult,
    main
)

__all__ = [
    'UnifiedValidationSuite',
    'ValidationResult',
    'main'
]
