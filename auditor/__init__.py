"""
CI-CD-Supply-Chain-Auditor

A security-focused auditor for CI/CD pipelines, identifying vulnerabilities,
misconfigurations, and best-practice deviations in your software supply chain.

Copyright 2024 Raghu
Licensed under the Apache License, Version 2.0
"""

from typing import Final

__version__: Final[str] = "1.0.0"
__author__: Final[str] = "Raghu"
__license__: Final[str] = "Apache-2.0"

# Public API exports
from auditor.core.analyzer import Analyzer
from auditor.core.result import AuditResult, Finding
from auditor.core.severity import Severity
from auditor.config import AuditorConfig

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "Analyzer",
    "AuditResult",
    "Finding",
    "Severity",
    "AuditorConfig",
]
