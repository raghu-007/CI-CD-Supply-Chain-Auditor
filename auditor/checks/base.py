"""
Abstract base class for security checks.

Defines the interface that all security checks must implement.
Provides common functionality for finding creation and result handling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from auditor.core.result import Finding, FindingLocation
from auditor.core.severity import Severity
from auditor.logging_config import get_logger

if TYPE_CHECKING:
    from auditor.config import AuditorConfig

logger = get_logger("checks")


class BaseCheck(ABC):
    """
    Abstract base class for security checks.
    
    Subclasses must implement:
    - id: Unique check identifier
    - name: Human-readable name
    - description: What the check looks for
    - run: Main check logic
    
    The base class provides:
    - Finding creation helpers
    - Common validation utilities
    - Logging integration
    """
    
    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier for this check (e.g., 'secrets-001')."""
        ...
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the check."""
        ...
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Description of what this check looks for."""
        ...
    
    @property
    def default_severity(self) -> Severity:
        """Default severity for findings from this check."""
        return Severity.MEDIUM
    
    @property
    def references(self) -> tuple[str, ...]:
        """Documentation references for this check."""
        return ()
    
    @property
    def cwe_ids(self) -> tuple[str, ...]:
        """CWE identifiers related to this check."""
        return ()
    
    @abstractmethod
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """
        Run the security check.
        
        Args:
            parsed_files: List of parsed pipeline configurations
            config: Auditor configuration
        
        Returns:
            List of findings from this check
        """
        ...
    
    def create_finding(
        self,
        title: str,
        description: str,
        severity: Severity | None = None,
        file_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        remediation: str | None = None,
        evidence: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """
        Create a finding with this check's metadata.
        
        Args:
            title: Short, descriptive title
            description: Detailed explanation
            severity: Override default severity
            file_path: File where issue was found
            line_start: Starting line number
            line_end: Ending line number
            remediation: How to fix the issue
            evidence: Sanitized evidence (NO secrets!)
            metadata: Additional context
        
        Returns:
            Configured Finding instance
        """
        location = None
        if file_path:
            location = FindingLocation(
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
            )
        
        return Finding(
            check_id=self.id,
            title=title,
            severity=severity or self.default_severity,
            description=description,
            location=location,
            remediation=remediation,
            references=self.references,
            cwe_ids=self.cwe_ids,
            evidence=self._sanitize_evidence(evidence),
            metadata=metadata or {},
        )
    
    def _sanitize_evidence(self, evidence: str | None) -> str | None:
        """
        Sanitize evidence to remove potential secrets.
        
        SECURITY: This method must remove any sensitive data
        before including evidence in findings.
        """
        if evidence is None:
            return None
        
        from auditor.constants import SECRET_PATTERNS, MAX_REPORT_VALUE_LENGTH
        
        # Truncate if too long
        if len(evidence) > MAX_REPORT_VALUE_LENGTH:
            evidence = evidence[:MAX_REPORT_VALUE_LENGTH] + "... [truncated]"
        
        # Redact potential secrets
        for pattern in SECRET_PATTERNS.values():
            evidence = pattern.sub("[REDACTED]", evidence)
        
        return evidence
    
    def _get_files_by_type(
        self,
        parsed_files: list[dict[str, Any]],
        file_type: str,
    ) -> list[dict[str, Any]]:
        """Filter parsed files by type."""
        return [
            f for f in parsed_files
            if f.get("type") == file_type
        ]
    
    def _log_finding(self, finding: Finding) -> None:
        """Log a finding at appropriate level."""
        if finding.severity >= Severity.HIGH:
            logger.warning(
                f"[{self.id}] {finding.title}",
                extra={"severity": finding.severity.name},
            )
        else:
            logger.debug(
                f"[{self.id}] {finding.title}",
                extra={"severity": finding.severity.name},
            )
