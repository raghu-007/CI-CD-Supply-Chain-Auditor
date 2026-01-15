"""
Audit result data structures.

Defines immutable data classes for representing audit findings and results.
These structures are designed to be serializable and type-safe.

SECURITY: Finding content is sanitized before storage to prevent
sensitive data leakage in reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditor.core.severity import Severity


@dataclass(frozen=True)
class FindingLocation:
    """
    Location of a security finding in source code.
    
    Immutable to ensure findings cannot be modified after creation.
    """
    
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    
    def __post_init__(self) -> None:
        """Validate location data."""
        if self.line_start is not None and self.line_start < 1:
            raise ValueError("line_start must be >= 1")
        if self.line_end is not None:
            if self.line_end < 1:
                raise ValueError("line_end must be >= 1")
            if self.line_start is not None and self.line_end < self.line_start:
                raise ValueError("line_end must be >= line_start")
    
    @property
    def file_name(self) -> str:
        """Get just the filename without path."""
        return Path(self.file_path).name
    
    def to_string(self) -> str:
        """Format location as human-readable string."""
        result = self.file_path
        if self.line_start is not None:
            result += f":{self.line_start}"
            if self.line_end is not None and self.line_end != self.line_start:
                result += f"-{self.line_end}"
        return result
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "column_start": self.column_start,
            "column_end": self.column_end,
        }


@dataclass(frozen=True)
class Finding:
    """
    A single security finding from an audit check.
    
    Immutable to ensure findings cannot be modified after creation.
    Contains all information needed to understand and remediate the issue.
    """
    
    # Required fields
    check_id: str  # Unique identifier for the check that found this
    title: str     # Short, descriptive title
    severity: Severity
    description: str  # Detailed explanation of the issue
    
    # Optional fields
    location: FindingLocation | None = None
    remediation: str | None = None  # How to fix the issue
    references: tuple[str, ...] = field(default_factory=tuple)  # URLs to documentation
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)  # CWE identifiers
    evidence: str | None = None  # Sanitized evidence (NO secrets!)
    metadata: dict[str, Any] = field(default_factory=dict)  # Additional context
    
    def __post_init__(self) -> None:
        """Validate finding data."""
        if not self.check_id:
            raise ValueError("check_id cannot be empty")
        if not self.title:
            raise ValueError("title cannot be empty")
        if not self.description:
            raise ValueError("description cannot be empty")
        
        # Validate severity is correct type
        if not isinstance(self.severity, Severity):
            raise TypeError(f"severity must be Severity, got {type(self.severity)}")
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "description": self.description,
            "location": self.location.to_dict() if self.location else None,
            "remediation": self.remediation,
            "references": list(self.references),
            "cwe_ids": list(self.cwe_ids),
            "evidence": self.evidence,
            "metadata": dict(self.metadata),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create Finding from dictionary."""
        location = None
        if data.get("location"):
            location = FindingLocation(**data["location"])
        
        return cls(
            check_id=data["check_id"],
            title=data["title"],
            severity=Severity.from_string(data["severity"]),
            description=data["description"],
            location=location,
            remediation=data.get("remediation"),
            references=tuple(data.get("references", [])),
            cwe_ids=tuple(data.get("cwe_ids", [])),
            evidence=data.get("evidence"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class CheckResult:
    """
    Result of running a single security check.
    
    Mutable to allow accumulating findings during check execution.
    """
    
    check_id: str
    check_name: str
    passed: bool = True
    findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0
    error_message: str | None = None
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update passed status."""
        self.findings.append(finding)
        if finding.severity >= Severity.LOW:
            self.passed = False
    
    @property
    def highest_severity(self) -> Severity | None:
        """Get the highest severity among findings."""
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "passed": self.passed,
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
        }


@dataclass
class AuditResult:
    """
    Complete result of an audit run.
    
    Contains all findings, metadata, and summary statistics.
    """
    
    # Target information
    target_path: str
    target_type: str  # "local" or "remote"
    
    # Timing
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    
    # Results
    check_results: list[CheckResult] = field(default_factory=list)
    
    # Metadata
    auditor_version: str = "1.0.0"
    platform: str = "unknown"
    
    @property
    def duration_seconds(self) -> float | None:
        """Calculate total audit duration in seconds."""
        if self.completed_at is None:
            return None
        delta = self.completed_at - self.started_at
        return delta.total_seconds()
    
    @property
    def all_findings(self) -> list[Finding]:
        """Get all findings from all checks."""
        findings = []
        for result in self.check_results:
            findings.extend(result.findings)
        return findings
    
    @property
    def total_findings(self) -> int:
        """Get total number of findings."""
        return sum(len(r.findings) for r in self.check_results)
    
    @property
    def passed(self) -> bool:
        """Check if the audit passed (no findings above INFO)."""
        return all(r.passed for r in self.check_results)
    
    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.name.lower(): 0 for s in Severity}
        for finding in self.all_findings:
            counts[finding.severity.name.lower()] += 1
        return counts
    
    @property
    def highest_severity(self) -> Severity | None:
        """Get the highest severity finding in the audit."""
        findings = self.all_findings
        if not findings:
            return None
        return max(f.severity for f in findings)
    
    def add_check_result(self, result: CheckResult) -> None:
        """Add a check result to the audit."""
        self.check_results.append(result)
    
    def complete(self) -> None:
        """Mark the audit as complete."""
        self.completed_at = datetime.now(timezone.utc)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "target_path": self.target_path,
            "target_type": self.target_type,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "auditor_version": self.auditor_version,
            "platform": self.platform,
            "summary": {
                "total_findings": self.total_findings,
                "passed": self.passed,
                "severity_counts": self.severity_counts,
                "highest_severity": (
                    self.highest_severity.name.lower() if self.highest_severity else None
                ),
            },
            "check_results": [r.to_dict() for r in self.check_results],
        }
    
    def get_findings_by_severity(
        self,
        min_severity: Severity = Severity.INFO,
    ) -> list[Finding]:
        """Get findings at or above the specified severity."""
        return [
            f for f in self.all_findings
            if f.severity >= min_severity
        ]
