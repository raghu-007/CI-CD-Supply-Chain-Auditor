"""
JSON report generator.

Generates machine-readable JSON reports suitable for integration
with other tools and systems.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from auditor.reporters.base import BaseReporter

if TYPE_CHECKING:
    from auditor.core.result import AuditResult


class JSONReporter(BaseReporter):
    """
    Generate JSON format audit reports.
    
    Output is a single JSON object with:
    - Audit metadata
    - Summary statistics
    - Detailed findings
    
    Suitable for:
    - CI/CD pipeline integration
    - Custom dashboards
    - Data analysis
    """
    
    @property
    def format_name(self) -> str:
        return "JSON"
    
    @property
    def file_extension(self) -> str:
        return ".json"
    
    def __init__(self, pretty: bool = True) -> None:
        """
        Initialize JSON reporter.
        
        Args:
            pretty: If True, output formatted JSON with indentation
        """
        self.pretty = pretty
    
    def generate(self, result: "AuditResult") -> str:
        """Generate JSON report."""
        report_data = self._build_report_data(result)
        
        if self.pretty:
            return json.dumps(report_data, indent=2, default=str, ensure_ascii=False)
        else:
            return json.dumps(report_data, default=str, ensure_ascii=False)
    
    def _build_report_data(self, result: "AuditResult") -> dict[str, Any]:
        """Build the report data structure."""
        return {
            "schema_version": "1.0",
            "audit": {
                "target": result.target_path,
                "target_type": result.target_type,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "duration_seconds": result.duration_seconds,
                "auditor_version": result.auditor_version,
                "platform": result.platform,
            },
            "summary": {
                "passed": result.passed,
                "total_findings": result.total_findings,
                "highest_severity": (
                    result.highest_severity.name.lower()
                    if result.highest_severity else None
                ),
                "severity_counts": result.severity_counts,
                "checks_run": len(result.check_results),
                "checks_passed": sum(1 for r in result.check_results if r.passed),
            },
            "findings": [
                self._format_finding(f) for f in result.all_findings
            ],
            "check_results": [
                self._format_check_result(r) for r in result.check_results
            ],
        }
    
    def _format_finding(self, finding: Any) -> dict[str, Any]:
        """Format a single finding for JSON output."""
        return {
            "id": finding.check_id,
            "title": self._sanitize_text(finding.title),
            "severity": finding.severity.name.lower(),
            "description": self._sanitize_text(finding.description),
            "location": (
                {
                    "file": finding.location.file_path,
                    "line_start": finding.location.line_start,
                    "line_end": finding.location.line_end,
                }
                if finding.location else None
            ),
            "remediation": self._sanitize_text(finding.remediation),
            "references": list(finding.references),
            "cwe_ids": list(finding.cwe_ids),
            "evidence": self._sanitize_text(finding.evidence),
        }
    
    def _format_check_result(self, result: Any) -> dict[str, Any]:
        """Format a check result for JSON output."""
        return {
            "check_id": result.check_id,
            "check_name": result.check_name,
            "passed": result.passed,
            "finding_count": len(result.findings),
            "duration_ms": round(result.duration_ms, 2),
            "error": result.error_message,
        }
