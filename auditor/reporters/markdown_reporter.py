"""
Markdown report generator.

Generates human-readable Markdown reports suitable for documentation,
GitHub issues, or wiki pages.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from auditor.core.severity import Severity
from auditor.reporters.base import BaseReporter

if TYPE_CHECKING:
    from auditor.core.result import AuditResult, Finding


class MarkdownReporter(BaseReporter):
    """
    Generate Markdown format audit reports.
    
    Output is a well-formatted Markdown document with:
    - Executive summary
    - Findings by severity
    - Detailed findings with remediation
    - Statistics
    
    Suitable for:
    - GitHub issues/PRs
    - Wiki documentation
    - Email reports
    """
    
    @property
    def format_name(self) -> str:
        return "Markdown"
    
    @property
    def file_extension(self) -> str:
        return ".md"
    
    def generate(self, result: "AuditResult") -> str:
        """Generate Markdown report."""
        lines: list[str] = []
        
        # Header
        lines.extend(self._generate_header(result))
        
        # Executive summary
        lines.extend(self._generate_summary(result))
        
        # Findings by severity
        if result.total_findings > 0:
            lines.extend(self._generate_findings_section(result))
        else:
            lines.append("## ✅ No Issues Found\n")
            lines.append("The audit completed successfully with no security findings.\n")
        
        # Check results summary
        lines.extend(self._generate_check_summary(result))
        
        # Footer
        lines.extend(self._generate_footer(result))
        
        return "\n".join(lines)
    
    def _generate_header(self, result: "AuditResult") -> list[str]:
        """Generate report header."""
        lines = [
            "# 🔒 CI/CD Security Audit Report\n",
            f"**Target:** `{result.target_path}`\n",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            f"**Platform:** {result.platform}\n",
            "",
            "---\n",
        ]
        return lines
    
    def _generate_summary(self, result: "AuditResult") -> list[str]:
        """Generate executive summary."""
        lines = [
            "## 📊 Executive Summary\n",
        ]
        
        # Overall status
        if result.passed:
            lines.append("> ✅ **PASSED** - No critical security issues detected.\n")
        else:
            highest = result.highest_severity
            if highest and highest >= Severity.CRITICAL:
                lines.append("> 🔴 **CRITICAL ISSUES FOUND** - Immediate attention required.\n")
            elif highest and highest >= Severity.HIGH:
                lines.append("> 🟠 **HIGH SEVERITY ISSUES** - Should be addressed soon.\n")
            else:
                lines.append("> 🟡 **ISSUES FOUND** - Review recommended.\n")
        
        lines.append("")
        
        # Statistics table
        lines.append("### Findings Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        
        for severity in reversed(list(Severity)):
            count = result.severity_counts.get(severity.name.lower(), 0)
            if count > 0:
                emoji = self._get_severity_emoji(severity.name)
                lines.append(f"| {emoji} {severity.name.capitalize()} | {count} |")
        
        lines.append("")
        lines.append(f"**Total Findings:** {result.total_findings}\n")
        lines.append("")
        
        return lines
    
    def _generate_findings_section(self, result: "AuditResult") -> list[str]:
        """Generate detailed findings section."""
        lines = [
            "## 🔍 Detailed Findings\n",
        ]
        
        # Group findings by severity
        findings_by_severity: dict[Severity, list[Finding]] = {}
        for finding in result.all_findings:
            if finding.severity not in findings_by_severity:
                findings_by_severity[finding.severity] = []
            findings_by_severity[finding.severity].append(finding)
        
        # Output in severity order (highest first)
        for severity in reversed(list(Severity)):
            findings = findings_by_severity.get(severity, [])
            if not findings:
                continue
            
            emoji = self._get_severity_emoji(severity.name)
            lines.append(f"### {emoji} {severity.name.capitalize()} Severity\n")
            
            for i, finding in enumerate(findings, 1):
                lines.extend(self._format_finding(finding, i))
            
            lines.append("")
        
        return lines
    
    def _format_finding(self, finding: Any, index: int) -> list[str]:
        """Format a single finding."""
        lines = [
            f"#### {index}. {self._sanitize_text(finding.title)}\n",
        ]
        
        # Location
        if finding.location:
            lines.append(f"📍 **Location:** `{finding.location.to_string()}`\n")
        
        # Description
        lines.append("**Description:**\n")
        lines.append(f"{self._sanitize_text(finding.description)}\n")
        
        # Evidence (if any)
        if finding.evidence:
            lines.append("<details>")
            lines.append("<summary>Evidence</summary>\n")
            lines.append("```")
            lines.append(self._sanitize_text(finding.evidence))
            lines.append("```\n")
            lines.append("</details>\n")
        
        # Remediation
        if finding.remediation:
            lines.append("**Remediation:**\n")
            lines.append(f"{self._sanitize_text(finding.remediation)}\n")
        
        # References
        if finding.references:
            lines.append("**References:**")
            for ref in finding.references:
                lines.append(f"- {ref}")
            lines.append("")
        
        # CWE IDs
        if finding.cwe_ids:
            cwe_links = [
                f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html)"
                for cwe in finding.cwe_ids
            ]
            lines.append(f"**CWE:** {', '.join(cwe_links)}\n")
        
        lines.append("---\n")
        
        return lines
    
    def _generate_check_summary(self, result: "AuditResult") -> list[str]:
        """Generate check results summary."""
        lines = [
            "## 📋 Checks Performed\n",
            "| Check | Status | Findings | Duration |",
            "|-------|--------|----------|----------|",
        ]
        
        for check_result in result.check_results:
            status = "✅ Pass" if check_result.passed else "❌ Fail"
            duration = f"{check_result.duration_ms:.0f}ms"
            lines.append(
                f"| {check_result.check_name} | {status} | "
                f"{len(check_result.findings)} | {duration} |"
            )
        
        lines.append("")
        
        return lines
    
    def _generate_footer(self, result: "AuditResult") -> list[str]:
        """Generate report footer."""
        lines = [
            "---\n",
            f"*Generated by CI-CD-Supply-Chain-Auditor v{result.auditor_version}*\n",
        ]
        
        if result.duration_seconds:
            lines.append(f"*Audit duration: {result.duration_seconds:.2f} seconds*\n")
        
        return lines
