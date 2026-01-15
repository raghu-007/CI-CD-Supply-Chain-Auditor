"""
Abstract base class for report generators.

Provides common functionality for all report types including
output sanitization and file writing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from auditor.constants import ESCAPE_CHARS, MAX_REPORT_VALUE_LENGTH
from auditor.exceptions import ReportError
from auditor.logging_config import get_logger

if TYPE_CHECKING:
    from auditor.core.result import AuditResult

logger = get_logger("reporters")


class BaseReporter(ABC):
    """
    Abstract base class for report generators.
    
    Subclasses must implement:
    - format_name: Name of the output format
    - file_extension: File extension for output
    - generate: Main report generation logic
    """
    
    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the report format (e.g., 'JSON', 'Markdown')."""
        ...
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """File extension for output files (e.g., '.json')."""
        ...
    
    @abstractmethod
    def generate(self, result: "AuditResult") -> str:
        """
        Generate the report content.
        
        Args:
            result: Audit result to report on
        
        Returns:
            Report content as string
        """
        ...
    
    def write(
        self,
        result: "AuditResult",
        output_path: Path,
    ) -> Path:
        """
        Generate and write report to file.
        
        Args:
            result: Audit result to report on
            output_path: Directory or file path for output
        
        Returns:
            Path to the written report file
        
        Raises:
            ReportError: If writing fails
        """
        # Determine output file path
        if output_path.is_dir():
            filename = f"audit_report{self.file_extension}"
            file_path = output_path / filename
        else:
            file_path = output_path
        
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate content
        try:
            content = self.generate(result)
        except Exception as e:
            raise ReportError(
                f"Failed to generate {self.format_name} report: {e}"
            ) from e
        
        # Write to file
        try:
            file_path.write_text(content, encoding="utf-8")
            logger.info(f"{self.format_name} report written to: {file_path}")
        except IOError as e:
            raise ReportError(
                f"Failed to write report to {file_path}: {e}"
            ) from e
        
        return file_path
    
    def _sanitize_text(self, text: str | None) -> str:
        """
        Sanitize text for safe output.
        
        Truncates long values and removes potentially dangerous content.
        """
        if text is None:
            return ""
        
        # Truncate if too long
        if len(text) > MAX_REPORT_VALUE_LENGTH:
            text = text[:MAX_REPORT_VALUE_LENGTH] + "..."
        
        return text
    
    def _escape_html(self, text: str | None) -> str:
        """
        Escape HTML special characters.
        
        SECURITY: Prevents XSS in HTML reports.
        """
        if text is None:
            return ""
        
        result = text
        for char, escape in ESCAPE_CHARS.items():
            result = result.replace(char, escape)
        
        return result
    
    def _get_severity_emoji(self, severity_name: str) -> str:
        """Get emoji for severity level."""
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }
        return emojis.get(severity_name.lower(), "❓")
    
    def _get_severity_color(self, severity_name: str) -> str:
        """Get color for severity level."""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }
        return colors.get(severity_name.lower(), "#6c757d")
