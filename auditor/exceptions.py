"""
Custom exceptions for the CI-CD-Supply-Chain-Auditor.

All exceptions inherit from AuditorError to allow catching all auditor-specific
exceptions with a single except clause. Each exception includes context about
the error without exposing sensitive information.
"""

from typing import Any


class AuditorError(Exception):
    """
    Base exception for all auditor-related errors.
    
    Attributes:
        message: Human-readable error description
        details: Additional context (sanitized, no secrets)
    """
    
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self) -> str:
        if self.details:
            detail_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({detail_str})"
        return self.message
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, details={self.details!r})"


class ConfigurationError(AuditorError):
    """
    Raised when there's an issue with configuration.
    
    Examples:
        - Missing required configuration values
        - Invalid configuration format
        - Configuration file not found
    """
    pass


class ValidationError(AuditorError):
    """
    Raised when input validation fails.
    
    Examples:
        - Invalid file path (path traversal attempt)
        - Malformed YAML content
        - Input exceeds size limits
    """
    
    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if field:
            details["field"] = field
        # Never include the actual invalid value in logs for security
        if value:
            details["value_length"] = len(value)
        super().__init__(message, details)


class ParserError(AuditorError):
    """
    Raised when parsing pipeline configuration fails.
    
    Examples:
        - Invalid YAML syntax
        - Unsupported pipeline format
        - Missing required fields in workflow
    """
    
    def __init__(
        self,
        message: str,
        file_path: str | None = None,
        line_number: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if file_path:
            # Only include filename, not full path for security
            from pathlib import Path
            details["file"] = Path(file_path).name
        if line_number:
            details["line"] = line_number
        super().__init__(message, details)


class SecurityCheckError(AuditorError):
    """
    Raised when a security check fails to execute.
    
    Note: This is NOT raised when a check finds a vulnerability.
    This is for errors during the check execution itself.
    
    Examples:
        - Check module failed to load
        - External service unavailable
        - Timeout during check execution
    """
    
    def __init__(
        self,
        message: str,
        check_name: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if check_name:
            details["check"] = check_name
        super().__init__(message, details)


class ReportError(AuditorError):
    """
    Raised when report generation fails.
    
    Examples:
        - Template rendering error
        - Output file write permission denied
        - Invalid output format
    """
    pass


class GitOperationError(AuditorError):
    """
    Raised when a Git operation fails.
    
    Examples:
        - Repository not found
        - Invalid commit reference
        - Permission denied to repository
    """
    
    def __init__(
        self,
        message: str,
        repository: str | None = None,
        operation: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if repository:
            # Only include repo name, not full URL (may contain tokens)
            details["repository"] = repository.split("/")[-1] if "/" in repository else repository
        if operation:
            details["operation"] = operation
        super().__init__(message, details)


class RateLimitError(AuditorError):
    """
    Raised when an API rate limit is exceeded.
    
    Examples:
        - GitHub API rate limit
        - External service throttling
    """
    
    def __init__(
        self,
        message: str,
        retry_after: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        details = details or {}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(message, details)
