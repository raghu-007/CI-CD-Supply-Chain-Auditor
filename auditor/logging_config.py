"""
Secure logging configuration for the CI-CD-Supply-Chain-Auditor.

This module provides logging that:
- Never logs secrets or sensitive data
- Sanitizes user input before logging
- Supports structured JSON logging for production
- Uses appropriate log levels

SECURITY: All log messages pass through sanitization to prevent
log injection attacks and accidental secret exposure.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

from auditor.constants import SECRET_PATTERNS, SECRET_KEYWORDS


class SecretFilter(logging.Filter):
    """
    Filter that redacts potential secrets from log messages.
    
    This filter scans log messages for patterns that might indicate
    secrets and replaces them with [REDACTED].
    """
    
    REDACTED = "[REDACTED]"
    
    def __init__(self, name: str = "") -> None:
        super().__init__(name)
        # Pre-compile a combined pattern for efficiency
        self._secret_keywords_pattern = re.compile(
            r"(?i)(" + "|".join(re.escape(kw) for kw in SECRET_KEYWORDS) + r")\s*[:=]\s*\S+",
        )
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize the log record."""
        # Sanitize the main message
        if record.msg:
            record.msg = self._sanitize(str(record.msg))
        
        # Sanitize arguments if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._sanitize(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self._sanitize(str(arg)) if isinstance(arg, str) else arg
                    for arg in record.args
                )
        
        return True  # Always allow the record through after sanitization
    
    def _sanitize(self, text: str) -> str:
        """Remove potential secrets from text."""
        result = text
        
        # Apply secret patterns
        for pattern_name, pattern in SECRET_PATTERNS.items():
            if pattern.search(result):
                result = pattern.sub(self.REDACTED, result)
        
        # Apply keyword-based detection
        result = self._secret_keywords_pattern.sub(
            lambda m: f"{m.group(1)}={self.REDACTED}",
            result
        )
        
        return result


class SanitizingFormatter(logging.Formatter):
    """
    Formatter that sanitizes log output to prevent log injection.
    
    Removes newlines and control characters that could be used
    for log injection attacks.
    """
    
    # Pattern to match dangerous control characters
    CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the record with sanitization."""
        # Get the formatted message
        message = super().format(record)
        
        # Remove control characters (except newline which we handle separately)
        message = self.CONTROL_CHARS.sub("", message)
        
        # Escape newlines in the message body to prevent log injection
        # Keep the final newline that the handler might add
        message = message.replace("\n", "\\n").replace("\r", "\\r")
        
        return message


class JsonFormatter(logging.Formatter):
    """
    JSON formatter for structured logging in production.
    
    Outputs log records as single-line JSON for easy parsing
    by log aggregation systems.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the record as JSON."""
        import json
        from datetime import datetime, timezone
        
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add location info
        if record.pathname and record.lineno:
            log_data["location"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        # Add any extra fields
        if hasattr(record, "extra_data"):
            log_data["extra"] = record.extra_data
        
        return json.dumps(log_data, default=str)


def setup_logging(
    level: str = "INFO",
    json_output: bool = False,
    no_color: bool = False,
) -> logging.Logger:
    """
    Set up logging with security-focused configuration.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_output: If True, output structured JSON logs
        no_color: If True, disable colored output
    
    Returns:
        Configured logger instance
    """
    # Get the root logger for the auditor package
    logger = logging.getLogger("auditor")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    
    # Add secret filter
    handler.addFilter(SecretFilter())
    
    # Choose formatter
    if json_output:
        formatter = JsonFormatter()
    else:
        if no_color:
            format_str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        else:
            # Simple colored output using ANSI codes
            format_str = (
                "\033[90m%(asctime)s\033[0m "
                "[\033[1m%(levelname)s\033[0m] "
                "\033[36m%(name)s\033[0m: %(message)s"
            )
        formatter = SanitizingFormatter(format_str, datefmt="%Y-%m-%d %H:%M:%S")
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Don't propagate to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the auditor namespace.
    
    Args:
        name: Logger name (will be prefixed with 'auditor.')
    
    Returns:
        Logger instance
    """
    if not name.startswith("auditor"):
        name = f"auditor.{name}"
    return logging.getLogger(name)


# Create a module-level logger
logger = get_logger("core")
