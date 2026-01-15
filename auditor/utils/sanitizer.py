"""
Output sanitization utilities.

Provides functions to sanitize output for logs, displays, and reports
to prevent sensitive data leakage and injection attacks.
"""

from __future__ import annotations

import re
from typing import Any

from auditor.constants import (
    SECRET_PATTERNS,
    SECRET_KEYWORDS,
    ESCAPE_CHARS,
    MAX_REPORT_VALUE_LENGTH,
)


def sanitize_for_log(value: Any) -> str:
    """
    Sanitize a value for safe logging.
    
    Removes:
    - Potential secrets
    - Control characters
    - Excessive length
    
    Args:
        value: Value to sanitize
    
    Returns:
        Sanitized string safe for logging
    """
    if value is None:
        return ""
    
    text = str(value)
    
    # Remove control characters
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    
    # Redact secrets
    text = redact_secrets(text)
    
    # Truncate if too long
    if len(text) > MAX_REPORT_VALUE_LENGTH:
        text = text[:MAX_REPORT_VALUE_LENGTH] + "...[truncated]"
    
    # Escape newlines for single-line logging
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    
    return text


def sanitize_for_display(
    value: Any,
    max_length: int = MAX_REPORT_VALUE_LENGTH,
) -> str:
    """
    Sanitize a value for display in reports/UI.
    
    Args:
        value: Value to sanitize
        max_length: Maximum output length
    
    Returns:
        Sanitized string safe for display
    """
    if value is None:
        return ""
    
    text = str(value)
    
    # Redact secrets
    text = redact_secrets(text)
    
    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "..."
    
    return text


def redact_secrets(text: str) -> str:
    """
    Redact potential secrets from text.
    
    Uses pattern matching and keyword detection to identify
    and replace potential sensitive data.
    
    Args:
        text: Text to redact
    
    Returns:
        Text with secrets replaced by [REDACTED]
    """
    if not text:
        return text
    
    result = text
    
    # Apply secret patterns
    for pattern in SECRET_PATTERNS.values():
        result = pattern.sub("[REDACTED]", result)
    
    # Apply keyword-based detection for key=value patterns
    for keyword in SECRET_KEYWORDS:
        # Match keyword followed by = or : and a value
        pattern = re.compile(
            rf"({re.escape(keyword)})\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?",
            re.IGNORECASE,
        )
        result = pattern.sub(r"\1=[REDACTED]", result)
    
    return result


def escape_html(text: str) -> str:
    """
    Escape HTML special characters to prevent XSS.
    
    Args:
        text: Text to escape
    
    Returns:
        HTML-safe text
    """
    if not text:
        return ""
    
    result = text
    for char, escape in ESCAPE_CHARS.items():
        result = result.replace(char, escape)
    
    return result


def escape_shell(text: str) -> str:
    """
    Escape text for safe shell usage.
    
    Note: This is for display/logging only. Never use this
    to construct shell commands from user input.
    
    Args:
        text: Text to escape
    
    Returns:
        Shell-escaped text
    """
    if not text:
        return "''"
    
    # Use single quotes and escape any internal single quotes
    return "'" + text.replace("'", "'\"'\"'") + "'"


def truncate(
    text: str,
    max_length: int = 100,
    suffix: str = "...",
) -> str:
    """
    Truncate text to a maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to append if truncated
    
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def mask_token(token: str, visible_chars: int = 4) -> str:
    """
    Mask a token showing only first/last few characters.
    
    Args:
        token: Token to mask
        visible_chars: Number of characters to show at start/end
    
    Returns:
        Masked token like "ghp_****XXXX"
    """
    if not token:
        return ""
    
    if len(token) <= visible_chars * 2:
        return "*" * len(token)
    
    return token[:visible_chars] + "****" + token[-visible_chars:]
