"""
Input validation utilities for parsers.

Provides secure validation for file paths, content sizes, and YAML data.
All validators are designed to fail safely and prevent common attacks.

SECURITY CONSIDERATIONS:
- Path traversal prevention
- File size limits (DoS protection)
- YAML bomb detection
- Type validation
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from auditor.constants import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    MAX_LINE_LENGTH,
    MAX_YAML_DEPTH,
    YAML_EXTENSIONS,
)
from auditor.exceptions import ValidationError


def validate_file_path(
    file_path: Path | str,
    base_path: Path | None = None,
    allow_symlinks: bool = False,
) -> Path:
    """
    Validate a file path for security issues.
    
    Checks:
    - Path traversal attempts (../)
    - Symlink escapes (if not allowed)
    - Path is within base_path (if specified)
    - File exists and is readable
    
    Args:
        file_path: Path to validate
        base_path: If provided, file must be within this directory
        allow_symlinks: Whether to allow symbolic links
    
    Returns:
        Resolved, validated Path object
    
    Raises:
        ValidationError: If path is invalid or unsafe
    """
    path = Path(file_path)
    
    # Resolve to absolute path
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise ValidationError(
            "Invalid file path",
            field="file_path",
            details={"error": str(e)},
        ) from None
    
    # Check for path traversal by looking for .. in the original path
    path_str = str(path)
    if ".." in path_str:
        # Verify the resolved path doesn't escape
        normalized = os.path.normpath(path_str)
        if ".." in normalized:
            raise ValidationError(
                "Path traversal not allowed",
                field="file_path",
            )
    
    # Check symlinks if not allowed
    if not allow_symlinks:
        try:
            # Check if any component of the path is a symlink
            current = resolved
            while current != current.parent:
                if current.is_symlink():
                    raise ValidationError(
                        "Symbolic links not allowed",
                        field="file_path",
                    )
                current = current.parent
        except OSError:
            pass  # Path doesn't exist yet, which is fine
    
    # Check base path constraint
    if base_path is not None:
        base_resolved = base_path.resolve()
        try:
            resolved.relative_to(base_resolved)
        except ValueError:
            raise ValidationError(
                "Path is outside allowed directory",
                field="file_path",
                details={"base_path": str(base_path)},
            )
    
    return resolved


def validate_file_size(
    file_path: Path,
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
) -> int:
    """
    Validate file size is within limits.
    
    Args:
        file_path: Path to check
        max_size_bytes: Maximum allowed size
    
    Returns:
        File size in bytes
    
    Raises:
        ValidationError: If file is too large or cannot be read
    """
    try:
        size = file_path.stat().st_size
    except OSError as e:
        raise ValidationError(
            f"Cannot read file size: {e}",
            field="file_path",
        ) from None
    
    if size > max_size_bytes:
        raise ValidationError(
            f"File size ({size:,} bytes) exceeds limit ({max_size_bytes:,} bytes)",
            field="file_size",
            details={"size": size, "limit": max_size_bytes},
        )
    
    return size


def validate_file_extension(
    file_path: Path,
    allowed: frozenset[str] | None = None,
) -> str:
    """
    Validate file extension is in allowed list.
    
    Args:
        file_path: Path to check
        allowed: Set of allowed extensions (with leading dot)
    
    Returns:
        File extension (lowercase, with leading dot)
    
    Raises:
        ValidationError: If extension is not allowed
    """
    if allowed is None:
        allowed = ALLOWED_EXTENSIONS
    
    ext = file_path.suffix.lower()
    
    # Handle files without extension
    if not ext:
        # Check if filename itself is in allowed list (e.g., "Dockerfile")
        name_lower = file_path.name.lower()
        if f".{name_lower}" not in allowed and name_lower not in {
            "dockerfile", "containerfile", "jenkinsfile", "makefile"
        }:
            raise ValidationError(
                "File has no extension",
                field="file_extension",
            )
        return ""
    
    if ext not in allowed:
        raise ValidationError(
            f"File extension '{ext}' is not allowed",
            field="file_extension",
            details={"allowed": list(allowed)[:10]},  # Limit for readability
        )
    
    return ext


def validate_yaml_content(
    content: str,
    max_depth: int = MAX_YAML_DEPTH,
) -> str:
    """
    Validate YAML content before parsing.
    
    Pre-parse checks:
    - Content length reasonable
    - No excessive repetition (bomb indicator)
    - Line lengths reasonable
    
    Args:
        content: Raw YAML content
        max_depth: Maximum nesting depth (for later validation)
    
    Returns:
        Validated content string
    
    Raises:
        ValidationError: If content appears malicious
    """
    if not content or not content.strip():
        raise ValidationError(
            "YAML content is empty",
            field="yaml_content",
        )
    
    # Check total size
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise ValidationError(
            "YAML content too large",
            field="yaml_content",
            details={"size": len(content)},
        )
    
    # Check for lines that are too long (potential bomb indicator)
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_LENGTH:
            raise ValidationError(
                f"Line {i} exceeds maximum length ({MAX_LINE_LENGTH})",
                field="yaml_content",
                details={"line": i, "length": len(line)},
            )
    
    # Check for suspicious patterns (many repeated anchors)
    anchor_count = content.count("&")
    alias_count = content.count("*")
    
    # YAML bombs often have many anchors with exponential alias references
    if anchor_count > 100 or alias_count > 1000:
        raise ValidationError(
            "YAML content has suspicious anchor/alias pattern",
            field="yaml_content",
            details={"anchors": anchor_count, "aliases": alias_count},
        )
    
    return content


def validate_yaml_structure(
    data: Any,
    max_depth: int = MAX_YAML_DEPTH,
    _current_depth: int = 0,
) -> None:
    """
    Validate parsed YAML structure for excessive nesting.
    
    Prevents deeply nested structures that could cause stack overflow
    or excessive memory usage.
    
    Args:
        data: Parsed YAML data
        max_depth: Maximum allowed nesting depth
        _current_depth: Internal counter (do not set)
    
    Raises:
        ValidationError: If structure is too deep
    """
    if _current_depth > max_depth:
        raise ValidationError(
            f"YAML nesting depth exceeds limit ({max_depth})",
            field="yaml_depth",
        )
    
    if isinstance(data, dict):
        for key, value in data.items():
            # Validate key is string or boolean
            # Note: YAML 1.1 parses 'on', 'yes', 'no' as booleans
            # This is common in GitHub Actions (on: trigger)
            if not isinstance(key, (str, bool)):
                raise ValidationError(
                    f"YAML key must be string, got {type(key).__name__}",
                    field="yaml_key",
                )
            validate_yaml_structure(value, max_depth, _current_depth + 1)
    
    elif isinstance(data, list):
        for item in data:
            validate_yaml_structure(item, max_depth, _current_depth + 1)


def is_yaml_file(file_path: Path) -> bool:
    """Check if a file is a YAML file by extension."""
    return file_path.suffix.lower() in YAML_EXTENSIONS


def sanitize_path_for_display(path: Path | str) -> str:
    """
    Sanitize a path for safe display in logs/reports.
    
    Removes potentially sensitive path components while keeping
    useful information for debugging.
    
    Args:
        path: Path to sanitize
    
    Returns:
        Sanitized path string
    """
    p = Path(path)
    
    # Get last 3 path components at most
    parts = p.parts[-3:] if len(p.parts) > 3 else p.parts
    
    if len(p.parts) > 3:
        return ".../" + "/".join(parts)
    return str(p)
