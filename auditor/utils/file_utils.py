"""
Secure file operations.

Provides safe file reading and writing with proper validation
and error handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from auditor.constants import MAX_FILE_SIZE_BYTES
from auditor.exceptions import ValidationError
from auditor.parsers.validators import validate_file_path, validate_file_size


def safe_read_file(
    file_path: Path | str,
    base_path: Optional[Path] = None,
    max_size: int = MAX_FILE_SIZE_BYTES,
    encoding: str = "utf-8",
) -> str:
    """
    Safely read a file with security validations.
    
    Args:
        file_path: Path to file to read
        base_path: If provided, file must be within this directory
        max_size: Maximum file size in bytes
        encoding: File encoding
    
    Returns:
        File contents as string
    
    Raises:
        ValidationError: If file is invalid or unsafe
    """
    path = Path(file_path)
    
    # Validate path
    validated_path = validate_file_path(path, base_path=base_path)
    
    # Check file exists
    if not validated_path.exists():
        raise ValidationError(
            "File does not exist",
            field="file_path",
        )
    
    if not validated_path.is_file():
        raise ValidationError(
            "Path is not a file",
            field="file_path",
        )
    
    # Validate size
    validate_file_size(validated_path, max_size)
    
    # Read with proper encoding handling
    try:
        return validated_path.read_text(encoding=encoding)
    except UnicodeDecodeError:
        # Try with error replacement
        return validated_path.read_text(encoding=encoding, errors="replace")


def safe_write_file(
    file_path: Path | str,
    content: str,
    base_path: Optional[Path] = None,
    encoding: str = "utf-8",
    overwrite: bool = False,
) -> Path:
    """
    Safely write content to a file.
    
    Args:
        file_path: Path to write to
        content: Content to write
        base_path: If provided, file must be within this directory
        encoding: File encoding
        overwrite: If True, overwrite existing file
    
    Returns:
        Path to written file
    
    Raises:
        ValidationError: If path is invalid or unsafe
    """
    path = Path(file_path)
    
    # Validate path (allow non-existent for new files)
    validated_path = validate_file_path(
        path,
        base_path=base_path,
        allow_symlinks=False,
    )
    
    # Check if file exists
    if validated_path.exists() and not overwrite:
        raise ValidationError(
            "File already exists and overwrite=False",
            field="file_path",
        )
    
    # Ensure parent directory exists
    validated_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write file
    validated_path.write_text(content, encoding=encoding)
    
    return validated_path


def ensure_directory(
    dir_path: Path | str,
    base_path: Optional[Path] = None,
) -> Path:
    """
    Ensure a directory exists, creating if necessary.
    
    Args:
        dir_path: Directory path
        base_path: If provided, directory must be within this path
    
    Returns:
        Path to directory
    
    Raises:
        ValidationError: If path is invalid
    """
    path = Path(dir_path)
    
    # Basic validation
    if base_path:
        try:
            resolved = path.resolve()
            resolved.relative_to(base_path.resolve())
        except ValueError:
            raise ValidationError(
                "Directory is outside allowed base path",
                field="dir_path",
            )
    
    # Create directory
    path.mkdir(parents=True, exist_ok=True)
    
    return path
