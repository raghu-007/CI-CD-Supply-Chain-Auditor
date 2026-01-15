"""
Abstract base class for pipeline parsers.

Defines the interface that all pipeline parsers must implement.
Provides common functionality for file discovery and validation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditor.exceptions import ParserError
from auditor.logging_config import get_logger
from auditor.parsers.validators import (
    validate_file_path,
    validate_file_size,
    validate_yaml_content,
    validate_yaml_structure,
)

if TYPE_CHECKING:
    from auditor.config import ScanConfig

logger = get_logger("parsers")


class BaseParser(ABC):
    """
    Abstract base class for CI/CD pipeline parsers.
    
    Subclasses must implement:
    - name: Human-readable parser name
    - file_patterns: Glob patterns for discovering files
    - _parse_content: Actual parsing logic
    
    The base class provides:
    - File discovery with security validation
    - Safe file reading
    - YAML loading with security protections
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the parser."""
        ...
    
    @property
    @abstractmethod
    def file_patterns(self) -> list[str]:
        """Glob patterns for discovering pipeline files."""
        ...
    
    @property
    def directories(self) -> list[str]:
        """Directories to search for pipeline files."""
        return ["."]
    
    def discover_files(
        self,
        root_path: Path,
        config: "ScanConfig",
    ) -> list[Path]:
        """
        Discover pipeline files in a directory.
        
        Args:
            root_path: Root directory to search
            config: Scan configuration
        
        Returns:
            List of discovered file paths
        """
        discovered = []
        
        for directory in self.directories:
            search_path = root_path / directory
            
            if not search_path.exists():
                continue
            
            for pattern in self.file_patterns:
                try:
                    # Use rglob for recursive search
                    matches = list(search_path.rglob(pattern))
                    
                    for match in matches:
                        # Skip if not a file
                        if not match.is_file():
                            continue
                        
                        # Skip symlinks if not allowed
                        if not config.follow_symlinks and match.is_symlink():
                            logger.debug(f"Skipping symlink: {match.name}")
                            continue
                        
                        # Skip excluded patterns
                        if self._is_excluded(match, config.exclude_patterns):
                            continue
                        
                        # Skip hidden files unless configured to include
                        if not config.include_hidden:
                            if any(part.startswith(".") for part in match.parts[len(root_path.parts):]):
                                # But allow .github directory specifically
                                if ".github" not in match.parts:
                                    continue
                        
                        # Validate path
                        try:
                            validated = validate_file_path(
                                match,
                                base_path=root_path,
                                allow_symlinks=config.follow_symlinks,
                            )
                            discovered.append(validated)
                        except Exception as e:
                            logger.debug(f"Skipping invalid path {match.name}: {e}")
                            continue
                        
                        # Check limit
                        if len(discovered) >= config.max_files:
                            logger.warning(
                                f"Reached maximum file limit ({config.max_files})"
                            )
                            return discovered
                
                except Exception as e:
                    logger.debug(f"Error searching pattern '{pattern}': {e}")
                    continue
        
        return discovered
    
    def _is_excluded(self, path: Path, exclude_patterns: list[str]) -> bool:
        """Check if a path matches any exclusion pattern."""
        path_str = str(path)
        path_parts = path.parts
        
        for pattern in exclude_patterns:
            # Check if any path component matches
            if pattern in path_parts:
                return True
            # Check glob-style matching
            if "*" in pattern:
                import fnmatch
                if fnmatch.fnmatch(path_str, f"*{pattern}*"):
                    return True
        
        return False
    
    def parse(self, file_path: Path) -> dict[str, Any] | None:
        """
        Parse a pipeline file.
        
        Args:
            file_path: Path to the pipeline file
        
        Returns:
            Parsed configuration dict, or None if parsing failed
        
        Raises:
            ParserError: If parsing fails critically
        """
        # Validate file
        try:
            validate_file_size(file_path)
        except Exception as e:
            raise ParserError(
                str(e),
                file_path=str(file_path),
            ) from None
        
        # Read content safely
        try:
            content = self._read_file_safely(file_path)
        except Exception as e:
            raise ParserError(
                f"Failed to read file: {e}",
                file_path=str(file_path),
            ) from None
        
        # Pre-validate YAML content
        try:
            validate_yaml_content(content)
        except Exception as e:
            raise ParserError(
                str(e),
                file_path=str(file_path),
            ) from None
        
        # Parse content
        try:
            result = self._parse_content(content, file_path)
        except ParserError:
            raise
        except Exception as e:
            raise ParserError(
                f"Failed to parse content: {e}",
                file_path=str(file_path),
            ) from e
        
        # Validate parsed structure
        if result is not None:
            try:
                validate_yaml_structure(result)
            except Exception as e:
                raise ParserError(
                    str(e),
                    file_path=str(file_path),
                ) from None
        
        return result
    
    def _read_file_safely(self, file_path: Path) -> str:
        """
        Read file content with security considerations.
        
        Uses UTF-8 encoding and handles encoding errors gracefully.
        """
        try:
            # Read with explicit encoding
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Try with error handling
            content = file_path.read_text(encoding="utf-8", errors="replace")
            logger.warning(f"File {file_path.name} contains non-UTF-8 characters")
        
        return content
    
    @abstractmethod
    def _parse_content(
        self,
        content: str,
        file_path: Path,
    ) -> dict[str, Any] | None:
        """
        Parse the file content.
        
        Args:
            content: Validated file content
            file_path: Path to the file (for error messages)
        
        Returns:
            Parsed configuration dict
        
        Raises:
            ParserError: If parsing fails
        """
        ...
    
    def _load_yaml_safely(self, content: str) -> Any:
        """
        Load YAML content using safe_load.
        
        SECURITY: Always uses yaml.safe_load to prevent
        arbitrary code execution.
        
        Args:
            content: YAML content string
        
        Returns:
            Parsed YAML data
        
        Raises:
            ParserError: If YAML is invalid
        """
        import yaml
        
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            # Extract line number if available
            line_num = None
            if hasattr(e, "problem_mark") and e.problem_mark:
                line_num = e.problem_mark.line + 1
            
            raise ParserError(
                f"Invalid YAML: {e}",
                line_number=line_num,
            ) from None
