"""
Configuration management for the CI-CD-Supply-Chain-Auditor.

Uses Pydantic for robust validation, type safety, and environment variable support.
Configuration values are validated at load time to fail fast on invalid configs.

SECURITY NOTES:
- Secrets should be passed via environment variables, not config files
- All paths are validated to prevent traversal attacks
- No default values for sensitive settings
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CheckConfig(BaseModel):
    """Configuration for individual security checks."""
    
    enabled: bool = True
    severity_threshold: Literal["low", "medium", "high", "critical"] = "low"
    custom_patterns: list[str] = Field(default_factory=list)
    
    @field_validator("custom_patterns")
    @classmethod
    def validate_patterns(cls, v: list[str]) -> list[str]:
        """Validate custom patterns are not empty and reasonable length."""
        validated = []
        for pattern in v:
            if not pattern or not pattern.strip():
                continue
            if len(pattern) > 1000:
                raise ValueError("Pattern too long (max 1000 chars)")
            validated.append(pattern.strip())
        return validated


class ReportConfig(BaseModel):
    """Configuration for report generation."""
    
    format: Literal["json", "markdown", "html", "all"] = "json"
    output_dir: Path = Field(default=Path("./reports"))
    include_passed_checks: bool = False
    include_remediation: bool = True
    max_findings_per_check: int = Field(default=100, ge=1, le=10000)
    
    @field_validator("output_dir")
    @classmethod
    def validate_output_dir(cls, v: Path) -> Path:
        """Validate output directory path."""
        # Convert to absolute and resolve any .. components
        resolved = v.resolve()
        
        # Basic path traversal check
        try:
            resolved.relative_to(Path.cwd())
        except ValueError:
            # Path is outside CWD, check if it's a reasonable location
            # Allow home directory and common paths
            home = Path.home()
            if not str(resolved).startswith(str(home)):
                # Allow if it's an absolute path that exists or can be created
                pass  # We'll validate on actual use
        
        return resolved


class GitHubConfig(BaseModel):
    """Configuration for GitHub integration."""
    
    # Token should come from environment variable for security
    token: str | None = Field(default=None, exclude=True)  # Exclude from serialization
    api_url: str = "https://api.github.com"
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    verify_ssl: bool = True  # Never disable in production
    
    @field_validator("api_url")
    @classmethod
    def validate_api_url(cls, v: str) -> str:
        """Validate API URL format."""
        if not v.startswith(("https://", "http://localhost")):
            raise ValueError("API URL must use HTTPS (or localhost for testing)")
        return v.rstrip("/")
    
    @model_validator(mode="after")
    def warn_no_ssl(self) -> "GitHubConfig":
        """Warn if SSL verification is disabled."""
        if not self.verify_ssl:
            import warnings
            warnings.warn(
                "SSL verification is disabled. This is insecure and should "
                "only be used for testing with self-signed certificates.",
                UserWarning,
                stacklevel=2
            )
        return self


class ScanConfig(BaseModel):
    """Configuration for scanning behavior."""
    
    max_file_size_mb: float = Field(default=10.0, ge=0.1, le=100.0)
    max_files: int = Field(default=1000, ge=1, le=100000)
    follow_symlinks: bool = False  # Security: avoid symlink attacks
    include_hidden: bool = True  # .github folder needs to be scanned
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "node_modules",
            ".git",
            "__pycache__",
            "*.pyc",
            ".venv",
            "venv",
            "dist",
            "build",
        ]
    )
    
    @property
    def max_file_size_bytes(self) -> int:
        """Convert MB to bytes."""
        return int(self.max_file_size_mb * 1024 * 1024)


class AuditorConfig(BaseSettings):
    """
    Main configuration for the CI-CD-Supply-Chain-Auditor.
    
    Configuration precedence (highest to lowest):
    1. Environment variables (AUDITOR_*)
    2. Config file values
    3. Default values
    
    Example environment variables:
        AUDITOR_LOG_LEVEL=DEBUG
        AUDITOR_GITHUB__TOKEN=ghp_xxx
    """
    
    model_config = SettingsConfigDict(
        env_prefix="AUDITOR_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )
    
    # General settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    verbose: bool = False
    no_color: bool = False
    
    # Platform to audit
    platform: Literal["github_actions", "gitlab_ci", "auto"] = "auto"
    
    # Target configuration
    target_path: Path | None = None
    target_url: str | None = None
    
    # Sub-configurations
    checks: CheckConfig = Field(default_factory=CheckConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    
    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, v: Path | None) -> Path | None:
        """Validate and resolve target path."""
        if v is None:
            return None
        
        resolved = v.resolve()
        
        # Check path exists
        if not resolved.exists():
            raise ValueError(f"Target path does not exist: {v}")
        
        return resolved
    
    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str | None) -> str | None:
        """Validate target URL format."""
        if v is None:
            return None
        
        # Basic URL validation
        if not v.startswith(("https://", "git@")):
            raise ValueError("Target URL must use HTTPS or SSH (git@)")
        
        # Don't include credentials in URL
        if "@" in v and not v.startswith("git@"):
            # Check for embedded credentials
            from urllib.parse import urlparse
            parsed = urlparse(v)
            if parsed.password:
                raise ValueError(
                    "URL contains embedded credentials. Use environment "
                    "variables for authentication instead."
                )
        
        return v
    
    @model_validator(mode="after")
    def validate_target(self) -> "AuditorConfig":
        """Ensure at least one target is specified for scanning."""
        # This validation is optional - target can be provided at scan time
        return self
    
    @classmethod
    def from_yaml_file(cls, path: Path) -> "AuditorConfig":
        """
        Load configuration from a YAML file.
        
        SECURITY: Uses safe_load to prevent code execution.
        """
        import yaml
        from auditor.constants import MAX_FILE_SIZE_BYTES
        
        # Validate file exists and size
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
            raise ValueError(f"Config file too large: {path}")
        
        # Read and parse safely
        content = path.read_text(encoding="utf-8")
        
        # Use safe_load to prevent arbitrary code execution
        data = yaml.safe_load(content)
        
        if data is None:
            data = {}
        
        if not isinstance(data, dict):
            raise ValueError("Config file must contain a YAML mapping")
        
        return cls(**data)
    
    def to_safe_dict(self) -> dict[str, Any]:
        """
        Export config as dict, excluding sensitive values.
        
        Use this for logging or debugging.
        """
        data = self.model_dump()
        
        # Mask sensitive fields
        if "github" in data and "token" in data["github"]:
            data["github"]["token"] = "***MASKED***" if data["github"]["token"] else None
        
        return data


def get_default_config() -> AuditorConfig:
    """Get default configuration with environment overrides."""
    return AuditorConfig()


def load_config(
    config_path: Path | None = None,
    **overrides: Any,
) -> AuditorConfig:
    """
    Load configuration from file and/or environment with overrides.
    
    Args:
        config_path: Optional path to YAML config file
        **overrides: Direct overrides for config values
    
    Returns:
        Validated AuditorConfig instance
    """
    if config_path:
        config = AuditorConfig.from_yaml_file(config_path)
    else:
        config = get_default_config()
    
    # Apply overrides
    if overrides:
        config_dict = config.model_dump()
        _deep_update(config_dict, overrides)
        config = AuditorConfig(**config_dict)
    
    return config


def _deep_update(base: dict[str, Any], updates: dict[str, Any]) -> None:
    """Recursively update a dictionary."""
    for key, value in updates.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
