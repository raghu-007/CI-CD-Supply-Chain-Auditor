"""
Tests for configuration module.
"""

import pytest
from pathlib import Path

from auditor.config import AuditorConfig, CheckConfig, ScanConfig, load_config
from auditor.exceptions import ValidationError


class TestAuditorConfig:
    """Tests for AuditorConfig."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = AuditorConfig()
        
        assert config.log_level == "INFO"
        assert config.platform == "auto"
        assert config.verbose is False
        assert config.checks.enabled is True
    
    def test_config_with_target_path(self, temp_dir: Path):
        """Test configuration with target path."""
        config = AuditorConfig(target_path=temp_dir)
        
        assert config.target_path == temp_dir.resolve()
    
    def test_invalid_target_path(self):
        """Test configuration with non-existent path."""
        import pydantic
        with pytest.raises((ValidationError, pydantic.ValidationError)):
            AuditorConfig(target_path=Path("/non/existent/path"))
    
    def test_safe_dict_masks_token(self):
        """Test that to_safe_dict excludes or masks sensitive values."""
        config = AuditorConfig()
        # Manually set a token (would normally come from env)
        config.github.token = "ghp_secrettoken123"
        
        safe = config.to_safe_dict()
        
        # Token should either be masked or not present (excluded from serialization)
        github_data = safe.get("github", {})
        token_value = github_data.get("token")
        assert token_value in (None, "***MASKED***"), f"Token should be masked or None, got: {token_value}"


class TestCheckConfig:
    """Tests for CheckConfig."""
    
    def test_default_check_config(self):
        """Test default check configuration."""
        config = CheckConfig()
        
        assert config.enabled is True
        assert config.severity_threshold == "low"
        assert config.custom_patterns == []
    
    def test_custom_patterns_validation(self):
        """Test that empty patterns are filtered."""
        config = CheckConfig(custom_patterns=["valid", "", "  ", "also-valid"])
        
        assert config.custom_patterns == ["valid", "also-valid"]
    
    def test_pattern_length_limit(self):
        """Test that overly long patterns are rejected."""
        with pytest.raises(ValueError, match="too long"):
            CheckConfig(custom_patterns=["x" * 1001])


class TestScanConfig:
    """Tests for ScanConfig."""
    
    def test_default_scan_config(self):
        """Test default scan configuration."""
        config = ScanConfig()
        
        assert config.max_file_size_mb == 10.0
        assert config.max_files == 1000
        assert config.follow_symlinks is False
        assert config.include_hidden is True
    
    def test_max_file_size_bytes(self):
        """Test max file size conversion to bytes."""
        config = ScanConfig(max_file_size_mb=5.0)
        
        assert config.max_file_size_bytes == 5 * 1024 * 1024


class TestLoadConfig:
    """Tests for load_config function."""
    
    def test_load_config_from_yaml(self, temp_dir: Path):
        """Test loading configuration from YAML file."""
        config_content = """
log_level: DEBUG
platform: github_actions
checks:
  enabled: true
  severity_threshold: high
"""
        config_file = temp_dir / "config.yml"
        config_file.write_text(config_content)
        
        config = load_config(config_file)
        
        assert config.log_level == "DEBUG"
        assert config.platform == "github_actions"
        assert config.checks.severity_threshold == "high"
    
    def test_load_config_with_overrides(self, temp_dir: Path):
        """Test loading configuration with overrides."""
        config_content = "log_level: INFO"
        config_file = temp_dir / "config.yml"
        config_file.write_text(config_content)
        
        config = load_config(config_file, log_level="DEBUG")
        
        assert config.log_level == "DEBUG"
