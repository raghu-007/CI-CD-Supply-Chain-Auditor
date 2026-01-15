"""
Tests for parser modules.
"""

import pytest
from pathlib import Path

from auditor.parsers.github_actions import GitHubActionsParser
from auditor.parsers.gitlab_ci import GitLabCIParser
from auditor.parsers.validators import (
    validate_file_path,
    validate_file_size,
    validate_yaml_content,
    validate_yaml_structure,
)
from auditor.exceptions import ValidationError, ParserError


class TestValidators:
    """Tests for parser validators."""
    
    def test_validate_file_path_basic(self, temp_dir: Path):
        """Test basic file path validation."""
        test_file = temp_dir / "test.yml"
        test_file.write_text("test: content")
        
        result = validate_file_path(test_file)
        
        assert result == test_file.resolve()
    
    def test_validate_file_path_traversal(self, temp_dir: Path):
        """Test path traversal detection."""
        malicious_path = temp_dir / ".." / ".." / "etc" / "passwd"
        
        # Should not raise as long as resolved path is valid
        # The check is for when resolved path escapes base_path
        with pytest.raises(ValidationError, match="outside"):
            validate_file_path(malicious_path, base_path=temp_dir)
    
    def test_validate_file_path_symlink_blocked(self, temp_dir: Path):
        """Test symlink blocking."""
        import os
        
        target = temp_dir / "target.txt"
        target.write_text("target content")
        
        link = temp_dir / "link.txt"
        try:
            os.symlink(target, link)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")
        
        with pytest.raises(ValidationError, match="[Ss]ymbolic"):
            validate_file_path(link, allow_symlinks=False)
    
    def test_validate_file_size_within_limit(self, temp_dir: Path):
        """Test file size validation for small file."""
        test_file = temp_dir / "small.txt"
        test_file.write_text("small content")
        
        size = validate_file_size(test_file, max_size_bytes=1024)
        
        assert size == len("small content")
    
    def test_validate_file_size_exceeds_limit(self, temp_dir: Path):
        """Test file size validation for large file."""
        test_file = temp_dir / "large.txt"
        test_file.write_text("x" * 1000)
        
        with pytest.raises(ValidationError, match="exceeds limit"):
            validate_file_size(test_file, max_size_bytes=100)
    
    def test_validate_yaml_content_basic(self):
        """Test basic YAML content validation."""
        content = "key: value\nlist:\n  - item1\n  - item2"
        
        result = validate_yaml_content(content)
        
        assert result == content
    
    def test_validate_yaml_content_empty(self):
        """Test empty YAML content rejection."""
        with pytest.raises(ValidationError, match="empty"):
            validate_yaml_content("")
    
    def test_validate_yaml_structure_depth(self):
        """Test YAML structure depth validation."""
        # Create deeply nested structure
        deep = {"a": {"b": {"c": {"d": {"e": {}}}}}}
        
        # Should pass with enough depth
        validate_yaml_structure(deep, max_depth=10)
        
        # Should fail with limited depth
        with pytest.raises(ValidationError, match="depth"):
            validate_yaml_structure(deep, max_depth=3)


class TestGitHubActionsParser:
    """Tests for GitHub Actions parser."""
    
    def test_parse_basic_workflow(self, temp_dir: Path, sample_github_workflow: str):
        """Test parsing a basic workflow."""
        workflow_file = temp_dir / "workflow.yml"
        workflow_file.write_text(sample_github_workflow)
        
        parser = GitHubActionsParser()
        result = parser.parse(workflow_file)
        
        assert result is not None
        assert result["type"] == "github_actions"
        assert result["name"] == "CI"
        assert "build" in result["jobs"]
    
    def test_parse_triggers(self):
        """Test trigger parsing."""
        parser = GitHubActionsParser()
        
        # String trigger
        data = {"on": "push", "jobs": {}}
        triggers = parser._parse_triggers(data)
        assert "push" in triggers
        
        # List trigger
        data = {"on": ["push", "pull_request"], "jobs": {}}
        triggers = parser._parse_triggers(data)
        assert "push" in triggers
        assert "pull_request" in triggers
    
    def test_parse_permissions(self):
        """Test permission parsing."""
        parser = GitHubActionsParser()
        
        # No permissions
        data = {}
        perms = parser._parse_permissions(data)
        assert perms["defined"] is False
        
        # String permission
        data = {"permissions": "write-all"}
        perms = parser._parse_permissions(data)
        assert perms["defined"] is True
        assert perms["value"] == "write-all"
        assert perms["type"] == "string"
        
        # Granular permissions
        data = {"permissions": {"contents": "read", "issues": "write"}}
        perms = parser._parse_permissions(data)
        assert perms["defined"] is True
        assert perms["type"] == "granular"
    
    def test_parse_action_reference(self):
        """Test action reference parsing."""
        parser = GitHubActionsParser()
        
        # Remote action with tag
        result = parser._parse_action_reference("actions/checkout@v4")
        assert result["type"] == "remote"
        assert result["owner"] == "actions"
        assert result["repo"] == "checkout"
        assert result["version"] == "v4"
        assert result["version_type"] == "semver"
        
        # Remote action with SHA
        sha = "a" * 40
        result = parser._parse_action_reference(f"owner/repo@{sha}")
        assert result["version_type"] == "sha"
        assert result["is_pinned"] is True
        
        # Local action
        result = parser._parse_action_reference("./my-action")
        assert result["type"] == "local"
        assert result["path"] == "./my-action"
        
        # Docker action
        result = parser._parse_action_reference("docker://alpine:3.18")
        assert result["type"] == "docker"
        assert result["image"] == "alpine:3.18"
    
    def test_discover_workflow_files(self, workflow_dir: Path):
        """Test workflow file discovery."""
        from auditor.config import ScanConfig
        
        parser = GitHubActionsParser()
        config = ScanConfig()
        
        files = parser.discover_files(workflow_dir, config)
        
        assert len(files) == 1
        assert files[0].name == "ci.yml"


class TestGitLabCIParser:
    """Tests for GitLab CI parser."""
    
    def test_parse_basic_pipeline(self, temp_dir: Path, sample_gitlab_ci: str):
        """Test parsing a basic GitLab CI pipeline."""
        ci_file = temp_dir / ".gitlab-ci.yml"
        ci_file.write_text(sample_gitlab_ci)
        
        parser = GitLabCIParser()
        result = parser.parse(ci_file)
        
        assert result is not None
        assert result["type"] == "gitlab_ci"
        assert "build" in result["stages"]
        assert "test" in result["stages"]
        assert "build" in result["jobs"]
        assert "test" in result["jobs"]
    
    def test_parse_variables(self):
        """Test variable parsing."""
        parser = GitLabCIParser()
        
        variables = {
            "SIMPLE": "value",
            "EXPANDED": {"value": "expanded_value", "description": "A variable"},
        }
        
        result = parser._parse_variables(variables)
        
        assert result["SIMPLE"]["value"] == "value"
        assert result["EXPANDED"]["value"] == "expanded_value"
        assert result["EXPANDED"]["description"] == "A variable"
