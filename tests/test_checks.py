"""
Tests for security check modules.
"""

import pytest
from pathlib import Path

from auditor.checks.secrets import SecretsCheck
from auditor.checks.permissions import PermissionsCheck
from auditor.checks.actions import ActionsCheck
from auditor.checks.runners import RunnersCheck
from auditor.checks.dependencies import DependenciesCheck
from auditor.checks.slsa import SLSACheck
from auditor.config import AuditorConfig
from auditor.core.severity import Severity


class TestSecretsCheck:
    """Tests for secrets detection check."""
    
    @pytest.fixture
    def check(self):
        return SecretsCheck()
    
    @pytest.fixture
    def config(self):
        return AuditorConfig()
    
    def test_detect_hardcoded_token(self, check, config):
        """Test detection of hardcoded GitHub token."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "env": {
                "TOKEN": {
                    "value": "ghp_1234567890abcdefghij1234567890abcdefgh",
                    "uses_secret": False,
                }
            },
            "jobs": {},
        }]
        
        findings = check.run(parsed_files, config)
        
        assert len(findings) > 0
        assert any("token" in f.title.lower() for f in findings)
    
    def test_safe_secret_usage(self, check, config):
        """Test that proper secrets usage is not flagged."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "env": {
                "TOKEN": {
                    "value": "${{ secrets.MY_TOKEN }}",
                    "uses_secret": True,
                }
            },
            "jobs": {},
        }]
        
        findings = check.run(parsed_files, config)
        
        # Should not have findings about this specific variable
        assert not any(
            "hardcoded" in f.title.lower() and "TOKEN" in str(f.metadata)
            for f in findings
        )
    
    def test_detect_secret_logging(self, check, config):
        """Test detection of potential secret logging."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "env": {},
            "jobs": {
                "build": {
                    "steps": [{
                        "type": "run",
                        "name": "Debug",
                        "run": "echo ${{ secrets.MY_SECRET }}",
                    }]
                }
            },
        }]
        
        findings = check.run(parsed_files, config)
        
        assert any("log" in f.title.lower() for f in findings)


class TestPermissionsCheck:
    """Tests for permissions analysis check."""
    
    @pytest.fixture
    def check(self):
        return PermissionsCheck()
    
    @pytest.fixture
    def config(self):
        return AuditorConfig()
    
    def test_detect_write_all(self, check, config):
        """Test detection of write-all permissions."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "permissions": {
                "defined": True,
                "value": "write-all",
                "type": "string",
            },
            "jobs": {},
        }]
        
        findings = check.run(parsed_files, config)
        
        assert len(findings) > 0
        assert any("write-all" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)
    
    def test_proper_permissions(self, check, config):
        """Test that proper permissions don't trigger critical findings."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "permissions": {
                "defined": True,
                "value": {"contents": "read"},
                "type": "granular",
            },
            "jobs": {},
        }]
        
        findings = check.run(parsed_files, config)
        
        # Should not have critical findings
        assert not any(f.severity == Severity.CRITICAL for f in findings)


class TestActionsCheck:
    """Tests for third-party actions check."""
    
    @pytest.fixture
    def check(self):
        return ActionsCheck()
    
    @pytest.fixture
    def config(self):
        return AuditorConfig()
    
    def test_detect_unpinned_action(self, check, config):
        """Test detection of unpinned action."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "triggers": {},
            "jobs": {
                "build": {
                    "steps": [{
                        "type": "action",
                        "name": "Checkout",
                        "action": {
                            "type": "remote",
                            "raw": "some-owner/some-action@main",
                            "owner": "some-owner",
                            "repo": "some-action",
                            "version": "main",
                            "version_type": "branch",
                            "is_pinned": False,
                        },
                        "with": {},
                    }]
                }
            },
        }]
        
        findings = check.run(parsed_files, config)
        
        assert len(findings) > 0
        assert any("branch" in f.title.lower() or "pinned" in f.title.lower() for f in findings)
    
    def test_detect_injection_vulnerability(self, check, config):
        """Test detection of script injection."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "triggers": {},
            "jobs": {
                "build": {
                    "steps": [{
                        "type": "run",
                        "name": "Process title",
                        "run": "echo ${{ github.event.issue.title }}",
                    }]
                }
            },
        }]
        
        findings = check.run(parsed_files, config)
        
        assert len(findings) > 0
        assert any("injection" in f.title.lower() for f in findings)


class TestRunnersCheck:
    """Tests for runner configuration check."""
    
    @pytest.fixture
    def check(self):
        return RunnersCheck()
    
    @pytest.fixture
    def config(self):
        return AuditorConfig()
    
    def test_detect_self_hosted_with_pr(self, check, config):
        """Test detection of self-hosted runner with PR trigger."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "triggers": {"pull_request": {}},
            "jobs": {
                "build": {
                    "runs_on": {
                        "type": "array",
                        "value": ["self-hosted", "linux"],
                        "self_hosted": True,
                    },
                    "container": None,
                    "services": {},
                    "steps": [],
                }
            },
        }]
        
        findings = check.run(parsed_files, config)
        
        assert len(findings) > 0
        assert any("self-hosted" in f.title.lower() for f in findings)
        assert any(f.severity >= Severity.HIGH for f in findings)


class TestDependenciesCheck:
    """Tests for dependency security check."""
    
    @pytest.fixture
    def check(self):
        return DependenciesCheck()
    
    @pytest.fixture
    def config(self):
        return AuditorConfig()
    
    def test_detect_curl_pipe(self, check, config):
        """Test detection of curl pipe to shell."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "jobs": {
                "build": {
                    "steps": [{
                        "type": "run",
                        "name": "Install",
                        "run": "curl -sSL https://example.com/install.sh | bash",
                    }]
                }
            },
        }]
        
        findings = check.run(parsed_files, config)
        
        assert len(findings) > 0
        assert any("curl" in f.title.lower() or "pipe" in f.title.lower() for f in findings)


class TestSLSACheck:
    """Tests for SLSA compliance check."""
    
    @pytest.fixture
    def check(self):
        return SLSACheck()
    
    @pytest.fixture
    def config(self):
        return AuditorConfig()
    
    def test_assess_basic_workflow(self, check, config):
        """Test SLSA assessment of basic workflow."""
        parsed_files = [{
            "type": "github_actions",
            "file_path": "test.yml",
            "name": "build",
            "triggers": {"push": {}},
            "jobs": {
                "build": {
                    "runs_on": {"self_hosted": False},
                    "container": None,
                    "steps": [{
                        "type": "run",
                        "run": "make build",
                    }],
                }
            },
            "raw": {},
        }]
        
        findings = check.run(parsed_files, config)
        
        # Should have findings about SLSA level
        assert len(findings) > 0
        assert any("slsa" in f.title.lower() for f in findings)
