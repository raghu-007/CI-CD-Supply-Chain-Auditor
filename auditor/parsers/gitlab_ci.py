"""
GitLab CI pipeline parser.

Parses .gitlab-ci.yml files and extracts structured data for security analysis.
This is a basic implementation that can be expanded for full GitLab CI support.

Reference: https://docs.gitlab.com/ee/ci/yaml/
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from auditor.logging_config import get_logger
from auditor.parsers.base import BaseParser

logger = get_logger("parsers.gitlab_ci")


class GitLabCIParser(BaseParser):
    """
    Parser for GitLab CI pipeline files.
    
    Parses .gitlab-ci.yml files at repository root and extracts:
    - Pipeline configuration
    - Job definitions
    - Scripts and commands
    - Variables and secrets usage
    
    Note: This is a basic implementation. Full GitLab CI support
    should include handling of includes, extends, and anchors.
    """
    
    @property
    def name(self) -> str:
        return "GitLab CI"
    
    @property
    def file_patterns(self) -> list[str]:
        return [".gitlab-ci.yml", ".gitlab-ci.yaml"]
    
    @property
    def directories(self) -> list[str]:
        return ["."]  # GitLab CI file is at root
    
    def _parse_content(
        self,
        content: str,
        file_path: Path,
    ) -> dict[str, Any] | None:
        """Parse GitLab CI pipeline YAML."""
        data = self._load_yaml_safely(content)
        
        if data is None:
            return None
        
        if not isinstance(data, dict):
            return None
        
        # Check if it looks like a GitLab CI file
        if not self._is_gitlab_ci_file(data):
            logger.debug(f"Skipping non-GitLab CI file: {file_path.name}")
            return None
        
        # Extract global configuration
        global_config = self._extract_global_config(data)
        
        # Extract jobs (keys that don't start with . and aren't reserved)
        jobs = self._extract_jobs(data)
        
        return {
            "type": "gitlab_ci",
            "file_path": str(file_path),
            "stages": data.get("stages", []),
            "variables": self._parse_variables(data.get("variables", {})),
            "default": data.get("default", {}),
            "include": self._parse_includes(data.get("include", [])),
            "workflow": data.get("workflow", {}),
            "global_config": global_config,
            "jobs": jobs,
            "raw": data,
        }
    
    def _is_gitlab_ci_file(self, data: dict[str, Any]) -> bool:
        """Check if data looks like a GitLab CI pipeline."""
        # GitLab CI files typically have stages, jobs, or other keywords
        gitlab_keywords = {
            "stages", "variables", "default", "include", "workflow",
            "before_script", "after_script", "image", "services", "cache",
        }
        
        # Check for GitLab keywords
        if any(key in data for key in gitlab_keywords):
            return True
        
        # Check for job-like definitions (dicts with script key)
        for key, value in data.items():
            if isinstance(value, dict) and "script" in value:
                return True
        
        return False
    
    def _extract_global_config(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract global configuration settings."""
        global_keys = {
            "image", "services", "before_script", "after_script",
            "cache", "artifacts", "retry", "timeout", "interruptible",
        }
        
        return {
            key: data[key]
            for key in global_keys
            if key in data
        }
    
    def _extract_jobs(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract job definitions from the pipeline."""
        reserved_keys = {
            "stages", "variables", "default", "include", "workflow",
            "before_script", "after_script", "image", "services",
            "cache", "artifacts", "retry", "timeout", "interruptible",
        }
        
        jobs = {}
        
        for key, value in data.items():
            # Skip reserved keys
            if key in reserved_keys:
                continue
            
            # Skip hidden jobs (start with .)
            if key.startswith("."):
                continue
            
            # Must be a dict to be a job
            if not isinstance(value, dict):
                continue
            
            jobs[key] = self._parse_job(key, value)
        
        return jobs
    
    def _parse_job(self, job_name: str, job_config: dict[str, Any]) -> dict[str, Any]:
        """Parse a single job configuration."""
        return {
            "name": job_name,
            "stage": job_config.get("stage", "test"),
            "image": job_config.get("image"),
            "services": job_config.get("services", []),
            "variables": self._parse_variables(job_config.get("variables", {})),
            "script": self._normalize_script(job_config.get("script", [])),
            "before_script": self._normalize_script(job_config.get("before_script", [])),
            "after_script": self._normalize_script(job_config.get("after_script", [])),
            "rules": job_config.get("rules", []),
            "only": job_config.get("only"),
            "except": job_config.get("except"),
            "when": job_config.get("when", "on_success"),
            "allow_failure": job_config.get("allow_failure", False),
            "needs": job_config.get("needs", []),
            "dependencies": job_config.get("dependencies"),
            "artifacts": job_config.get("artifacts", {}),
            "cache": job_config.get("cache", {}),
            "environment": job_config.get("environment"),
            "secrets": job_config.get("secrets", {}),
            "extends": job_config.get("extends"),
            "tags": job_config.get("tags", []),
        }
    
    def _parse_variables(self, variables: dict[str, Any] | list) -> dict[str, Any]:
        """Parse variable definitions."""
        result = {}
        
        if isinstance(variables, dict):
            for key, value in variables.items():
                if isinstance(value, dict):
                    # Expanded syntax with value and options
                    result[str(key)] = {
                        "value": str(value.get("value", "")),
                        "description": value.get("description"),
                        "expand": value.get("expand", True),
                        "uses_secret": self._might_be_secret(key, value),
                    }
                else:
                    result[str(key)] = {
                        "value": str(value) if value is not None else "",
                        "uses_secret": self._might_be_secret(key, value),
                    }
        
        return result
    
    def _parse_includes(self, includes: Any) -> list[dict[str, Any]]:
        """Parse include directives."""
        result = []
        
        if isinstance(includes, str):
            includes = [includes]
        
        if not isinstance(includes, list):
            return result
        
        for include in includes:
            if isinstance(include, str):
                result.append({"type": "local", "path": include})
            elif isinstance(include, dict):
                if "local" in include:
                    result.append({"type": "local", "path": include["local"]})
                elif "remote" in include:
                    result.append({"type": "remote", "url": include["remote"]})
                elif "project" in include:
                    result.append({
                        "type": "project",
                        "project": include["project"],
                        "file": include.get("file"),
                        "ref": include.get("ref"),
                    })
                elif "template" in include:
                    result.append({"type": "template", "name": include["template"]})
        
        return result
    
    def _normalize_script(self, script: Any) -> list[str]:
        """Normalize script to list of commands."""
        if script is None:
            return []
        if isinstance(script, str):
            return [script]
        if isinstance(script, list):
            return [str(cmd) for cmd in script]
        return [str(script)]
    
    def _might_be_secret(self, key: str, value: Any) -> bool:
        """Check if a variable might contain secrets."""
        secret_keywords = {
            "password", "secret", "token", "key", "auth",
            "credential", "api_key", "apikey", "private",
        }
        
        key_lower = key.lower()
        
        # Check key name
        if any(kw in key_lower for kw in secret_keywords):
            return True
        
        # Check for CI/CD variable syntax
        if isinstance(value, str):
            if value.startswith("$") or "${" in value:
                return True
        
        return False
