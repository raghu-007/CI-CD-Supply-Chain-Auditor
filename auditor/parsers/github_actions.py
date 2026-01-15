"""
GitHub Actions workflow parser.

Parses GitHub Actions YAML workflow files and extracts structured data
for security analysis. Handles all common workflow patterns and syntax.

Reference: https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from auditor.constants import GITHUB_WORKFLOWS_DIR
from auditor.exceptions import ParserError
from auditor.logging_config import get_logger
from auditor.parsers.base import BaseParser

logger = get_logger("parsers.github_actions")


class GitHubActionsParser(BaseParser):
    """
    Parser for GitHub Actions workflow files.
    
    Parses .github/workflows/*.yml files and extracts:
    - Workflow metadata (name, triggers)
    - Job configurations
    - Step definitions
    - Permissions
    - Environment variables
    - Secrets usage
    """
    
    @property
    def name(self) -> str:
        return "GitHub Actions"
    
    @property
    def file_patterns(self) -> list[str]:
        return ["*.yml", "*.yaml"]
    
    @property
    def directories(self) -> list[str]:
        return [GITHUB_WORKFLOWS_DIR]
    
    def _parse_content(
        self,
        content: str,
        file_path: Path,
    ) -> dict[str, Any] | None:
        """Parse GitHub Actions workflow YAML."""
        data = self._load_yaml_safely(content)
        
        if data is None:
            return None
        
        if not isinstance(data, dict):
            raise ParserError(
                "Workflow must be a YAML mapping",
                file_path=str(file_path),
            )
        
        # Validate it looks like a workflow file
        if not self._is_workflow_file(data):
            logger.debug(f"Skipping non-workflow file: {file_path.name}")
            return None
        
        # Extract structured data
        return {
            "type": "github_actions",
            "file_path": str(file_path),
            "name": data.get("name", file_path.stem),
            "triggers": self._parse_triggers(data),
            "permissions": self._parse_permissions(data),
            "env": self._parse_env(data.get("env", {})),
            "defaults": data.get("defaults", {}),
            "concurrency": data.get("concurrency"),
            "jobs": self._parse_jobs(data.get("jobs", {})),
            "raw": data,  # Keep raw for advanced checks
        }
    
    def _is_workflow_file(self, data: dict[str, Any]) -> bool:
        """Check if data looks like a GitHub Actions workflow."""
        # Must have at least 'on' trigger or 'jobs'
        has_trigger = "on" in data or "true" in data  # 'on' can be parsed as True
        has_jobs = "jobs" in data
        
        return has_trigger or has_jobs
    
    def _parse_triggers(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse workflow triggers (on: section)."""
        triggers = {}
        
        # Handle 'on' key (can be parsed as boolean True in YAML)
        on_data = data.get("on") or data.get(True)
        
        if on_data is None:
            return triggers
        
        # String trigger (e.g., on: push)
        if isinstance(on_data, str):
            triggers[on_data] = {}
        
        # List of triggers (e.g., on: [push, pull_request])
        elif isinstance(on_data, list):
            for trigger in on_data:
                if isinstance(trigger, str):
                    triggers[trigger] = {}
        
        # Dict of triggers with configurations
        elif isinstance(on_data, dict):
            triggers = dict(on_data)
        
        return triggers
    
    def _parse_permissions(
        self,
        data: dict[str, Any],
    ) -> dict[str, Any]:
        """Parse permissions at workflow level."""
        perms = data.get("permissions")
        
        if perms is None:
            return {"defined": False, "value": None}
        
        if isinstance(perms, str):
            # e.g., permissions: read-all
            return {"defined": True, "value": perms, "type": "string"}
        
        if isinstance(perms, dict):
            return {"defined": True, "value": perms, "type": "granular"}
        
        return {"defined": True, "value": str(perms), "type": "unknown"}
    
    def _parse_env(self, env_data: dict[str, Any]) -> dict[str, Any]:
        """Parse environment variables."""
        result = {}
        
        if not isinstance(env_data, dict):
            return result
        
        for key, value in env_data.items():
            result[str(key)] = {
                "value": str(value) if value is not None else "",
                "uses_secret": self._uses_secret(value),
                "uses_expression": self._uses_expression(value),
            }
        
        return result
    
    def _parse_jobs(self, jobs_data: dict[str, Any]) -> dict[str, Any]:
        """Parse all jobs in the workflow."""
        result = {}
        
        if not isinstance(jobs_data, dict):
            return result
        
        for job_id, job_config in jobs_data.items():
            if not isinstance(job_config, dict):
                continue
            
            result[str(job_id)] = self._parse_job(job_id, job_config)
        
        return result
    
    def _parse_job(self, job_id: str, job_config: dict[str, Any]) -> dict[str, Any]:
        """Parse a single job configuration."""
        return {
            "id": job_id,
            "name": job_config.get("name", job_id),
            "runs_on": self._parse_runs_on(job_config.get("runs-on")),
            "permissions": self._parse_permissions(job_config),
            "env": self._parse_env(job_config.get("env", {})),
            "if_condition": job_config.get("if"),
            "needs": self._normalize_list(job_config.get("needs", [])),
            "outputs": job_config.get("outputs", {}),
            "container": job_config.get("container"),
            "services": job_config.get("services", {}),
            "steps": self._parse_steps(job_config.get("steps", [])),
            "timeout_minutes": job_config.get("timeout-minutes"),
            "strategy": job_config.get("strategy"),
            "continue_on_error": job_config.get("continue-on-error", False),
        }
    
    def _parse_runs_on(self, runs_on: Any) -> dict[str, Any]:
        """Parse runs-on configuration."""
        if runs_on is None:
            return {"type": "undefined", "value": None}
        
        if isinstance(runs_on, str):
            is_self_hosted = "self-hosted" in runs_on.lower()
            return {
                "type": "string",
                "value": runs_on,
                "self_hosted": is_self_hosted,
                "uses_expression": self._uses_expression(runs_on),
            }
        
        if isinstance(runs_on, list):
            is_self_hosted = any(
                "self-hosted" in str(r).lower() for r in runs_on
            )
            return {
                "type": "array",
                "value": runs_on,
                "self_hosted": is_self_hosted,
            }
        
        # Could be a matrix expression
        return {
            "type": "complex",
            "value": runs_on,
            "self_hosted": False,
        }
    
    def _parse_steps(self, steps_data: list[Any]) -> list[dict[str, Any]]:
        """Parse workflow steps."""
        result = []
        
        if not isinstance(steps_data, list):
            return result
        
        for idx, step in enumerate(steps_data):
            if not isinstance(step, dict):
                continue
            
            parsed_step = self._parse_step(step, idx)
            result.append(parsed_step)
        
        return result
    
    def _parse_step(self, step: dict[str, Any], index: int) -> dict[str, Any]:
        """Parse a single step."""
        step_id = step.get("id", f"step_{index}")
        
        # Determine step type
        if "uses" in step:
            step_type = "action"
            action_ref = str(step["uses"])
        elif "run" in step:
            step_type = "run"
            action_ref = None
        else:
            step_type = "unknown"
            action_ref = None
        
        parsed = {
            "index": index,
            "id": step_id,
            "name": step.get("name", step_id),
            "type": step_type,
            "if_condition": step.get("if"),
            "env": self._parse_env(step.get("env", {})),
            "continue_on_error": step.get("continue-on-error", False),
            "timeout_minutes": step.get("timeout-minutes"),
            "working_directory": step.get("working-directory"),
        }
        
        if step_type == "action":
            parsed["uses"] = action_ref
            parsed["action"] = self._parse_action_reference(action_ref)
            parsed["with"] = self._parse_with_inputs(step.get("with", {}))
        
        elif step_type == "run":
            run_content = step.get("run", "")
            parsed["run"] = str(run_content)
            parsed["shell"] = step.get("shell")
            parsed["run_analysis"] = self._analyze_run_content(run_content)
        
        return parsed
    
    def _parse_action_reference(self, ref: str) -> dict[str, Any]:
        """Parse an action reference (uses: field)."""
        if not ref:
            return {"type": "unknown", "raw": ref}
        
        # Docker reference (docker://...)
        if ref.startswith("docker://"):
            return {
                "type": "docker",
                "raw": ref,
                "image": ref[9:],  # Remove docker:// prefix
            }
        
        # Local action (./)
        if ref.startswith("./"):
            return {
                "type": "local",
                "raw": ref,
                "path": ref,
            }
        
        # Remote action (owner/repo@ref or owner/repo/path@ref)
        if "@" in ref:
            parts = ref.split("@", 1)
            action_path = parts[0]
            version = parts[1] if len(parts) > 1 else None
            
            path_parts = action_path.split("/")
            owner = path_parts[0] if path_parts else None
            repo = path_parts[1] if len(path_parts) > 1 else None
            
            # Check if version is a SHA, tag, or branch
            version_type = "unknown"
            is_pinned = False
            
            if version:
                if len(version) == 40 and all(c in "0123456789abcdef" for c in version):
                    version_type = "sha"
                    is_pinned = True
                elif version.startswith("v") and any(c.isdigit() for c in version):
                    version_type = "semver"
                    is_pinned = False  # Can float
                else:
                    version_type = "branch"
                    is_pinned = False
            
            return {
                "type": "remote",
                "raw": ref,
                "owner": owner,
                "repo": repo,
                "path": "/".join(path_parts[2:]) if len(path_parts) > 2 else None,
                "version": version,
                "version_type": version_type,
                "is_pinned": is_pinned,
            }
        
        return {"type": "unknown", "raw": ref}
    
    def _parse_with_inputs(self, with_data: dict[str, Any]) -> dict[str, Any]:
        """Parse action inputs (with: field)."""
        result = {}
        
        if not isinstance(with_data, dict):
            return result
        
        for key, value in with_data.items():
            str_value = str(value) if value is not None else ""
            result[str(key)] = {
                "value": str_value,
                "uses_secret": self._uses_secret(value),
                "uses_expression": self._uses_expression(value),
            }
        
        return result
    
    def _analyze_run_content(self, content: Any) -> dict[str, Any]:
        """Analyze shell script content for security issues."""
        if content is None:
            return {"has_content": False}
        
        content_str = str(content)
        
        return {
            "has_content": bool(content_str.strip()),
            "uses_expression": self._uses_expression(content_str),
            "uses_secret": self._uses_secret(content_str),
            "line_count": content_str.count("\n") + 1,
            "has_curl_pipe": self._has_curl_pipe(content_str),
            "has_eval": "eval " in content_str or "eval(" in content_str,
        }
    
    def _uses_secret(self, value: Any) -> bool:
        """Check if a value references secrets."""
        if value is None:
            return False
        return "${{ secrets." in str(value)
    
    def _uses_expression(self, value: Any) -> bool:
        """Check if a value uses GitHub Actions expression syntax."""
        if value is None:
            return False
        return "${{" in str(value)
    
    def _has_curl_pipe(self, content: str) -> bool:
        """Check for potentially dangerous curl|bash patterns."""
        dangerous_patterns = [
            "curl",
            "wget",
        ]
        pipe_patterns = [
            "| sh",
            "| bash",
            "| zsh",
            "|sh",
            "|bash",
            "|zsh",
            "| sudo",
            "|sudo",
        ]
        
        content_lower = content.lower()
        has_download = any(p in content_lower for p in dangerous_patterns)
        has_pipe = any(p in content_lower for p in pipe_patterns)
        
        return has_download and has_pipe
    
    def _normalize_list(self, value: Any) -> list[str]:
        """Normalize a value to a list of strings."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]
