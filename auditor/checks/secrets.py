"""
Secrets exposure detection check.

Detects hardcoded secrets, exposed credentials, and insecure
secret handling patterns in CI/CD pipeline configurations.

CWE References:
- CWE-798: Use of Hard-coded Credentials
- CWE-259: Use of Hard-coded Password
- CWE-522: Insufficiently Protected Credentials
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from auditor.checks.base import BaseCheck
from auditor.constants import SECRET_PATTERNS, SECRET_KEYWORDS
from auditor.core.result import Finding
from auditor.core.severity import Severity

if TYPE_CHECKING:
    from auditor.config import AuditorConfig


class SecretsCheck(BaseCheck):
    """
    Check for exposed secrets and insecure credential handling.
    
    Detects:
    - Hardcoded API keys, tokens, and passwords
    - Secrets in environment variable values
    - Insecure secret interpolation patterns
    - Secrets logged or exposed in outputs
    """
    
    @property
    def id(self) -> str:
        return "secrets-001"
    
    @property
    def name(self) -> str:
        return "Secrets Exposure Detection"
    
    @property
    def description(self) -> str:
        return (
            "Detects hardcoded secrets, exposed credentials, and "
            "insecure secret handling patterns in CI/CD pipelines."
        )
    
    @property
    def default_severity(self) -> Severity:
        return Severity.CRITICAL
    
    @property
    def references(self) -> tuple[str, ...]:
        return (
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
            "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
        )
    
    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return ("CWE-798", "CWE-259", "CWE-522")
    
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """Run secrets exposure checks."""
        findings: list[Finding] = []
        
        for file_data in parsed_files:
            file_type = file_data.get("type", "unknown")
            file_path = file_data.get("file_path", "unknown")
            
            if file_type == "github_actions":
                findings.extend(self._check_github_actions(file_data, file_path))
            elif file_type == "gitlab_ci":
                findings.extend(self._check_gitlab_ci(file_data, file_path))
        
        return findings
    
    def _check_github_actions(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check GitHub Actions workflow for secrets issues."""
        findings: list[Finding] = []
        
        # Check workflow-level environment variables
        env_vars = file_data.get("env", {})
        findings.extend(self._check_env_vars(env_vars, file_path, "workflow"))
        
        # Check each job
        jobs = file_data.get("jobs", {})
        for job_id, job in jobs.items():
            # Check job-level env vars
            job_env = job.get("env", {})
            findings.extend(
                self._check_env_vars(job_env, file_path, f"job:{job_id}")
            )
            
            # Check steps
            for step in job.get("steps", []):
                step_name = step.get("name", step.get("id", "unnamed"))
                
                # Check step env vars
                step_env = step.get("env", {})
                findings.extend(
                    self._check_env_vars(step_env, file_path, f"step:{step_name}")
                )
                
                # Check action inputs (with:)
                if step.get("type") == "action":
                    with_inputs = step.get("with", {})
                    findings.extend(
                        self._check_action_inputs(
                            with_inputs, file_path, step_name
                        )
                    )
                
                # Check run scripts
                if step.get("type") == "run":
                    run_content = step.get("run", "")
                    findings.extend(
                        self._check_run_script(run_content, file_path, step_name)
                    )
        
        return findings
    
    def _check_gitlab_ci(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check GitLab CI pipeline for secrets issues."""
        findings: list[Finding] = []
        
        # Check global variables
        variables = file_data.get("variables", {})
        for var_name, var_data in variables.items():
            if isinstance(var_data, dict):
                value = var_data.get("value", "")
            else:
                value = str(var_data)
            
            findings.extend(
                self._check_single_value(value, file_path, f"variable:{var_name}")
            )
        
        # Check jobs
        jobs = file_data.get("jobs", {})
        for job_name, job in jobs.items():
            # Check job variables
            job_vars = job.get("variables", {})
            for var_name, var_data in job_vars.items():
                if isinstance(var_data, dict):
                    value = var_data.get("value", "")
                else:
                    value = str(var_data)
                
                findings.extend(
                    self._check_single_value(
                        value, file_path, f"job:{job_name}:variable:{var_name}"
                    )
                )
            
            # Check scripts
            for script_type in ["script", "before_script", "after_script"]:
                scripts = job.get(script_type, [])
                for script in scripts:
                    findings.extend(
                        self._check_run_script(script, file_path, f"{job_name}:{script_type}")
                    )
        
        return findings
    
    def _check_env_vars(
        self,
        env_vars: dict[str, Any],
        file_path: str,
        context: str,
    ) -> list[Finding]:
        """Check environment variables for secrets."""
        findings: list[Finding] = []
        
        for var_name, var_data in env_vars.items():
            if isinstance(var_data, dict):
                value = var_data.get("value", "")
                uses_secret = var_data.get("uses_secret", False)
            else:
                value = str(var_data)
                uses_secret = "${{ secrets." in value
            
            # Skip if properly using secrets context
            if uses_secret and self._is_safe_secret_usage(value):
                continue
            
            # Check for hardcoded secrets
            findings.extend(
                self._check_single_value(value, file_path, f"{context}:env:{var_name}")
            )
            
            # Warn about sensitive variable names without secrets
            if self._is_sensitive_var_name(var_name) and not uses_secret:
                if value and not value.startswith("$"):  # Not a variable reference
                    findings.append(self.create_finding(
                        title=f"Sensitive variable '{var_name}' may contain hardcoded secret",
                        description=(
                            f"The environment variable '{var_name}' has a name suggesting "
                            f"it contains sensitive data, but it's not using the secrets context. "
                            f"Consider using GitHub Secrets or environment variables."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        remediation=(
                            f"Store the value in GitHub Secrets and reference it as "
                            f"'${{{{ secrets.{var_name.upper()} }}}}'"
                        ),
                        metadata={"context": context, "variable": var_name},
                    ))
        
        return findings
    
    def _check_action_inputs(
        self,
        inputs: dict[str, Any],
        file_path: str,
        step_name: str,
    ) -> list[Finding]:
        """Check action inputs for exposed secrets."""
        findings: list[Finding] = []
        
        for input_name, input_data in inputs.items():
            if isinstance(input_data, dict):
                value = input_data.get("value", "")
            else:
                value = str(input_data)
            
            findings.extend(
                self._check_single_value(value, file_path, f"step:{step_name}:with:{input_name}")
            )
        
        return findings
    
    def _check_run_script(
        self,
        script: str,
        file_path: str,
        context: str,
    ) -> list[Finding]:
        """Check a run script for exposed secrets."""
        findings: list[Finding] = []
        
        if not script:
            return findings
        
        # Check for hardcoded secrets in script
        for pattern_name, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(script)
            if matches:
                # Don't include the actual match in the finding!
                findings.append(self.create_finding(
                    title=f"Potential {pattern_name.replace('_', ' ')} detected in script",
                    description=(
                        f"A pattern matching '{pattern_name}' was detected in a run script. "
                        f"Hardcoded secrets in scripts are a security risk."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    remediation=(
                        "Store secrets in GitHub Secrets or your CI/CD platform's secure "
                        "secrets storage, and reference them using the secrets context."
                    ),
                    metadata={"context": context, "pattern": pattern_name},
                ))
        
        # Check for echo/print of secrets
        if self._might_log_secrets(script):
            findings.append(self.create_finding(
                title="Script may be logging secrets",
                description=(
                    "The script appears to echo or print values that might contain secrets. "
                    "This could expose secrets in CI/CD logs."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                remediation="Avoid printing secret values. Use masking if debugging is needed.",
                metadata={"context": context},
            ))
        
        return findings
    
    def _check_single_value(
        self,
        value: str,
        file_path: str,
        context: str,
    ) -> list[Finding]:
        """Check a single value for hardcoded secrets."""
        findings: list[Finding] = []
        
        if not value:
            return findings
        
        for pattern_name, pattern in SECRET_PATTERNS.items():
            if pattern.search(value):
                findings.append(self.create_finding(
                    title=f"Potential hardcoded {pattern_name.replace('_', ' ')}",
                    description=(
                        f"A value matching the pattern for '{pattern_name}' was detected. "
                        f"This may be a hardcoded secret that should be stored securely."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    remediation=(
                        "Store this value in your CI/CD platform's secure secrets storage "
                        "and reference it using the appropriate syntax."
                    ),
                    metadata={"context": context, "pattern": pattern_name},
                ))
        
        return findings
    
    def _is_safe_secret_usage(self, value: str) -> bool:
        """Check if a secret is being used safely."""
        # Safe if only referencing secrets context
        if value == "${{ secrets." or not value:
            return False
        
        # Check if the entire value is just a secret reference
        secret_ref_pattern = r"^\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}$"
        return bool(re.match(secret_ref_pattern, value, re.IGNORECASE))
    
    def _is_sensitive_var_name(self, name: str) -> bool:
        """Check if a variable name suggests sensitive content."""
        name_lower = name.lower()
        return any(kw in name_lower for kw in SECRET_KEYWORDS)
    
    def _might_log_secrets(self, script: str) -> bool:
        """Check if a script might be logging secrets."""
        script_lower = script.lower()
        
        logging_commands = ["echo", "print", "cat", "printf", "write-host"]
        secret_refs = ["${{ secrets.", "${secrets.", "$secrets"]
        
        has_logging = any(cmd in script_lower for cmd in logging_commands)
        has_secret_ref = any(ref.lower() in script_lower for ref in secret_refs)
        
        return has_logging and has_secret_ref
