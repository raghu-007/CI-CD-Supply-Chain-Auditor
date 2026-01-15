"""
Permissions analysis check.

Analyzes workflow and job permissions for overly permissive settings
that could allow privilege escalation or unauthorized actions.

CWE References:
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auditor.checks.base import BaseCheck
from auditor.constants import DANGEROUS_PERMISSIONS, SENSITIVE_PERMISSIONS
from auditor.core.result import Finding
from auditor.core.severity import Severity

if TYPE_CHECKING:
    from auditor.config import AuditorConfig


class PermissionsCheck(BaseCheck):
    """
    Check for overly permissive workflow permissions.
    
    Detects:
    - write-all permissions
    - Missing permission restrictions
    - Overly broad token permissions
    - Permissions not following least privilege
    """
    
    @property
    def id(self) -> str:
        return "permissions-001"
    
    @property
    def name(self) -> str:
        return "Permissions Analysis"
    
    @property
    def description(self) -> str:
        return (
            "Analyzes workflow permissions for overly permissive settings "
            "that violate the principle of least privilege."
        )
    
    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH
    
    @property
    def references(self) -> tuple[str, ...]:
        return (
            "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
            "https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs",
        )
    
    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return ("CWE-250", "CWE-269")
    
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """Run permissions checks."""
        findings: list[Finding] = []
        
        for file_data in parsed_files:
            file_type = file_data.get("type", "unknown")
            file_path = file_data.get("file_path", "unknown")
            
            if file_type == "github_actions":
                findings.extend(self._check_github_actions(file_data, file_path))
        
        return findings
    
    def _check_github_actions(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check GitHub Actions workflow for permission issues."""
        findings: list[Finding] = []
        
        # Check workflow-level permissions
        workflow_perms = file_data.get("permissions", {})
        findings.extend(
            self._analyze_permissions(workflow_perms, file_path, "workflow")
        )
        
        # Check if workflow has no permissions defined
        if not workflow_perms.get("defined", False):
            # Check if any job has elevated access needs
            jobs = file_data.get("jobs", {})
            has_sensitive_operations = self._has_sensitive_operations(jobs)
            
            if has_sensitive_operations:
                findings.append(self.create_finding(
                    title="Workflow missing explicit permissions",
                    description=(
                        "This workflow does not define explicit permissions but appears to "
                        "perform sensitive operations. Without explicit permissions, the "
                        "GITHUB_TOKEN receives default permissions which may be overly broad."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    remediation=(
                        "Add a 'permissions' block at the workflow level with minimal required "
                        "permissions. For read-only operations, use:\n"
                        "permissions:\n  contents: read"
                    ),
                ))
        
        # Check job-level permissions
        jobs = file_data.get("jobs", {})
        for job_id, job in jobs.items():
            job_perms = job.get("permissions", {})
            findings.extend(
                self._analyze_permissions(job_perms, file_path, f"job:{job_id}")
            )
        
        return findings
    
    def _analyze_permissions(
        self,
        perms_data: dict[str, Any],
        file_path: str,
        context: str,
    ) -> list[Finding]:
        """Analyze a permissions block for security issues."""
        findings: list[Finding] = []
        
        if not perms_data.get("defined", False):
            return findings
        
        perm_value = perms_data.get("value")
        perm_type = perms_data.get("type")
        
        # Check for write-all or read-all
        if perm_type == "string":
            if perm_value == "write-all":
                findings.append(self.create_finding(
                    title="Overly permissive 'write-all' permissions",
                    description=(
                        f"The {context} uses 'write-all' permissions, granting full write "
                        f"access to all repository resources. This violates the principle "
                        f"of least privilege and could enable privilege escalation attacks."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    remediation=(
                        "Replace 'write-all' with specific, minimal permissions:\n"
                        "permissions:\n  contents: read\n  pull-requests: write"
                    ),
                    metadata={"context": context, "permissions": perm_value},
                ))
            elif perm_value == "read-all":
                findings.append(self.create_finding(
                    title="Broad 'read-all' permissions may not be necessary",
                    description=(
                        f"The {context} uses 'read-all' permissions, granting read access "
                        f"to all repository resources including potentially sensitive data."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    remediation=(
                        "Consider specifying only the specific read permissions needed."
                    ),
                    metadata={"context": context, "permissions": perm_value},
                ))
        
        # Check granular permissions for issues
        elif perm_type == "granular" and isinstance(perm_value, dict):
            for perm_name, perm_level in perm_value.items():
                if isinstance(perm_level, str):
                    perm_level = perm_level.lower()
                    
                    # Check for write on sensitive permissions
                    if perm_level == "write" and perm_name in SENSITIVE_PERMISSIONS:
                        findings.append(self.create_finding(
                            title=f"Write permission on sensitive scope: {perm_name}",
                            description=(
                                f"The {context} grants write access to '{perm_name}'. "
                                f"This is a sensitive permission that should be carefully reviewed."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            remediation=(
                                f"Verify that write access to '{perm_name}' is truly required. "
                                f"Consider using read-only access if writes aren't needed."
                            ),
                            metadata={
                                "context": context,
                                "permission": perm_name,
                                "level": perm_level,
                            },
                        ))
                    
                    # Check for id-token write (OIDC)
                    if perm_name == "id-token" and perm_level == "write":
                        findings.append(self.create_finding(
                            title="OIDC token generation enabled",
                            description=(
                                f"The {context} can generate OIDC tokens (id-token: write). "
                                f"While needed for cloud authentication, ensure this is "
                                f"intentional and the workflow is trusted."
                            ),
                            severity=Severity.INFO,
                            file_path=file_path,
                            metadata={"context": context},
                        ))
        
        return findings
    
    def _has_sensitive_operations(self, jobs: dict[str, Any]) -> bool:
        """Check if any job appears to do sensitive operations."""
        sensitive_actions = [
            "checkout", "push", "deploy", "release", "publish",
            "upload-artifact", "download-artifact", "github-script",
        ]
        sensitive_commands = [
            "git push", "git commit", "npm publish", "docker push",
            "gh release", "gh pr", "curl -X POST", "curl -X PUT",
        ]
        
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            
            for step in job.get("steps", []):
                # Check action uses
                if step.get("type") == "action":
                    action = step.get("action", {})
                    if isinstance(action, dict):
                        repo = action.get("repo", "")
                        if any(sa in str(repo).lower() for sa in sensitive_actions):
                            return True
                
                # Check run commands
                if step.get("type") == "run":
                    run_content = str(step.get("run", "")).lower()
                    if any(cmd in run_content for cmd in sensitive_commands):
                        return True
        
        return False
