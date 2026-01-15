"""
Third-party actions security check.

Analyzes usage of GitHub Actions for security risks including:
- Unpinned action versions
- Actions from untrusted sources
- Script injection vulnerabilities

CWE References:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-94: Improper Control of Generation of Code ('Code Injection')
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auditor.checks.base import BaseCheck
from auditor.constants import VERIFIED_ACTION_OWNERS, COMMAND_INJECTION_PATTERNS
from auditor.core.result import Finding
from auditor.core.severity import Severity

if TYPE_CHECKING:
    from auditor.config import AuditorConfig


class ActionsCheck(BaseCheck):
    """
    Check for third-party action security risks.
    
    Detects:
    - Unpinned action versions (not using SHA)
    - Actions from unknown/unverified sources
    - Potential script injection via expressions
    - Dangerous action patterns
    """
    
    @property
    def id(self) -> str:
        return "actions-001"
    
    @property
    def name(self) -> str:
        return "Third-Party Actions Security"
    
    @property
    def description(self) -> str:
        return (
            "Analyzes third-party GitHub Actions for security risks "
            "including unpinned versions and untrusted sources."
        )
    
    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def references(self) -> tuple[str, ...]:
        return (
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        )
    
    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return ("CWE-829", "CWE-94")
    
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """Run third-party actions security checks."""
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
        """Check GitHub Actions workflow for action security issues."""
        findings: list[Finding] = []
        
        jobs = file_data.get("jobs", {})
        
        for job_id, job in jobs.items():
            for step in job.get("steps", []):
                if step.get("type") != "action":
                    continue
                
                action = step.get("action", {})
                if not isinstance(action, dict):
                    continue
                
                step_name = step.get("name", step.get("id", "unnamed"))
                
                # Check version pinning
                findings.extend(
                    self._check_version_pinning(action, file_path, step_name)
                )
                
                # Check action source
                findings.extend(
                    self._check_action_source(action, file_path, step_name)
                )
                
                # Check for injection vulnerabilities
                findings.extend(
                    self._check_injection_risks(step, file_path, step_name)
                )
        
        # Check for script injection in run steps
        for job_id, job in jobs.items():
            for step in job.get("steps", []):
                if step.get("type") != "run":
                    continue
                
                step_name = step.get("name", step.get("id", "unnamed"))
                findings.extend(
                    self._check_run_injection(step, file_path, step_name)
                )
        
        return findings
    
    def _check_version_pinning(
        self,
        action: dict[str, Any],
        file_path: str,
        step_name: str,
    ) -> list[Finding]:
        """Check if action is properly pinned to a SHA."""
        findings: list[Finding] = []
        
        if action.get("type") != "remote":
            return findings
        
        version = action.get("version", "")
        version_type = action.get("version_type", "unknown")
        is_pinned = action.get("is_pinned", False)
        owner = action.get("owner", "")
        repo = action.get("repo", "")
        raw = action.get("raw", "")
        
        # Allow trusted owners with semver
        if owner in VERIFIED_ACTION_OWNERS and version_type == "semver":
            return findings
        
        if not is_pinned:
            if version_type == "semver":
                severity = Severity.MEDIUM if owner in VERIFIED_ACTION_OWNERS else Severity.HIGH
                findings.append(self.create_finding(
                    title=f"Action '{raw}' not pinned to SHA",
                    description=(
                        f"The action '{owner}/{repo}' uses version '{version}' which is a "
                        f"mutable tag. Tags can be moved to point to different commits, "
                        f"potentially introducing malicious code."
                    ),
                    severity=severity,
                    file_path=file_path,
                    remediation=(
                        f"Pin the action to a specific SHA:\n"
                        f"uses: {owner}/{repo}@<full-commit-sha>  # {version}\n\n"
                        f"You can find the SHA by checking the action's releases on GitHub."
                    ),
                    metadata={
                        "step": step_name,
                        "action": raw,
                        "version_type": version_type,
                    },
                ))
            elif version_type == "branch":
                findings.append(self.create_finding(
                    title=f"Action '{raw}' pinned to branch",
                    description=(
                        f"The action '{owner}/{repo}' is pinned to branch '{version}'. "
                        f"Branches are mutable and can receive new commits at any time, "
                        f"including potentially malicious code."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    remediation=(
                        f"Pin the action to a specific SHA instead of a branch:\n"
                        f"uses: {owner}/{repo}@<full-commit-sha>"
                    ),
                    metadata={
                        "step": step_name,
                        "action": raw,
                        "version_type": version_type,
                    },
                ))
        
        return findings
    
    def _check_action_source(
        self,
        action: dict[str, Any],
        file_path: str,
        step_name: str,
    ) -> list[Finding]:
        """Check if action comes from a trusted source."""
        findings: list[Finding] = []
        
        action_type = action.get("type", "unknown")
        
        if action_type == "docker":
            # Docker actions have their own risks
            image = action.get("image", "")
            findings.append(self.create_finding(
                title=f"Docker action from external registry",
                description=(
                    f"This step uses a Docker image from an external registry. "
                    f"Ensure the image is from a trusted source and uses a specific tag or digest."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                remediation=(
                    "Pin Docker images to specific digests:\n"
                    "uses: docker://image@sha256:<digest>"
                ),
                metadata={"step": step_name, "image": image},
            ))
        
        elif action_type == "remote":
            owner = action.get("owner", "")
            repo = action.get("repo", "")
            raw = action.get("raw", "")
            
            if owner and owner not in VERIFIED_ACTION_OWNERS:
                findings.append(self.create_finding(
                    title=f"Action from unverified source: {owner}",
                    description=(
                        f"The action '{raw}' is from '{owner}' which is not a verified "
                        f"GitHub Actions publisher. While this doesn't mean the action is "
                        f"malicious, extra caution is advised."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    remediation=(
                        f"Review the action's source code at https://github.com/{owner}/{repo} "
                        f"to ensure it's trustworthy. Consider forking the action to your "
                        f"organization for added control."
                    ),
                    metadata={"step": step_name, "owner": owner, "repo": repo},
                ))
        
        return findings
    
    def _check_injection_risks(
        self,
        step: dict[str, Any],
        file_path: str,
        step_name: str,
    ) -> list[Finding]:
        """Check for potential injection vulnerabilities in action inputs."""
        findings: list[Finding] = []
        
        with_inputs = step.get("with", {})
        
        for input_name, input_data in with_inputs.items():
            if isinstance(input_data, dict):
                value = input_data.get("value", "")
            else:
                value = str(input_data)
            
            # Check for dangerous expression interpolations
            for pattern_name, pattern in COMMAND_INJECTION_PATTERNS.items():
                if pattern.search(value):
                    findings.append(self.create_finding(
                        title=f"Potential injection in action input: {input_name}",
                        description=(
                            f"The input '{input_name}' contains a GitHub expression that "
                            f"could be vulnerable to injection attacks. User-controlled data "
                            f"from pull request titles, branch names, or comments could be "
                            f"injected into the workflow."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        remediation=(
                            "Avoid using user-controlled expressions directly. Instead:\n"
                            "1. Use an intermediate environment variable\n"
                            "2. Sanitize the input before use\n"
                            "3. Use the github-script action for safer interpolation"
                        ),
                        metadata={
                            "step": step_name,
                            "input": input_name,
                            "pattern": pattern_name,
                        },
                    ))
        
        return findings
    
    def _check_run_injection(
        self,
        step: dict[str, Any],
        file_path: str,
        step_name: str,
    ) -> list[Finding]:
        """Check run scripts for injection vulnerabilities."""
        findings: list[Finding] = []
        
        run_content = step.get("run", "")
        if not run_content:
            return findings
        
        # Check for dangerous expression interpolations in scripts
        for pattern_name, pattern in COMMAND_INJECTION_PATTERNS.items():
            if pattern.search(run_content):
                findings.append(self.create_finding(
                    title=f"Script injection vulnerability: {pattern_name}",
                    description=(
                        f"The run script contains '{pattern_name}' which could be "
                        f"vulnerable to command injection. An attacker could craft a "
                        f"malicious pull request title, branch name, or comment to "
                        f"execute arbitrary commands."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    remediation=(
                        "Never directly interpolate user-controlled data in scripts:\n\n"
                        "❌ Bad:\n"
                        "  run: echo ${{ github.event.issue.title }}\n\n"
                        "✅ Good:\n"
                        "  env:\n"
                        "    TITLE: ${{ github.event.issue.title }}\n"
                        "  run: echo \"$TITLE\""
                    ),
                    metadata={
                        "step": step_name,
                        "pattern": pattern_name,
                    },
                ))
        
        return findings
