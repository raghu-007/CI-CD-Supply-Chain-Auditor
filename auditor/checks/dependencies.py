"""
Dependency security check.

Analyzes CI/CD configurations for dependency-related security issues
including unsafe installation patterns and missing integrity checks.

CWE References:
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-494: Download of Code Without Integrity Check
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from auditor.checks.base import BaseCheck
from auditor.core.result import Finding
from auditor.core.severity import Severity

if TYPE_CHECKING:
    from auditor.config import AuditorConfig


class DependenciesCheck(BaseCheck):
    """
    Check for dependency security issues in CI/CD pipelines.
    
    Detects:
    - Curl pipe to shell patterns
    - Missing dependency lockfiles
    - Unsafe npm/pip/gem install patterns
    - Missing integrity verification
    """
    
    @property
    def id(self) -> str:
        return "dependencies-001"
    
    @property
    def name(self) -> str:
        return "Dependency Security"
    
    @property
    def description(self) -> str:
        return (
            "Analyzes CI/CD pipelines for dependency-related security issues "
            "including unsafe installation patterns and missing integrity checks."
        )
    
    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def references(self) -> tuple[str, ...]:
        return (
            "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html",
            "https://slsa.dev/spec/v1.0/requirements",
        )
    
    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return ("CWE-829", "CWE-494")
    
    # Patterns for detecting dangerous install patterns
    CURL_PIPE_PATTERNS = [
        re.compile(r"curl\s+[^|]*\|\s*(ba)?sh", re.IGNORECASE),
        re.compile(r"wget\s+[^|]*\|\s*(ba)?sh", re.IGNORECASE),
        re.compile(r"curl\s+[^|]*\|\s*sudo", re.IGNORECASE),
        re.compile(r"wget\s+[^|]*\|\s*sudo", re.IGNORECASE),
    ]
    
    UNSAFE_NPM_PATTERNS = [
        re.compile(r"npm\s+install\s+(?!.*--ignore-scripts).*(?<!package\.json)$", re.MULTILINE),
    ]
    
    UNSAFE_PIP_PATTERNS = [
        re.compile(r"pip\s+install\s+(?!.*-r\s+requirements)(?!.*--hash)", re.IGNORECASE),
    ]
    
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """Run dependency security checks."""
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
        """Check GitHub Actions for dependency issues."""
        findings: list[Finding] = []
        
        jobs = file_data.get("jobs", {})
        
        for job_id, job in jobs.items():
            for step in job.get("steps", []):
                step_name = step.get("name", step.get("id", "unnamed"))
                
                # Check run scripts
                if step.get("type") == "run":
                    run_content = step.get("run", "")
                    findings.extend(
                        self._check_script(run_content, file_path, f"{job_id}:{step_name}")
                    )
                
                # Check action usage for dependency patterns
                if step.get("type") == "action":
                    findings.extend(
                        self._check_action_dependencies(step, file_path, f"{job_id}:{step_name}")
                    )
        
        return findings
    
    def _check_gitlab_ci(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check GitLab CI for dependency issues."""
        findings: list[Finding] = []
        
        jobs = file_data.get("jobs", {})
        
        for job_name, job in jobs.items():
            # Check all script types
            for script_type in ["before_script", "script", "after_script"]:
                scripts = job.get(script_type, [])
                for script in scripts:
                    findings.extend(
                        self._check_script(script, file_path, f"{job_name}:{script_type}")
                    )
        
        return findings
    
    def _check_script(
        self,
        script: str,
        file_path: str,
        context: str,
    ) -> list[Finding]:
        """Check a script for dependency security issues."""
        findings: list[Finding] = []
        
        if not script:
            return findings
        
        # Check for curl pipe to shell
        for pattern in self.CURL_PIPE_PATTERNS:
            if pattern.search(script):
                findings.append(self.create_finding(
                    title="Dangerous curl pipe to shell pattern",
                    description=(
                        "The script downloads and executes code in a single command. "
                        "This is dangerous because:\n"
                        "1. You can't verify the code before execution\n"
                        "2. HTTPS doesn't guarantee content integrity\n"
                        "3. The download could be intercepted or modified"
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    remediation=(
                        "Instead of piping to shell:\n"
                        "1. Download the script first\n"
                        "2. Verify its checksum\n"
                        "3. Review the contents\n"
                        "4. Then execute it\n\n"
                        "Or better: use a package manager with integrity verification."
                    ),
                    metadata={"context": context},
                ))
                break  # Only report once per script
        
        # Check for npm install without lockfile
        if "npm install" in script and "package-lock.json" not in script:
            if "npm ci" not in script:
                findings.append(self.create_finding(
                    title="npm install without lockfile enforcement",
                    description=(
                        "Using 'npm install' in CI can lead to inconsistent builds "
                        "as it may update packages beyond what's in package-lock.json."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    remediation=(
                        "Use 'npm ci' instead of 'npm install' in CI pipelines. "
                        "'npm ci' installs exact versions from the lockfile."
                    ),
                    metadata={"context": context},
                ))
        
        # Check for pip install without hash checking
        if re.search(r"pip\s+install", script, re.IGNORECASE):
            if "--require-hashes" not in script and "--hash" not in script:
                findings.append(self.create_finding(
                    title="pip install without hash verification",
                    description=(
                        "Python dependencies are being installed without hash verification. "
                        "This means the integrity of downloaded packages isn't verified."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    remediation=(
                        "Use pip with hash checking:\n"
                        "1. Generate hashes: pip-compile --generate-hashes\n"
                        "2. Install with: pip install --require-hashes -r requirements.txt"
                    ),
                    metadata={"context": context},
                ))
        
        # Check for gem install
        if "gem install" in script:
            findings.append(self.create_finding(
                title="gem install in CI pipeline",
                description=(
                    "Installing gems directly can lead to inconsistent builds. "
                    "Consider using Bundler with a lockfile instead."
                ),
                severity=Severity.LOW,
                file_path=file_path,
                remediation="Use 'bundle install' with a Gemfile.lock.",
                metadata={"context": context},
            ))
        
        # Check for go install from remote
        if re.search(r"go\s+install\s+\S+@", script):
            findings.append(self.create_finding(
                title="go install from remote without vendoring",
                description=(
                    "Installing Go packages directly from remote sources can lead "
                    "to supply chain attacks if the module is compromised."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                remediation=(
                    "Consider:\n"
                    "1. Vendoring dependencies with 'go mod vendor'\n"
                    "2. Using a Go proxy with verification\n"
                    "3. Pinning to specific versions/commits"
                ),
                metadata={"context": context},
            ))
        
        # Check for add-apt-repository
        if "add-apt-repository" in script:
            findings.append(self.create_finding(
                title="Adding external APT repository",
                description=(
                    "Adding external APT repositories introduces third-party "
                    "packages that may not be as thoroughly vetted."
                ),
                severity=Severity.LOW,
                file_path=file_path,
                remediation=(
                    "If possible, use official repositories or container images "
                    "that already include the required packages."
                ),
                metadata={"context": context},
            ))
        
        return findings
    
    def _check_action_dependencies(
        self,
        step: dict[str, Any],
        file_path: str,
        context: str,
    ) -> list[Finding]:
        """Check action usage for dependency-related issues."""
        findings: list[Finding] = []
        
        action = step.get("action", {})
        if not isinstance(action, dict):
            return findings
        
        owner = action.get("owner", "")
        repo = action.get("repo", "")
        
        # Check for setup actions without caching
        setup_actions = ["setup-node", "setup-python", "setup-go", "setup-java"]
        
        if any(sa in str(repo) for sa in setup_actions):
            with_inputs = step.get("with", {})
            
            # Check if cache is configured
            has_cache = False
            for key in with_inputs:
                if "cache" in str(key).lower():
                    has_cache = True
                    break
            
            if not has_cache:
                findings.append(self.create_finding(
                    title=f"Setup action without caching",
                    description=(
                        f"The action '{owner}/{repo}' is used without caching. "
                        f"This can slow down builds and increase network requests."
                    ),
                    severity=Severity.INFO,
                    file_path=file_path,
                    remediation="Consider enabling caching for faster builds.",
                    metadata={"context": context, "action": f"{owner}/{repo}"},
                ))
        
        return findings
