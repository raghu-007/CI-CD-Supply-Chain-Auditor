"""
Runner configuration security check.

Analyzes workflow runner configurations for security risks including
self-hosted runner vulnerabilities and insecure runner settings.

CWE References:
- CWE-269: Improper Privilege Management
- CWE-693: Protection Mechanism Failure
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auditor.checks.base import BaseCheck
from auditor.core.result import Finding
from auditor.core.severity import Severity

if TYPE_CHECKING:
    from auditor.config import AuditorConfig


class RunnersCheck(BaseCheck):
    """
    Check for runner configuration security risks.
    
    Detects:
    - Self-hosted runner usage in public repos
    - Missing runner labels/restrictions
    - Insecure runner environment settings
    - Container configuration issues
    """
    
    @property
    def id(self) -> str:
        return "runners-001"
    
    @property
    def name(self) -> str:
        return "Runner Configuration Security"
    
    @property
    def description(self) -> str:
        return (
            "Analyzes workflow runner configurations for security risks "
            "including self-hosted runner vulnerabilities."
        )
    
    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH
    
    @property
    def references(self) -> tuple[str, ...]:
        return (
            "https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#self-hosted-runner-security",
            "https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners",
        )
    
    @property
    def cwe_ids(self) -> tuple[str, ...]:
        return ("CWE-269", "CWE-693")
    
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """Run runner security checks."""
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
        """Check GitHub Actions workflow for runner security issues."""
        findings: list[Finding] = []
        
        # Check workflow triggers for self-hosted runner risks
        triggers = file_data.get("triggers", {})
        is_public_triggerable = self._can_be_triggered_publicly(triggers)
        
        jobs = file_data.get("jobs", {})
        
        for job_id, job in jobs.items():
            runs_on = job.get("runs_on", {})
            
            # Check for self-hosted runners
            if runs_on.get("self_hosted", False):
                findings.extend(
                    self._check_self_hosted(
                        job_id, runs_on, file_path, is_public_triggerable, triggers
                    )
                )
            
            # Check for expression in runs-on (dangerous)
            if runs_on.get("uses_expression", False):
                findings.append(self.create_finding(
                    title=f"Dynamic runner selection in job '{job_id}'",
                    description=(
                        f"The job '{job_id}' uses an expression for runner selection. "
                        f"This could potentially allow an attacker to influence which "
                        f"runner executes the job if the expression uses user-controlled data."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    remediation="Use static runner labels instead of expressions when possible.",
                    metadata={"job": job_id},
                ))
            
            # Check container configuration
            container = job.get("container")
            if container:
                findings.extend(self._check_container(job_id, container, file_path))
            
            # Check services
            services = job.get("services", {})
            if services:
                findings.extend(self._check_services(job_id, services, file_path))
        
        return findings
    
    def _check_self_hosted(
        self,
        job_id: str,
        runs_on: dict[str, Any],
        file_path: str,
        is_public_triggerable: bool,
        triggers: dict[str, Any],
    ) -> list[Finding]:
        """Check self-hosted runner security."""
        findings: list[Finding] = []
        
        # Self-hosted runners triggered by pull_request from forks is very dangerous
        if is_public_triggerable:
            # Check if it's specifically pull_request
            if "pull_request" in triggers or "pull_request_target" in triggers:
                severity = Severity.CRITICAL
                if "pull_request_target" in triggers:
                    title = f"Self-hosted runner with pull_request_target trigger"
                    description = (
                        f"The job '{job_id}' uses a self-hosted runner and can be triggered "
                        f"by pull_request_target. This is extremely dangerous as forked PRs "
                        f"can execute code on your self-hosted infrastructure with access to secrets."
                    )
                else:
                    title = f"Self-hosted runner with public PR trigger"
                    description = (
                        f"The job '{job_id}' uses a self-hosted runner and can be triggered "
                        f"by pull requests. If this is a public repository, malicious PRs could "
                        f"execute arbitrary code on your self-hosted infrastructure."
                    )
                
                findings.append(self.create_finding(
                    title=title,
                    description=description,
                    severity=severity,
                    file_path=file_path,
                    remediation=(
                        "For self-hosted runners:\n"
                        "1. Never use them with pull_request triggers on public repos\n"
                        "2. Use 'workflow_run' instead with proper controls\n"
                        "3. Use GitHub-hosted runners for untrusted code\n"
                        "4. If self-hosted is required, use ephemeral runners"
                    ),
                    metadata={"job": job_id, "runs_on": runs_on.get("value")},
                ))
        
        # General self-hosted runner warning
        findings.append(self.create_finding(
            title=f"Self-hosted runner used in job '{job_id}'",
            description=(
                f"The job '{job_id}' uses a self-hosted runner. Self-hosted runners "
                f"require careful security configuration to prevent compromise."
            ),
            severity=Severity.INFO,
            file_path=file_path,
            remediation=(
                "Ensure self-hosted runners:\n"
                "- Run in ephemeral/containerized environments\n"
                "- Don't persist sensitive data between jobs\n"
                "- Have minimal network access\n"
                "- Are only used for trusted workflows"
            ),
            metadata={"job": job_id},
        ))
        
        return findings
    
    def _can_be_triggered_publicly(self, triggers: dict[str, Any]) -> bool:
        """Check if workflow can be triggered by external contributors."""
        public_triggers = {
            "pull_request",
            "pull_request_target",
            "issue_comment",
            "issues",
            "fork",
            "public",
        }
        return bool(set(triggers.keys()) & public_triggers)
    
    def _check_container(
        self,
        job_id: str,
        container: Any,
        file_path: str,
    ) -> list[Finding]:
        """Check container configuration for security issues."""
        findings: list[Finding] = []
        
        if isinstance(container, str):
            container = {"image": container}
        
        if not isinstance(container, dict):
            return findings
        
        image = container.get("image", "")
        
        # Check for non-pinned images
        if image and ":" not in image:
            findings.append(self.create_finding(
                title=f"Container image without tag in job '{job_id}'",
                description=(
                    f"The container image '{image}' doesn't specify a tag. "
                    f"This means 'latest' will be used, which is mutable and "
                    f"could change unexpectedly."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                remediation="Pin the image to a specific tag or digest.",
                metadata={"job": job_id, "image": image},
            ))
        elif image and "@sha256:" not in image:
            # Has tag but not pinned to digest
            findings.append(self.create_finding(
                title=f"Container image not pinned to digest in job '{job_id}'",
                description=(
                    f"The container image uses a tag which is mutable. "
                    f"Consider pinning to a digest for reproducibility."
                ),
                severity=Severity.LOW,
                file_path=file_path,
                remediation="Pin to digest: image@sha256:<digest>",
                metadata={"job": job_id},
            ))
        
        # Check for privileged mode
        options = container.get("options", "")
        if "--privileged" in str(options):
            findings.append(self.create_finding(
                title=f"Container running in privileged mode in job '{job_id}'",
                description=(
                    f"The container is running with --privileged flag. "
                    f"This grants full host access and is extremely dangerous."
                ),
                severity=Severity.CRITICAL,
                file_path=file_path,
                remediation="Remove --privileged unless absolutely necessary.",
                metadata={"job": job_id},
            ))
        
        return findings
    
    def _check_services(
        self,
        job_id: str,
        services: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check service container configurations."""
        findings: list[Finding] = []
        
        for service_id, service in services.items():
            if isinstance(service, str):
                service = {"image": service}
            
            if not isinstance(service, dict):
                continue
            
            # Check for unverified images
            image = service.get("image", "")
            if image and not self._is_trusted_image(image):
                findings.append(self.create_finding(
                    title=f"Unverified service image in job '{job_id}'",
                    description=(
                        f"The service '{service_id}' uses image '{image}'. "
                        f"Ensure this image is from a trusted source."
                    ),
                    severity=Severity.LOW,
                    file_path=file_path,
                    metadata={"job": job_id, "service": service_id},
                ))
        
        return findings
    
    def _is_trusted_image(self, image: str) -> bool:
        """Check if an image is from a trusted registry."""
        trusted_prefixes = [
            "ghcr.io/actions/",
            "docker.io/library/",
            "mcr.microsoft.com/",
            "gcr.io/google",
            "public.ecr.aws/",
        ]
        
        # Official Docker images (no prefix)
        official_images = {
            "postgres", "mysql", "redis", "mongo", "elasticsearch",
            "rabbitmq", "nginx", "node", "python", "ruby", "golang",
        }
        
        image_lower = image.lower()
        
        # Check prefixes
        if any(image_lower.startswith(prefix) for prefix in trusted_prefixes):
            return True
        
        # Check official images
        image_name = image.split(":")[0].split("/")[-1]
        if image_name in official_images:
            return True
        
        return False
    
    def _check_gitlab_ci(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check GitLab CI for runner security issues."""
        findings: list[Finding] = []
        
        jobs = file_data.get("jobs", {})
        
        for job_name, job in jobs.items():
            tags = job.get("tags", [])
            
            # Check for specific runner tags
            if tags:
                for tag in tags:
                    if "privileged" in str(tag).lower():
                        findings.append(self.create_finding(
                            title=f"Job '{job_name}' requests privileged runner",
                            description=(
                                f"The job requests a runner with tag '{tag}' which "
                                f"suggests a privileged runner configuration."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            metadata={"job": job_name, "tag": tag},
                        ))
            
            # Check image configuration
            image = job.get("image")
            if image and isinstance(image, str):
                if "@" not in image and ":" not in image:
                    findings.append(self.create_finding(
                        title=f"Unpinned image in job '{job_name}'",
                        description=(
                            f"The image '{image}' is not pinned to a specific version."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        metadata={"job": job_name, "image": image},
                    ))
        
        return findings
