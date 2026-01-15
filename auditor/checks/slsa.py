"""
SLSA (Supply-chain Levels for Software Artifacts) compliance check.

Evaluates CI/CD pipelines against SLSA framework requirements to assess
the security and integrity of the software supply chain.

Reference: https://slsa.dev/spec/v1.0/
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from auditor.checks.base import BaseCheck
from auditor.constants import SLSA_LEVELS
from auditor.core.result import Finding
from auditor.core.severity import Severity

if TYPE_CHECKING:
    from auditor.config import AuditorConfig


class SLSACheck(BaseCheck):
    """
    Check for SLSA compliance.
    
    Evaluates:
    - SLSA Level 1: Build process documentation
    - SLSA Level 2: Version control and hosted builds
    - SLSA Level 3: Hardened builds and provenance
    - SLSA Level 4: Hermetic and reproducible builds
    """
    
    @property
    def id(self) -> str:
        return "slsa-001"
    
    @property
    def name(self) -> str:
        return "SLSA Compliance Check"
    
    @property
    def description(self) -> str:
        return (
            "Evaluates CI/CD pipelines against SLSA framework requirements "
            "for supply chain security."
        )
    
    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def references(self) -> tuple[str, ...]:
        return (
            "https://slsa.dev/",
            "https://slsa.dev/spec/v1.0/requirements",
            "https://github.com/slsa-framework/slsa-github-generator",
        )
    
    def run(
        self,
        parsed_files: list[dict[str, Any]],
        config: "AuditorConfig",
    ) -> list[Finding]:
        """Run SLSA compliance checks."""
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
        """Check GitHub Actions workflow for SLSA compliance."""
        findings: list[Finding] = []
        
        # Collect SLSA compliance indicators
        compliance = self._assess_compliance(file_data)
        
        # Report current level and gaps
        current_level = self._determine_level(compliance)
        
        # Add finding about current SLSA level
        if current_level == 0:
            findings.append(self.create_finding(
                title="Workflow does not meet SLSA Level 1",
                description=(
                    "This workflow does not meet the minimum SLSA Level 1 requirements. "
                    "SLSA Level 1 requires a documented build process."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                remediation=self._get_level_1_remediation(),
                metadata={"current_level": 0, "compliance": compliance},
            ))
        elif current_level == 1:
            findings.append(self.create_finding(
                title="Workflow meets SLSA Level 1 but not Level 2",
                description=(
                    "This workflow meets SLSA Level 1 (documented build process) but "
                    "does not meet Level 2 requirements for version control and hosted builds."
                ),
                severity=Severity.LOW,
                file_path=file_path,
                remediation=self._get_level_2_remediation(),
                metadata={"current_level": 1, "compliance": compliance},
            ))
        elif current_level == 2:
            findings.append(self.create_finding(
                title="Workflow meets SLSA Level 2 but not Level 3",
                description=(
                    "This workflow meets SLSA Level 2 but lacks Level 3 requirements "
                    "for hardened builds and signed provenance."
                ),
                severity=Severity.INFO,
                file_path=file_path,
                remediation=self._get_level_3_remediation(),
                metadata={"current_level": 2, "compliance": compliance},
            ))
        else:
            findings.append(self.create_finding(
                title=f"Workflow meets SLSA Level {current_level}",
                description=(
                    f"This workflow meets SLSA Level {current_level} requirements. "
                    f"{'Consider enhancing to Level 4 for maximum security.' if current_level < 4 else 'Great job on achieving maximum SLSA compliance!'}"
                ),
                severity=Severity.INFO,
                file_path=file_path,
                metadata={"current_level": current_level, "compliance": compliance},
            ))
        
        # Check for specific SLSA-related issues
        findings.extend(self._check_provenance(file_data, file_path))
        findings.extend(self._check_build_isolation(file_data, file_path))
        
        return findings
    
    def _assess_compliance(self, file_data: dict[str, Any]) -> dict[str, bool]:
        """Assess compliance with various SLSA requirements."""
        compliance = {
            "documented_build_process": True,  # By definition (workflow exists)
            "version_controlled_source": True,  # GitHub = version controlled
            "hosted_build_service": True,  # GitHub Actions = hosted
            "build_as_code": True,  # Workflow file = build as code
            "ephemeral_build_environment": False,
            "isolated_builds": False,
            "signed_provenance": False,
            "hermetic_builds": False,
            "reproducible_builds": False,
            "two_person_review": False,
        }
        
        jobs = file_data.get("jobs", {})
        
        # Check for ephemeral environment (GitHub-hosted runners are ephemeral)
        for job in jobs.values():
            runs_on = job.get("runs_on", {})
            if not runs_on.get("self_hosted", False):
                compliance["ephemeral_build_environment"] = True
                break
        
        # Check for isolated builds (containers)
        for job in jobs.values():
            if job.get("container"):
                compliance["isolated_builds"] = True
                break
        
        # Check for provenance generation
        for job in jobs.values():
            for step in job.get("steps", []):
                action = step.get("action", {})
                if isinstance(action, dict):
                    ref = action.get("raw", "")
                    if "slsa" in ref.lower() and "provenance" in ref.lower():
                        compliance["signed_provenance"] = True
                    if "attest" in ref.lower():
                        compliance["signed_provenance"] = True
        
        # Check for hermetic builds (no network access pattern)
        # This is hard to detect, so we look for indicators
        raw = file_data.get("raw", {})
        if "hermetic" in str(raw).lower():
            compliance["hermetic_builds"] = True
        
        return compliance
    
    def _determine_level(self, compliance: dict[str, bool]) -> int:
        """Determine the SLSA level based on compliance."""
        # Check each level's requirements
        for level in range(4, 0, -1):
            requirements = SLSA_LEVELS.get(level, {}).get("requirements", [])
            if all(compliance.get(req, False) for req in requirements):
                return level
        
        return 0
    
    def _check_provenance(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check for provenance generation."""
        findings: list[Finding] = []
        
        # Look for SLSA provenance generators
        uses_provenance = False
        uses_attestation = False
        
        jobs = file_data.get("jobs", {})
        for job in jobs.values():
            for step in job.get("steps", []):
                action = step.get("action", {})
                if isinstance(action, dict):
                    ref = action.get("raw", "")
                    ref_lower = ref.lower()
                    
                    if "slsa-framework/slsa-github-generator" in ref_lower:
                        uses_provenance = True
                    if "actions/attest" in ref_lower:
                        uses_attestation = True
        
        if not uses_provenance and not uses_attestation:
            # Check if this looks like a build/release workflow
            triggers = file_data.get("triggers", {})
            is_release = "release" in triggers or "push" in triggers
            
            name = file_data.get("name", "").lower()
            is_build_workflow = any(
                kw in name for kw in ["build", "release", "publish", "deploy"]
            )
            
            if is_release or is_build_workflow:
                findings.append(self.create_finding(
                    title="Build workflow without provenance generation",
                    description=(
                        "This appears to be a build or release workflow but does not "
                        "generate SLSA provenance. Provenance provides a tamper-proof "
                        "record of how artifacts were built."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    remediation=(
                        "Consider using the official SLSA provenance generator:\n"
                        "1. slsa-framework/slsa-github-generator\n"
                        "2. actions/attest-build-provenance\n\n"
                        "These create signed provenance attestations for your artifacts."
                    ),
                ))
        
        return findings
    
    def _check_build_isolation(
        self,
        file_data: dict[str, Any],
        file_path: str,
    ) -> list[Finding]:
        """Check for build isolation practices."""
        findings: list[Finding] = []
        
        jobs = file_data.get("jobs", {})
        
        for job_id, job in jobs.items():
            # Check if job uses container
            uses_container = bool(job.get("container"))
            
            # Check if job accesses external networks (heuristic)
            has_network_calls = False
            for step in job.get("steps", []):
                if step.get("type") == "run":
                    run_content = str(step.get("run", "")).lower()
                    network_indicators = ["curl", "wget", "npm install", "pip install", "apt-get"]
                    if any(ind in run_content for ind in network_indicators):
                        has_network_calls = True
                        break
            
            if has_network_calls and not uses_container:
                findings.append(self.create_finding(
                    title=f"Job '{job_id}' has network access without isolation",
                    description=(
                        "This job appears to make network requests but doesn't use "
                        "container isolation. For SLSA Level 3+, consider using "
                        "containerized builds with explicit network policies."
                    ),
                    severity=Severity.INFO,
                    file_path=file_path,
                    remediation=(
                        "Consider:\n"
                        "1. Using a container for the job\n"
                        "2. Pre-caching dependencies\n"
                        "3. Using a network-restricted environment"
                    ),
                    metadata={"job": job_id},
                ))
        
        return findings
    
    def _get_level_1_remediation(self) -> str:
        """Get remediation steps for SLSA Level 1."""
        return (
            "To meet SLSA Level 1:\n"
            "1. Document your build process in the workflow\n"
            "2. Add comments explaining build steps\n"
            "3. Ensure the workflow is version controlled"
        )
    
    def _get_level_2_remediation(self) -> str:
        """Get remediation steps for SLSA Level 2."""
        return (
            "To meet SLSA Level 2:\n"
            "1. Use GitHub-hosted runners (hosted build service)\n"
            "2. Ensure all source code is version controlled\n"
            "3. Define build process as code (you're already doing this!)"
        )
    
    def _get_level_3_remediation(self) -> str:
        """Get remediation steps for SLSA Level 3."""
        return (
            "To meet SLSA Level 3:\n"
            "1. Use GitHub-hosted runners (ephemeral environment)\n"
            "2. Consider using container jobs for isolation\n"
            "3. Generate signed provenance using:\n"
            "   - slsa-framework/slsa-github-generator\n"
            "   - actions/attest-build-provenance\n"
            "4. Enable artifact signing"
        )
