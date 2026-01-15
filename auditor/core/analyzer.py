"""
Main analysis orchestrator for the CI-CD-Supply-Chain-Auditor.

Coordinates parsing, security checks, and result collection.
Handles errors gracefully and provides progress updates.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from auditor.config import AuditorConfig
from auditor.core.result import AuditResult, CheckResult
from auditor.core.severity import Severity
from auditor.exceptions import (
    AuditorError,
    ParserError,
    SecurityCheckError,
    ValidationError,
)
from auditor.logging_config import get_logger

if TYPE_CHECKING:
    from auditor.checks.base import BaseCheck
    from auditor.parsers.base import BaseParser

logger = get_logger("analyzer")


class Analyzer:
    """
    Main orchestrator for CI/CD pipeline security audits.
    
    Coordinates:
    - Pipeline file discovery
    - Configuration parsing
    - Security check execution
    - Result aggregation
    
    Example:
        config = AuditorConfig(target_path=Path("./my-repo"))
        analyzer = Analyzer(config)
        result = analyzer.run()
    """
    
    def __init__(self, config: AuditorConfig) -> None:
        """
        Initialize the analyzer.
        
        Args:
            config: Validated auditor configuration
        """
        self.config = config
        self._checks: list[BaseCheck] = []
        self._parsers: dict[str, BaseParser] = {}
        self._initialized = False
    
    def initialize(self) -> None:
        """
        Initialize parsers and checks.
        
        Called automatically on first run, but can be called explicitly
        for early validation.
        """
        if self._initialized:
            return
        
        self._load_parsers()
        self._load_checks()
        self._initialized = True
        
        logger.info(
            "Analyzer initialized",
            extra={
                "parsers": list(self._parsers.keys()),
                "checks": len(self._checks),
            }
        )
    
    def _load_parsers(self) -> None:
        """Load pipeline parsers based on configuration."""
        from auditor.parsers.github_actions import GitHubActionsParser
        from auditor.parsers.gitlab_ci import GitLabCIParser
        
        platform = self.config.platform
        
        if platform in ("github_actions", "auto"):
            self._parsers["github_actions"] = GitHubActionsParser()
        
        if platform in ("gitlab_ci", "auto"):
            self._parsers["gitlab_ci"] = GitLabCIParser()
        
        if not self._parsers:
            raise ValidationError(
                f"No parsers available for platform: {platform}",
                field="platform",
            )
    
    def _load_checks(self) -> None:
        """Load security checks based on configuration."""
        from auditor.checks.secrets import SecretsCheck
        from auditor.checks.permissions import PermissionsCheck
        from auditor.checks.actions import ActionsCheck
        from auditor.checks.runners import RunnersCheck
        from auditor.checks.dependencies import DependenciesCheck
        from auditor.checks.slsa import SLSACheck
        
        all_checks = [
            SecretsCheck(),
            PermissionsCheck(),
            ActionsCheck(),
            RunnersCheck(),
            DependenciesCheck(),
            SLSACheck(),
        ]
        
        # Filter by enabled status
        self._checks = [
            check for check in all_checks
            if self.config.checks.enabled
        ]
    
    def run(
        self,
        target_path: Path | None = None,
        progress_callback: callable | None = None,
    ) -> AuditResult:
        """
        Run a complete security audit.
        
        Args:
            target_path: Override target path from config
            progress_callback: Optional callback(check_name, status)
        
        Returns:
            Complete audit result with all findings
        
        Raises:
            ValidationError: If target is invalid
            ParserError: If pipeline files cannot be parsed
        """
        self.initialize()
        
        # Resolve target path
        path = target_path or self.config.target_path
        if path is None:
            raise ValidationError(
                "No target path specified",
                field="target_path",
            )
        
        path = Path(path).resolve()
        
        if not path.exists():
            raise ValidationError(
                "Target path does not exist",
                field="target_path",
                details={"path_exists": False},
            )
        
        logger.info(f"Starting audit of: {path.name}")
        
        # Create result container
        result = AuditResult(
            target_path=str(path),
            target_type="local",
            platform=self.config.platform,
        )
        
        try:
            # Discover and parse pipeline files
            parsed_files = self._discover_and_parse(path)
            
            if not parsed_files:
                logger.warning("No pipeline files found in target")
                result.complete()
                return result
            
            logger.info(f"Found {len(parsed_files)} pipeline file(s)")
            
            # Run each security check
            total_checks = len(self._checks)
            for i, check in enumerate(self._checks, 1):
                check_name = check.name
                
                if progress_callback:
                    progress_callback(check_name, f"Running ({i}/{total_checks})")
                
                check_result = self._run_check(check, parsed_files)
                result.add_check_result(check_result)
                
                if check_result.findings:
                    logger.info(
                        f"Check '{check_name}' found {len(check_result.findings)} issue(s)"
                    )
        
        except AuditorError:
            # Re-raise known errors
            raise
        except Exception as e:
            # Wrap unexpected errors
            logger.exception("Unexpected error during audit")
            raise SecurityCheckError(
                f"Audit failed: {type(e).__name__}",
                details={"error_type": type(e).__name__},
            ) from e
        finally:
            result.complete()
        
        # Log summary
        self._log_summary(result)
        
        return result
    
    def _discover_and_parse(self, path: Path) -> list[dict]:
        """
        Discover pipeline files and parse them.
        
        Args:
            path: Root path to search
        
        Returns:
            List of parsed pipeline configurations
        """
        parsed_files = []
        
        for parser_name, parser in self._parsers.items():
            try:
                files = parser.discover_files(path, self.config.scan)
                
                for file_path in files:
                    try:
                        parsed = parser.parse(file_path)
                        if parsed:
                            # Add file path to parsed content if not present
                            if "file_path" not in parsed:
                                parsed["file_path"] = str(file_path)
                            parsed_files.append(parsed)
                    except ParserError as e:
                        logger.warning(f"Failed to parse {file_path.name}: {e}")
                        continue
                        
            except Exception as e:
                logger.warning(f"Parser '{parser_name}' discovery failed: {e}")
                continue
        
        return parsed_files
    
    def _run_check(
        self,
        check: "BaseCheck",
        parsed_files: list[dict],
    ) -> CheckResult:
        """
        Run a single security check.
        
        Args:
            check: The check to run
            parsed_files: List of parsed pipeline files
        
        Returns:
            Check result with findings
        """
        result = CheckResult(
            check_id=check.id,
            check_name=check.name,
        )
        
        start_time = time.perf_counter()
        
        try:
            # Run the check
            findings = check.run(parsed_files, self.config)
            
            # Add findings to result
            for finding in findings:
                result.add_finding(finding)
            
            result.passed = len(findings) == 0
            
        except Exception as e:
            logger.exception(f"Check '{check.name}' failed")
            result.passed = False
            result.error_message = str(e)
        
        result.duration_ms = (time.perf_counter() - start_time) * 1000
        
        return result
    
    def _log_summary(self, result: AuditResult) -> None:
        """Log audit summary."""
        severity_counts = result.severity_counts
        
        summary_parts = []
        for severity in reversed(list(Severity)):
            count = severity_counts.get(severity.name.lower(), 0)
            if count > 0:
                summary_parts.append(f"{severity.name}: {count}")
        
        if summary_parts:
            logger.info(f"Audit complete. Findings: {', '.join(summary_parts)}")
        else:
            logger.info("Audit complete. No issues found.")
        
        if result.duration_seconds:
            logger.debug(f"Audit duration: {result.duration_seconds:.2f}s")
