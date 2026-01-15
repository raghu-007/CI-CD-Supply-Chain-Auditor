"""
Command-line interface for the CI-CD-Supply-Chain-Auditor.

Provides a rich, user-friendly CLI using Click with:
- Clear help messages
- Progress indicators
- Colored output
- Multiple output formats
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from auditor import __version__
from auditor.config import AuditorConfig, load_config
from auditor.core.analyzer import Analyzer
from auditor.core.severity import Severity
from auditor.exceptions import AuditorError, ValidationError
from auditor.logging_config import setup_logging, get_logger
from auditor.reporters import JSONReporter, MarkdownReporter, HTMLReporter

logger = get_logger("cli")
console = Console()


def print_banner() -> None:
    """Print the application banner."""
    banner = f"""
[bold blue]╔═══════════════════════════════════════════════════════════╗
║        CI-CD-Supply-Chain-Auditor v{__version__:<21}║
║   Security auditor for CI/CD pipelines & supply chains   ║
╚═══════════════════════════════════════════════════════════╝[/bold blue]
"""
    console.print(banner)


@click.group()
@click.version_option(version=__version__, prog_name="auditor")
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output"
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Suppress non-essential output"
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output"
)
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, no_color: bool) -> None:
    """
    CI-CD-Supply-Chain-Auditor - Secure your CI/CD pipelines.
    
    Analyze CI/CD pipeline configurations for security vulnerabilities,
    misconfigurations, and best-practice violations.
    
    Examples:
    
        # Scan current directory
        auditor scan .
        
        # Scan with JSON output
        auditor scan . --format json --output report.json
        
        # Scan with specific checks only
        auditor scan . --check secrets --check permissions
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["no_color"] = no_color
    
    # Setup logging
    log_level = "DEBUG" if verbose else ("WARNING" if quiet else "INFO")
    setup_logging(level=log_level, no_color=no_color)


@main.command()
@click.argument(
    "path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
)
@click.option(
    "--format", "-f",
    type=click.Choice(["json", "markdown", "html", "all"]),
    default="json",
    help="Output format for the report"
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    help="Output file or directory for the report"
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file"
)
@click.option(
    "--platform", "-p",
    type=click.Choice(["github_actions", "gitlab_ci", "auto"]),
    default="auto",
    help="CI/CD platform to analyze"
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to report"
)
@click.option(
    "--fail-on",
    type=click.Choice(["info", "low", "medium", "high", "critical", "none"]),
    default="high",
    help="Exit with error if findings at or above this severity"
)
@click.pass_context
def scan(
    ctx: click.Context,
    path: Path,
    format: str,
    output: Optional[Path],
    config: Optional[Path],
    platform: str,
    severity: str,
    fail_on: str,
) -> None:
    """
    Scan a directory for CI/CD pipeline security issues.
    
    PATH is the directory to scan (defaults to current directory).
    
    Examples:
    
        # Basic scan
        auditor scan .
        
        # Scan with HTML report
        auditor scan /path/to/repo --format html --output report.html
        
        # Scan only for high+ severity, fail on critical
        auditor scan . --severity high --fail-on critical
    """
    quiet = ctx.obj.get("quiet", False)
    no_color = ctx.obj.get("no_color", False)
    
    if not quiet:
        print_banner()
    
    try:
        # Load configuration
        auditor_config = _load_config(config, path, platform)
        
        # Create analyzer
        analyzer = Analyzer(auditor_config)
        
        # Run the audit with progress
        if not quiet:
            console.print(f"\n[bold]Scanning:[/bold] {path.resolve()}\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet,
        ) as progress:
            task = progress.add_task("Initializing...", total=None)
            
            def update_progress(check_name: str, status: str) -> None:
                progress.update(task, description=f"Running: {check_name}")
            
            progress.update(task, description="Analyzing pipeline files...")
            result = analyzer.run(progress_callback=update_progress)
            progress.update(task, description="Complete!")
        
        # Filter by severity
        min_severity = Severity.from_string(severity)
        filtered_findings = result.get_findings_by_severity(min_severity)
        
        # Generate and output report
        output_path = output or Path("./reports")
        _generate_reports(result, format, output_path)
        
        # Display summary
        if not quiet:
            _display_summary(result, min_severity)
        
        # Determine exit code
        exit_code = 0
        if fail_on != "none":
            fail_severity = Severity.from_string(fail_on)
            high_findings = result.get_findings_by_severity(fail_severity)
            if high_findings:
                exit_code = 1
                if not quiet:
                    console.print(
                        f"\n[red]✗ Found {len(high_findings)} finding(s) at or above "
                        f"{fail_on} severity[/red]"
                    )
        
        if exit_code == 0 and not quiet:
            console.print("\n[green]✓ Scan completed successfully[/green]")
        
        sys.exit(exit_code)
        
    except ValidationError as e:
        console.print(f"\n[red]Validation Error:[/red] {e}")
        sys.exit(2)
    except AuditorError as e:
        console.print(f"\n[red]Error:[/red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unexpected error during scan")
        console.print(f"\n[red]Unexpected error:[/red] {e}")
        sys.exit(1)


@main.command()
def version() -> None:
    """Display version information."""
    console.print(f"CI-CD-Supply-Chain-Auditor v{__version__}")


@main.command()
def checks() -> None:
    """List all available security checks."""
    print_banner()
    
    from auditor.checks import (
        SecretsCheck,
        PermissionsCheck,
        ActionsCheck,
        RunnersCheck,
        DependenciesCheck,
        SLSACheck,
    )
    
    all_checks = [
        SecretsCheck(),
        PermissionsCheck(),
        ActionsCheck(),
        RunnersCheck(),
        DependenciesCheck(),
        SLSACheck(),
    ]
    
    table = Table(title="Available Security Checks")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    
    for check in all_checks:
        table.add_row(
            check.id,
            check.name,
            check.description[:60] + "..." if len(check.description) > 60 else check.description,
        )
    
    console.print(table)


def _load_config(
    config_path: Optional[Path],
    target_path: Path,
    platform: str,
) -> AuditorConfig:
    """Load and configure the auditor."""
    if config_path:
        config = load_config(config_path)
    else:
        config = AuditorConfig()
    
    # Override with CLI options
    config = AuditorConfig(
        target_path=target_path,
        platform=platform,
        **config.model_dump(exclude={"target_path", "platform"}),
    )
    
    return config


def _generate_reports(
    result: "AuditResult",
    format: str,
    output_path: Path,
) -> None:
    """Generate reports in specified formats."""
    reporters = []
    
    if format in ("json", "all"):
        reporters.append(JSONReporter())
    if format in ("markdown", "all"):
        reporters.append(MarkdownReporter())
    if format in ("html", "all"):
        reporters.append(HTMLReporter())
    
    for reporter in reporters:
        try:
            path = reporter.write(result, output_path)
            console.print(f"  📄 {reporter.format_name}: {path}")
        except Exception as e:
            console.print(f"  [red]✗ Failed to write {reporter.format_name}: {e}[/red]")


def _display_summary(result: "AuditResult", min_severity: Severity) -> None:
    """Display audit summary in the terminal."""
    console.print("\n")
    
    # Create summary table
    table = Table(title="Audit Summary", show_header=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    
    severity_styles = {
        "critical": "red bold",
        "high": "bright_red",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }
    
    for sev in reversed(list(Severity)):
        if sev < min_severity:
            continue
        count = result.severity_counts.get(sev.name.lower(), 0)
        style = severity_styles.get(sev.name.lower(), "")
        emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }.get(sev.name.lower(), "")
        
        if count > 0:
            table.add_row(f"{emoji} {sev.name.capitalize()}", f"[{style}]{count}[/{style}]")
    
    console.print(table)
    
    # Overall status
    if result.passed:
        panel = Panel(
            "[green bold]✓ All checks passed[/green bold]",
            border_style="green",
        )
    else:
        panel = Panel(
            f"[red bold]✗ Found {result.total_findings} issue(s)[/red bold]",
            border_style="red",
        )
    
    console.print(panel)


# Ensure the main function is the entry point
if __name__ == "__main__":
    main()
