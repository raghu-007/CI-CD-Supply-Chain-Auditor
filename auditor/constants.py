"""
Security constants for the CI-CD-Supply-Chain-Auditor.

This module contains patterns, limits, and constants used throughout the
auditor to detect security issues and enforce safe defaults.

SECURITY NOTE: All regex patterns are pre-compiled for safety and performance.
Never construct patterns from user input.
"""

import re
from typing import Final

# =============================================================================
# SIZE LIMITS (Defense against resource exhaustion)
# =============================================================================

MAX_FILE_SIZE_BYTES: Final[int] = 10 * 1024 * 1024  # 10 MB
MAX_YAML_DEPTH: Final[int] = 50  # Prevent YAML bombs
MAX_YAML_EXPANSIONS: Final[int] = 10000  # Limit anchor expansions
MAX_WORKFLOW_FILES: Final[int] = 1000  # Max files to scan in a repo
MAX_LINE_LENGTH: Final[int] = 10000  # Max characters per line

# =============================================================================
# FILE EXTENSIONS
# =============================================================================

YAML_EXTENSIONS: Final[frozenset[str]] = frozenset({".yml", ".yaml"})
ALLOWED_EXTENSIONS: Final[frozenset[str]] = frozenset({
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
    ".sh", ".bash", ".ps1", ".bat", ".cmd",
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb",
    ".dockerfile", ".containerfile",
})

# =============================================================================
# GITHUB ACTIONS SPECIFIC
# =============================================================================

GITHUB_WORKFLOWS_DIR: Final[str] = ".github/workflows"
GITHUB_ACTIONS_DIR: Final[str] = ".github/actions"

# Dangerous GitHub Actions permissions
DANGEROUS_PERMISSIONS: Final[frozenset[str]] = frozenset({
    "write-all",
    "contents: write",
    "packages: write",
    "security-events: write",
    "id-token: write",
    "actions: write",
})

# Permissions that should be explicitly restricted
SENSITIVE_PERMISSIONS: Final[frozenset[str]] = frozenset({
    "contents",
    "packages",
    "deployments",
    "id-token",
    "security-events",
    "actions",
    "checks",
    "issues",
    "pull-requests",
    "repository-projects",
    "statuses",
})

# =============================================================================
# SECRET DETECTION PATTERNS
# =============================================================================

# Pre-compiled regex patterns for secret detection
# SECURITY: Never log matches from these patterns

SECRET_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "aws_access_key": re.compile(
        r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
        re.IGNORECASE
    ),
    "aws_secret_key": re.compile(
        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
    ),
    "github_token": re.compile(
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
        re.IGNORECASE
    ),
    "github_oauth": re.compile(
        r"gho_[A-Za-z0-9]{36,}"
    ),
    "generic_api_key": re.compile(
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,})[\"']?"
    ),
    "generic_secret": re.compile(
        r"(?i)(?:secret|password|passwd|pwd|token|auth)[\"']?\s*[:=]\s*[\"']?([^\s\"']{8,})[\"']?"
    ),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "jwt_token": re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    ),
    "slack_token": re.compile(
        r"xox[baprs]-[A-Za-z0-9-]+"
    ),
    "stripe_key": re.compile(
        r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}"
    ),
    "google_api_key": re.compile(
        r"AIza[A-Za-z0-9_-]{35}"
    ),
    "heroku_api_key": re.compile(
        r"[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
    ),
    "npm_token": re.compile(
        r"npm_[A-Za-z0-9]{36}"
    ),
    "pypi_token": re.compile(
        r"pypi-[A-Za-z0-9_-]{50,}"
    ),
}

# Keywords that might indicate secrets in variable names
SECRET_KEYWORDS: Final[frozenset[str]] = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "api-key", "auth", "credential", "private_key", "privatekey",
    "access_key", "accesskey", "secret_key", "secretkey", "bearer",
    "oauth", "jwt", "api_secret", "apisecret", "client_secret",
    "encryption_key", "signing_key", "ssh_key", "deploy_key",
})

# =============================================================================
# DANGEROUS PATTERNS IN WORKFLOWS
# =============================================================================

# Patterns indicating potential command injection vulnerabilities
COMMAND_INJECTION_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "github_event_interpolation": re.compile(
        r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review)\..*\}\}"
    ),
    "github_head_ref": re.compile(
        r"\$\{\{\s*github\.head_ref\s*\}\}"
    ),
    "shell_expansion": re.compile(
        r"\$\(\s*[^)]+\s*\)"
    ),
    "backtick_execution": re.compile(
        r"`[^`]+`"
    ),
}

# Dangerous shell commands that might indicate security issues
DANGEROUS_COMMANDS: Final[frozenset[str]] = frozenset({
    "eval", "exec", "curl | sh", "curl | bash", "wget | sh", "wget | bash",
    "bash -c", "sh -c", "powershell -encodedcommand", "iex",
})

# =============================================================================
# SLSA REQUIREMENTS
# =============================================================================

SLSA_LEVELS: Final[dict[int, dict[str, list[str]]]] = {
    1: {
        "description": ["Build process must be documented"],
        "requirements": [
            "documented_build_process",
        ],
    },
    2: {
        "description": ["Version control and hosted build service"],
        "requirements": [
            "version_controlled_source",
            "hosted_build_service",
            "build_as_code",
        ],
    },
    3: {
        "description": ["Hardened build and signed provenance"],
        "requirements": [
            "version_controlled_source",
            "hosted_build_service",
            "build_as_code",
            "ephemeral_build_environment",
            "isolated_builds",
            "signed_provenance",
        ],
    },
    4: {
        "description": ["Hermetic and reproducible builds"],
        "requirements": [
            "version_controlled_source",
            "hosted_build_service",
            "build_as_code",
            "ephemeral_build_environment",
            "isolated_builds",
            "signed_provenance",
            "hermetic_builds",
            "reproducible_builds",
            "two_person_review",
        ],
    },
}

# =============================================================================
# TRUSTED ACTIONS (Verified GitHub Actions)
# =============================================================================

VERIFIED_ACTION_OWNERS: Final[frozenset[str]] = frozenset({
    "actions",  # Official GitHub Actions
    "github",   # GitHub's own actions
    "azure",    # Microsoft Azure
    "aws-actions",  # AWS
    "google-github-actions",  # Google Cloud
    "docker",   # Docker
    "hashicorp",  # HashiCorp
})

# =============================================================================
# OUTPUT SANITIZATION
# =============================================================================

# Characters to escape in output to prevent injection
ESCAPE_CHARS: Final[dict[str, str]] = {
    "<": "&lt;",
    ">": "&gt;",
    "&": "&amp;",
    '"': "&quot;",
    "'": "&#x27;",
    "/": "&#x2F;",
}

# Maximum length for values in reports
MAX_REPORT_VALUE_LENGTH: Final[int] = 500
