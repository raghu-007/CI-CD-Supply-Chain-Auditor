# CI-CD-Supply-Chain-Auditor 🛡️🔗

[![CI](https://github.com/raghu-007/CI-CD-Supply-Chain-Auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/raghu-007/CI-CD-Supply-Chain-Auditor/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

A security-focused auditor for CI/CD pipelines that identifies vulnerabilities, misconfigurations, and best-practice deviations in your software supply chain. Built with secure coding practices and designed to help organizations improve their SLSA posture.

## 🎯 Features

- **🔍 Pipeline Analysis** - Parses GitHub Actions and GitLab CI configurations for security issues
- **🔐 Secrets Detection** - Finds hardcoded secrets, exposed credentials, and insecure secret handling
- **👤 Permission Analysis** - Identifies overly permissive settings and least-privilege violations
- **📦 Third-Party Actions** - Checks for unpinned versions and untrusted action sources
- **🏃 Runner Security** - Detects self-hosted runner risks and container misconfigurations
- **📋 SLSA Compliance** - Evaluates workflows against SLSA framework requirements
- **📊 Multiple Reports** - Generates JSON, Markdown, and HTML reports

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/raghu-007/CI-CD-Supply-Chain-Auditor.git
cd CI-CD-Supply-Chain-Auditor

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package
pip install -e .
```

### Basic Usage

```bash
# Scan current directory
auditor scan .

# Scan a specific repository
auditor scan /path/to/your/repo

# Generate HTML report
auditor scan . --format html --output report.html

# Only show high+ severity issues
auditor scan . --severity high

# Fail CI if critical issues found
auditor scan . --fail-on critical
```

### As a Python Module

```python
from pathlib import Path
from auditor import Analyzer, AuditorConfig

# Configure the auditor
config = AuditorConfig(
    target_path=Path("./my-repo"),
    platform="github_actions",
)

# Run the audit
analyzer = Analyzer(config)
result = analyzer.run()

# Check results
print(f"Total findings: {result.total_findings}")
print(f"Passed: {result.passed}")

for finding in result.all_findings:
    print(f"[{finding.severity}] {finding.title}")
```

## 📋 Security Checks

| Check | Description | Severity |
|-------|-------------|----------|
| **Secrets Detection** | Hardcoded API keys, tokens, passwords | Critical |
| **Write-All Permissions** | Overly permissive GITHUB_TOKEN | Critical |
| **Script Injection** | User input in `${{ }}` expressions | Critical |
| **Unpinned Actions** | Actions using branches/tags instead of SHA | High |
| **Self-Hosted Runners** | Self-hosted with public PR triggers | High |
| **Curl Pipe Bash** | Installing via `curl \| bash` | High |
| **Missing Permissions** | No explicit permission restrictions | Medium |
| **Unverified Actions** | Actions from unverified sources | Medium |
| **SLSA Compliance** | Missing provenance generation | Medium |

## 🔧 Configuration

Create a `config.yml` file (see `examples/config.example.yml`):

```yaml
log_level: INFO
platform: auto

checks:
  enabled: true
  severity_threshold: low

report:
  format: json
  output_dir: ./reports

scan:
  max_file_size_mb: 10
  exclude_patterns:
    - node_modules
    - .git
```

Use with:

```bash
auditor scan . --config config.yml
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AUDITOR_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `AUDITOR_PLATFORM` | CI/CD platform (github_actions, gitlab_ci, auto) |
| `AUDITOR_GITHUB__TOKEN` | GitHub API token for remote scanning |

## 📊 Report Formats

### JSON (Machine-readable)
```bash
auditor scan . --format json --output report.json
```

### Markdown (Documentation)
```bash
auditor scan . --format markdown --output report.md
```

### HTML (Visual Report)
```bash
auditor scan . --format html --output report.html
```

### All Formats
```bash
auditor scan . --format all --output ./reports/
```

## 🔒 Security-First Design

This auditor is built with security as a priority:

- **No `eval`/`exec`** - Only `yaml.safe_load()` for parsing
- **Path Traversal Prevention** - All file paths are validated
- **Secret Redaction** - Sensitive data never appears in logs or reports
- **XSS Prevention** - HTML reports use proper escaping
- **Input Validation** - All external inputs are validated
- **Type Safety** - Full type hints with mypy enforcement

## 📈 SLSA Compliance

The auditor evaluates workflows against [SLSA](https://slsa.dev/) requirements:

| Level | Requirements |
|-------|--------------|
| **Level 1** | Documented build process |
| **Level 2** | Version control + hosted build service |
| **Level 3** | Ephemeral environment + signed provenance |
| **Level 4** | Hermetic + reproducible builds |

## 🧪 Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/ -v --cov=auditor

# Run linting
ruff check auditor/

# Run type checking
mypy auditor/

# Run security scan
bandit -r auditor/
```

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas we'd love help with:
- Adding checks for more security patterns
- Supporting additional CI/CD platforms (Jenkins, CircleCI, etc.)
- Improving documentation
- Writing more tests

## 📜 License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is for auditing and educational purposes. Always ensure you have authorization before scanning any systems or pipelines. The tool identifies potential issues but cannot guarantee complete security coverage.

## 🙏 Acknowledgments

- [SLSA Framework](https://slsa.dev/) for supply chain security guidelines
- [GitHub Security Lab](https://securitylab.github.com/) for research on Actions security
- [OWASP](https://owasp.org/) for CI/CD security best practices
