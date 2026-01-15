# Contributing to CI-CD-Supply-Chain-Auditor

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- (Optional) A virtual environment tool like `venv` or `conda`

### Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/raghu-007/CI-CD-Supply-Chain-Auditor.git
   cd CI-CD-Supply-Chain-Auditor
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   pip install -e .
   ```

4. **Run tests to verify setup:**
   ```bash
   pytest tests/ -v
   ```

## 🔒 Security-First Development

This project takes security seriously. All contributions must follow these secure coding practices:

### Mandatory Security Practices

1. **Input Validation**
   - Validate ALL external input (file paths, YAML content, user input)
   - Use the validators in `auditor/parsers/validators.py`
   - Never trust data from pipeline files

2. **No Dynamic Code Execution**
   - Never use `eval()`, `exec()`, or similar
   - Always use `yaml.safe_load()` instead of `yaml.load()`
   - No string-based command construction

3. **Secret Handling**
   - Never log secrets or sensitive data
   - Use the sanitizers in `auditor/utils/sanitizer.py`
   - Redact any potential secrets before including in findings

4. **Path Security**
   - Use `auditor.parsers.validators.validate_file_path()` for all paths
   - Prevent path traversal attacks
   - Be careful with symlinks

5. **Output Sanitization**
   - Escape HTML in reports to prevent XSS
   - Truncate long strings
   - Use the reporters' built-in sanitization

### Pre-commit Checks

Before committing, ensure your code passes:

```bash
# Run linting
ruff check auditor/

# Run type checking
mypy auditor/

# Run security scan
bandit -r auditor/

# Run tests
pytest tests/ -v --cov=auditor
```

## 🏗️ Project Structure

```
CI-CD-Supply-Chain-Auditor/
├── auditor/                 # Main package
│   ├── core/               # Core analysis engine
│   ├── parsers/            # Pipeline parsers
│   ├── checks/             # Security checks
│   ├── reporters/          # Report generators
│   └── utils/              # Utility modules
├── tests/                  # Test suite
├── examples/               # Example configurations
└── .github/workflows/      # CI/CD workflows
```

## ✨ Adding New Features

### Adding a New Security Check

1. Create a new file in `auditor/checks/`:
   ```python
   from auditor.checks.base import BaseCheck
   
   class MyNewCheck(BaseCheck):
       @property
       def id(self) -> str:
           return "mycheck-001"
       
       @property
       def name(self) -> str:
           return "My New Check"
       
       # ... implement run() method
   ```

2. Register in `auditor/checks/__init__.py`

3. Add to `auditor/core/analyzer.py` in `_load_checks()`

4. Add tests in `tests/test_checks.py`

### Adding a New Parser

1. Create a new parser in `auditor/parsers/` extending `BaseParser`

2. Implement required methods: `name`, `file_patterns`, `_parse_content`

3. Register in `auditor/parsers/__init__.py`

4. Add to analyzer's `_load_parsers()` method

### Adding a New Reporter

1. Create a new reporter in `auditor/reporters/` extending `BaseReporter`

2. Implement required methods: `format_name`, `file_extension`, `generate`

3. Register in `auditor/reporters/__init__.py`

4. Add to CLI in `auditor/cli.py`

## 📝 Code Style

- Follow PEP 8 with a line length of 100 characters
- Use type hints for all function signatures
- Write docstrings for public classes and methods
- Keep functions focused and under 50 lines when possible

## 🧪 Testing

- Aim for >80% test coverage
- Write unit tests for new functionality
- Include both positive and negative test cases
- Test security edge cases

## 📋 Pull Request Process

1. **Fork and branch:** Create a feature branch from `main`

2. **Develop:** Make your changes following the guidelines above

3. **Test:** Ensure all tests pass and add new tests as needed

4. **Document:** Update documentation if needed

5. **Submit:** Create a PR with a clear description of changes

### PR Checklist

- [ ] Code follows security practices
- [ ] All tests pass
- [ ] Type hints are complete
- [ ] Documentation is updated
- [ ] No secrets or sensitive data in code

## 🐛 Reporting Issues

When reporting bugs, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages (sanitized of any secrets)

## 💡 Feature Requests

Feature requests are welcome! Please include:

- Use case description
- Proposed solution
- Any security considerations

## 📜 License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

## 🙏 Thank You!

Your contributions help make CI/CD pipelines more secure for everyone!
