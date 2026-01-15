"""
Entry point for running the auditor as a module.

Usage:
    python -m auditor --help
    python -m auditor scan --path /path/to/repo
"""

from auditor.cli import main

if __name__ == "__main__":
    main()
