"""
Pytest fixtures and configuration.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_github_workflow() -> str:
    """Sample GitHub Actions workflow content."""
    return '''
name: CI
on: [push, pull_request]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: echo "Testing"
'''


@pytest.fixture
def vulnerable_github_workflow() -> str:
    """GitHub Actions workflow with security issues."""
    return '''
name: Vulnerable CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@v4
      - uses: some-owner/some-action@main
      - name: Dangerous script
        run: |
          echo ${{ github.event.issue.title }}
          curl -s https://example.com/install.sh | bash
'''


@pytest.fixture
def sample_gitlab_ci() -> str:
    """Sample GitLab CI content."""
    return '''
stages:
  - build
  - test

variables:
  DOCKER_IMAGE: python:3.11

build:
  stage: build
  script:
    - pip install -r requirements.txt
    - python setup.py build

test:
  stage: test
  script:
    - pytest tests/
'''


@pytest.fixture
def workflow_dir(temp_dir: Path, sample_github_workflow: str) -> Path:
    """Create a directory with a sample workflow."""
    workflows_dir = temp_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    
    workflow_file = workflows_dir / "ci.yml"
    workflow_file.write_text(sample_github_workflow)
    
    return temp_dir


@pytest.fixture
def vulnerable_workflow_dir(temp_dir: Path, vulnerable_github_workflow: str) -> Path:
    """Create a directory with a vulnerable workflow."""
    workflows_dir = temp_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)
    
    workflow_file = workflows_dir / "ci.yml"
    workflow_file.write_text(vulnerable_github_workflow)
    
    return temp_dir
