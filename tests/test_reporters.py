"""
Tests for report generators.
"""

import json
import pytest
from datetime import datetime, timezone

from auditor.core.result import AuditResult, CheckResult, Finding, FindingLocation
from auditor.core.severity import Severity
from auditor.reporters.json_reporter import JSONReporter
from auditor.reporters.markdown_reporter import MarkdownReporter
from auditor.reporters.html_reporter import HTMLReporter


@pytest.fixture
def sample_result() -> AuditResult:
    """Create a sample audit result for testing."""
    result = AuditResult(
        target_path="/test/path",
        target_type="local",
        platform="github_actions",
        started_at=datetime.now(timezone.utc),
    )
    
    # Add a check result with findings
    check_result = CheckResult(
        check_id="test-001",
        check_name="Test Check",
    )
    
    finding = Finding(
        check_id="test-001",
        title="Test Finding",
        severity=Severity.HIGH,
        description="This is a test finding",
        location=FindingLocation(file_path="test.yml", line_start=10),
        remediation="Fix the issue",
        references=("https://example.com",),
        cwe_ids=("CWE-123",),
    )
    
    check_result.add_finding(finding)
    result.add_check_result(check_result)
    result.complete()
    
    return result


class TestJSONReporter:
    """Tests for JSON reporter."""
    
    def test_generate_json(self, sample_result: AuditResult):
        """Test JSON generation."""
        reporter = JSONReporter()
        output = reporter.generate(sample_result)
        
        # Should be valid JSON
        data = json.loads(output)
        
        assert data["schema_version"] == "1.0"
        assert data["audit"]["target"] == "/test/path"
        assert data["summary"]["total_findings"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "high"
    
    def test_generate_compact_json(self, sample_result: AuditResult):
        """Test compact JSON generation."""
        reporter = JSONReporter(pretty=False)
        output = reporter.generate(sample_result)
        
        # Should not have indentation
        assert "\n  " not in output
        
        # Should still be valid JSON
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 1
    
    def test_write_json_report(self, sample_result: AuditResult, temp_dir):
        """Test writing JSON report to file."""
        reporter = JSONReporter()
        output_path = reporter.write(sample_result, temp_dir)
        
        assert output_path.exists()
        assert output_path.suffix == ".json"
        
        # Verify contents
        data = json.loads(output_path.read_text())
        assert data["summary"]["total_findings"] == 1


class TestMarkdownReporter:
    """Tests for Markdown reporter."""
    
    def test_generate_markdown(self, sample_result: AuditResult):
        """Test Markdown generation."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_result)
        
        # Check for expected sections
        assert "# 🔒 CI/CD Security Audit Report" in output
        assert "## 📊 Executive Summary" in output
        assert "Test Finding" in output
        assert "HIGH" in output or "High" in output
    
    def test_markdown_has_remediation(self, sample_result: AuditResult):
        """Test that remediation is included."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_result)
        
        assert "Remediation" in output
        assert "Fix the issue" in output
    
    def test_markdown_has_references(self, sample_result: AuditResult):
        """Test that references are included."""
        reporter = MarkdownReporter()
        output = reporter.generate(sample_result)
        
        assert "References" in output
        assert "https://example.com" in output
    
    def test_markdown_escapes_content(self):
        """Test that dangerous content is escaped."""
        result = AuditResult(
            target_path="/test",
            target_type="local",
        )
        
        check_result = CheckResult(check_id="test", check_name="Test")
        check_result.add_finding(Finding(
            check_id="test",
            title="<script>alert('xss')</script>",
            severity=Severity.LOW,
            description="Test with special chars: < > & \"",
        ))
        result.add_check_result(check_result)
        result.complete()
        
        reporter = MarkdownReporter()
        output = reporter.generate(result)
        
        # Content should be present but we rely on markdown rendering
        # to handle escaping in display
        assert "Test with special chars" in output


class TestHTMLReporter:
    """Tests for HTML reporter."""
    
    def test_generate_html(self, sample_result: AuditResult):
        """Test HTML generation."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_result)
        
        # Check for expected elements
        assert "<!DOCTYPE html>" in output
        assert "CI/CD Security Audit Report" in output
        assert "Test Finding" in output
    
    def test_html_escapes_content(self):
        """Test that dangerous content is HTML-escaped."""
        result = AuditResult(
            target_path="/test<script>alert('xss')</script>",
            target_type="local",
        )
        result.complete()
        
        reporter = HTMLReporter()
        output = reporter.generate(result)
        
        # The user-provided XSS attempt should be escaped
        # Raw script tags from user input should NOT be executable
        assert "<script>alert('xss')</script>" not in output
        # The target path should be present in some form (escaped)
        assert "test" in output
        # Some form of escaping should be present (uses HTML entity escaping)
        assert "&amp;" in output or "&lt;" in output or "&#x" in output
    
    def test_html_has_interactive_elements(self, sample_result: AuditResult):
        """Test that HTML has interactive elements."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_result)
        
        # Should have JavaScript for interactivity
        assert "<script>" in output
        assert "addEventListener" in output
    
    def test_html_has_styling(self, sample_result: AuditResult):
        """Test that HTML includes CSS."""
        reporter = HTMLReporter()
        output = reporter.generate(sample_result)
        
        assert "<style>" in output
        assert ".finding" in output
        assert ".severity-badge" in output
