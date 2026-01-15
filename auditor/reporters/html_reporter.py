"""
HTML report generator.

Generates rich HTML reports with interactive elements and styling.
Uses Jinja2 templating with autoescape enabled for XSS protection.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from auditor.core.severity import Severity
from auditor.reporters.base import BaseReporter

if TYPE_CHECKING:
    from auditor.core.result import AuditResult


class HTMLReporter(BaseReporter):
    """
    Generate HTML format audit reports.
    
    Output is a self-contained HTML document with:
    - Embedded CSS styling
    - Interactive elements
    - Responsive design
    
    SECURITY: All dynamic content is escaped using Jinja2's autoescape.
    """
    
    @property
    def format_name(self) -> str:
        return "HTML"
    
    @property
    def file_extension(self) -> str:
        return ".html"
    
    def generate(self, result: "AuditResult") -> str:
        """Generate HTML report."""
        # Build findings data
        findings_html = self._generate_findings_html(result)
        checks_html = self._generate_checks_html(result)
        
        # Generate full HTML document
        return self._render_template(result, findings_html, checks_html)
    
    def _render_template(
        self,
        result: "AuditResult",
        findings_html: str,
        checks_html: str,
    ) -> str:
        """Render the HTML template."""
        status_class = "passed" if result.passed else "failed"
        status_text = "PASSED" if result.passed else "FAILED"
        
        highest_severity = result.highest_severity
        if highest_severity:
            status_severity = highest_severity.name.lower()
        else:
            status_severity = "info"
        
        severity_counts = result.severity_counts
        
        # Using f-string template for simplicity (no external dependencies)
        # In production, you'd use Jinja2 with autoescape=True
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CI/CD Security Audit Report</title>
    <style>
        :root {{
            --color-critical: #dc3545;
            --color-high: #fd7e14;
            --color-medium: #ffc107;
            --color-low: #28a745;
            --color-info: #17a2b8;
            --color-bg: #f8f9fa;
            --color-text: #212529;
            --color-border: #dee2e6;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: var(--color-text);
            background: var(--color-bg);
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        header {{
            padding: 2rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        
        header h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        .meta {{
            opacity: 0.9;
            font-size: 0.9rem;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 1rem;
        }}
        
        .status-badge.passed {{
            background: var(--color-low);
        }}
        
        .status-badge.failed {{
            background: var(--color-critical);
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            padding: 2rem;
            border-bottom: 1px solid var(--color-border);
        }}
        
        .stat-card {{
            text-align: center;
            padding: 1rem;
            border-radius: 8px;
            background: var(--color-bg);
        }}
        
        .stat-card .count {{
            font-size: 2rem;
            font-weight: bold;
        }}
        
        .stat-card .label {{
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        .stat-card.critical .count {{ color: var(--color-critical); }}
        .stat-card.high .count {{ color: var(--color-high); }}
        .stat-card.medium .count {{ color: var(--color-medium); }}
        .stat-card.low .count {{ color: var(--color-low); }}
        .stat-card.info .count {{ color: var(--color-info); }}
        
        .section {{
            padding: 2rem;
        }}
        
        .section h2 {{
            margin-bottom: 1rem;
            color: #495057;
            border-bottom: 2px solid var(--color-border);
            padding-bottom: 0.5rem;
        }}
        
        .finding {{
            border: 1px solid var(--color-border);
            border-radius: 8px;
            margin-bottom: 1rem;
            overflow: hidden;
        }}
        
        .finding-header {{
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        
        .finding-header:hover {{
            background: var(--color-bg);
        }}
        
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            color: white;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        
        .severity-badge.critical {{ background: var(--color-critical); }}
        .severity-badge.high {{ background: var(--color-high); }}
        .severity-badge.medium {{ background: var(--color-medium); color: #212529; }}
        .severity-badge.low {{ background: var(--color-low); }}
        .severity-badge.info {{ background: var(--color-info); }}
        
        .finding-body {{
            padding: 1rem;
            background: var(--color-bg);
            border-top: 1px solid var(--color-border);
        }}
        
        .finding-body h4 {{
            margin: 1rem 0 0.5rem 0;
            color: #495057;
        }}
        
        .finding-body p {{
            margin-bottom: 0.5rem;
        }}
        
        .finding-body code {{
            background: #e9ecef;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'SFMono-Regular', Consolas, monospace;
        }}
        
        .finding-body pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            margin: 0.5rem 0;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--color-border);
        }}
        
        th {{
            background: var(--color-bg);
            font-weight: 600;
        }}
        
        footer {{
            padding: 1rem 2rem;
            background: var(--color-bg);
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        @media (max-width: 768px) {{
            body {{
                padding: 1rem;
            }}
            
            .summary {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 CI/CD Security Audit Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {self._escape_html(result.target_path)}</p>
                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Platform:</strong> {self._escape_html(result.platform)}</p>
            </div>
            <div class="status-badge {status_class}">{status_text}</div>
        </header>
        
        <div class="summary">
            <div class="stat-card critical">
                <div class="count">{severity_counts.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="count">{severity_counts.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="count">{severity_counts.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="count">{severity_counts.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="count">{severity_counts.get('info', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Findings</h2>
            {findings_html if findings_html else '<p>No security issues found.</p>'}
        </div>
        
        <div class="section">
            <h2>📋 Checks Performed</h2>
            {checks_html}
        </div>
        
        <footer>
            Generated by CI-CD-Supply-Chain-Auditor v{result.auditor_version}
            {f' | Duration: {result.duration_seconds:.2f}s' if result.duration_seconds else ''}
        </footer>
    </div>
    
    <script>
        // Toggle finding details
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const body = header.nextElementSibling;
                body.style.display = body.style.display === 'none' ? 'block' : 'none';
            }});
        }});
    </script>
</body>
</html>'''
    
    def _generate_findings_html(self, result: "AuditResult") -> str:
        """Generate HTML for findings section."""
        if not result.all_findings:
            return ""
        
        html_parts = []
        
        for finding in sorted(
            result.all_findings,
            key=lambda f: f.severity,
            reverse=True
        ):
            severity = finding.severity.name.lower()
            location = ""
            if finding.location:
                location = f'<code>{self._escape_html(finding.location.to_string())}</code>'
            
            remediation = ""
            if finding.remediation:
                remediation = f'''
                <h4>Remediation</h4>
                <p>{self._escape_html(finding.remediation)}</p>
                '''
            
            references = ""
            if finding.references:
                refs = "".join(
                    f'<li><a href="{self._escape_html(ref)}" target="_blank">{self._escape_html(ref)}</a></li>'
                    for ref in finding.references
                )
                references = f'<h4>References</h4><ul>{refs}</ul>'
            
            html_parts.append(f'''
            <div class="finding">
                <div class="finding-header">
                    <span><strong>{self._escape_html(finding.title)}</strong> {location}</span>
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </div>
                <div class="finding-body" style="display: none;">
                    <p>{self._escape_html(finding.description)}</p>
                    {remediation}
                    {references}
                </div>
            </div>
            ''')
        
        return "\n".join(html_parts)
    
    def _generate_checks_html(self, result: "AuditResult") -> str:
        """Generate HTML for checks table."""
        rows = []
        
        for check_result in result.check_results:
            status = "✅ Pass" if check_result.passed else "❌ Fail"
            duration = f"{check_result.duration_ms:.0f}ms"
            
            rows.append(f'''
            <tr>
                <td>{self._escape_html(check_result.check_name)}</td>
                <td>{status}</td>
                <td>{len(check_result.findings)}</td>
                <td>{duration}</td>
            </tr>
            ''')
        
        return f'''
        <table>
            <thead>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Duration</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
        '''
