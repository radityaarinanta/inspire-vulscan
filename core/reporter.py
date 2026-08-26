import os
import io
import json
import csv
import html
from datetime import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import ScanResult, Severity, FindingEvidence, MalwareScanResult

class ReportGenerator:
    def __init__(self, template_dir: str = "templates", reports_dir: str = "reports"):
        self.template_dir = template_dir
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

        if os.path.exists(self.template_dir):
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.template_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None

    def generate_json_report(self, result: ScanResult, filename: str = None) -> str:
        """Generates comprehensive structured JSON audit report."""
        filename = filename or f"inspire_scan_report_{result.scan_id}.json"
        filepath = os.path.join(self.reports_dir, filename)

        data = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "generator": {
                "name": "Inspire Security Audit Suite",
                "version": "1.0.0",
                "schema_version": "1.0.0",
                "website": "https://github.com/radityaarinanta/inspire-vulscan",
                "generated_at": datetime.utcnow().isoformat() + "Z"
            },
            "scan_data": result.model_dump()
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return filepath

    def generate_sarif_report(self, result: ScanResult, filename: str = None) -> str:
        """
        Generates standard OASIS SARIF v2.1.0 report.
        Compatible with GitHub Security Code Scanning and IDE SARIF viewers.
        """
        filename = filename or f"inspire_scan_report_{result.scan_id}.sarif"
        filepath = os.path.join(self.reports_dir, filename)

        rules = []
        rule_indices = {}
        sarif_results = []

        for vuln in result.vulnerabilities:
            # Register rule if not already present
            if vuln.id not in rule_indices:
                rule_idx = len(rules)
                rule_indices[vuln.id] = rule_idx
                
                # Severity to SARIF level mapping
                if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                    level = "error"
                elif vuln.severity == Severity.MEDIUM:
                    level = "warning"
                else:
                    level = "note"

                tags = ["security", vuln.category]
                if vuln.cwe_id:
                    tags.append(vuln.cwe_id)
                if vuln.owasp_category:
                    tags.append(vuln.owasp_category)

                rule_obj = {
                    "id": vuln.id,
                    "name": vuln.name.replace(" ", "_").replace("'", "").replace('"', ""),
                    "shortDescription": {"text": vuln.name},
                    "fullDescription": {"text": vuln.description},
                    "help": {
                        "text": f"Remediation:\n{vuln.remediation}\n\nImpact:\n{vuln.impact}",
                        "markdown": f"### Remediation\n{vuln.remediation}\n\n### Impact\n{vuln.impact}"
                    },
                    "helpUri": vuln.references[0] if vuln.references else "https://owasp.org/www-project-top-ten/",
                    "properties": {
                        "tags": tags,
                        "precision": "high",
                        "security-severity": str(vuln.cvss_score)
                    },
                    "defaultConfiguration": {
                        "level": level
                    }
                }
                rules.append(rule_obj)
            else:
                rule_idx = rule_indices[vuln.id]

            # Build result instance
            if vuln.severity in [Severity.CRITICAL, Severity.HIGH]:
                res_level = "error"
            elif vuln.severity == Severity.MEDIUM:
                res_level = "warning"
            else:
                res_level = "note"

            locations = []
            ev_list = vuln.evidence if vuln.evidence else [FindingEvidence(url=result.target_url, description="Security finding")]
            for ev in ev_list:
                loc = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": ev.url or result.target_url
                        },
                        "region": {
                            "startLine": 1,
                            "snippet": {
                                "text": ev.response_snippet or ev.payload or ev.description
                            }
                        }
                    }
                }
                if ev.parameter:
                    loc["logicalLocations"] = [
                        {
                            "name": ev.parameter,
                            "kind": "parameter"
                        }
                    ]
                locations.append(loc)

            sarif_results.append({
                "ruleId": vuln.id,
                "ruleIndex": rule_idx,
                "level": res_level,
                "message": {
                    "text": f"[{vuln.severity.value}] {vuln.name} detected at {result.target_url}. {vuln.description}"
                },
                "locations": locations,
                "properties": {
                    "cvss_score": vuln.cvss_score,
                    "cwe_id": vuln.cwe_id,
                    "owasp_category": vuln.owasp_category,
                    "severity": vuln.severity.value
                }
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Inspire Security Suite",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://github.com/radityaarinanta/inspire-vulscan",
                            "rules": rules
                        }
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": result.end_time or (datetime.utcnow().isoformat() + "Z")
                        }
                    ]
                }
            ]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2, ensure_ascii=False)

        return filepath

    def generate_csv_report(self, result: ScanResult, filename: str = None) -> str:
        """Generates structured CSV report for spreadsheet audits."""
        filename = filename or f"inspire_scan_report_{result.scan_id}.csv"
        filepath = os.path.join(self.reports_dir, filename)

        headers = [
            "Vulnerability ID",
            "Severity",
            "CVSS Score",
            "Vulnerability Name",
            "Category",
            "OWASP Category",
            "CWE ID",
            "Affected URL / Endpoint",
            "Parameter",
            "Payload",
            "Description",
            "Impact",
            "Remediation",
            "References",
            "Discovered At"
        ]

        with open(filepath, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for vuln in result.vulnerabilities:
                ev_urls = "; ".join([ev.url for ev in vuln.evidence if ev.url]) or result.target_url
                ev_params = "; ".join([ev.parameter for ev in vuln.evidence if ev.parameter]) or "N/A"
                ev_payloads = "; ".join([ev.payload for ev in vuln.evidence if ev.payload]) or "N/A"
                refs = "; ".join(vuln.references) if vuln.references else "N/A"

                writer.writerow([
                    vuln.id,
                    vuln.severity.value,
                    vuln.cvss_score,
                    vuln.name,
                    vuln.category,
                    vuln.owasp_category or "N/A",
                    vuln.cwe_id or "N/A",
                    ev_urls,
                    ev_params,
                    ev_payloads,
                    vuln.description,
                    vuln.impact,
                    vuln.remediation,
                    refs,
                    vuln.timestamp
                ])

        return filepath

    def generate_html_report(self, result: ScanResult, filename: str = None) -> str:
        filename = filename or f"inspire_scan_report_{result.scan_id}.html"
        filepath = os.path.join(self.reports_dir, filename)

        if self.jinja_env:
            try:
                template = self.jinja_env.get_template("report_template.html")
                rendered_html = template.render(
                    result=result,
                    now=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                )
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(rendered_html)
                return filepath
            except Exception:
                pass

        # Fallback inline HTML generator
        html_content = self._build_fallback_html(result)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filepath

    def generate_pdf_report(self, result: ScanResult, filename: str = None) -> str:
        filename = filename or f"inspire_scan_report_{result.scan_id}.pdf"
        filepath = os.path.join(self.reports_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0F172A')
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#64748B')
        )
        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#0F172A'),
            spaceBefore=14,
            spaceAfter=6
        )
        body_text = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        code_snippet = ParagraphStyle(
            'CodeSnippet',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#0F172A'),
            backColor=colors.HexColor('#F1F5F9'),
            borderPadding=4
        )

        story = []

        # Header / Branding Banner
        story.append(Paragraph("INSPIRE SECURITY AUDIT REPORT", title_style))
        story.append(Paragraph(f"Automated Web Vulnerability & Compliance Assessment | Target: <b>{result.target_url}</b>", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00F0FF'), spaceAfter=15))

        # Executive Summary Box
        summary = result.summary
        grade_color = colors.HexColor('#10B981') if summary.security_grade in ['A+', 'A'] else colors.HexColor('#F59E0B') if summary.security_grade == 'B' else colors.HexColor('#EF4444')

        summary_data = [
            [
                Paragraph("<b>Target URL:</b>", body_text), Paragraph(result.target_url, body_text),
                Paragraph("<b>Overall Grade:</b>", body_text), Paragraph(f"<b><font size=14 color='{grade_color.hexval()}'>{summary.security_grade}</font></b>", body_text)
            ],
            [
                Paragraph("<b>Scan ID:</b>", body_text), Paragraph(result.scan_id, body_text),
                Paragraph("<b>Risk Score:</b>", body_text), Paragraph(f"<b>{summary.risk_score} / 100</b>", body_text)
            ],
            [
                Paragraph("<b>Scan Date:</b>", body_text), Paragraph(result.start_time[:19].replace('T', ' ') + " UTC", body_text),
                Paragraph("<b>Duration:</b>", body_text), Paragraph(f"{summary.duration_seconds}s", body_text)
            ],
            [
                Paragraph("<b>Total Findings:</b>", body_text), Paragraph(f"<b>{summary.total_findings}</b>", body_text),
                Paragraph("<b>Pages Crawled:</b>", body_text), Paragraph(f"{summary.urls_crawled_count}", body_text)
            ]
        ]

        summary_table = Table(summary_data, colWidths=[100, 180, 100, 160])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 15))

        # Severity Breakdown Table
        story.append(Paragraph("Vulnerability Severity Breakdown", section_heading))
        
        breakdown_data = [
            [
                Paragraph("<b>Severity Level</b>", body_text),
                Paragraph("<b>Findings Count</b>", body_text),
                Paragraph("<b>Risk Description</b>", body_text)
            ],
            [
                Paragraph("<font color='#EF4444'><b>CRITICAL</b></font>", body_text),
                Paragraph(f"<b>{summary.critical_count}</b>", body_text),
                Paragraph("Immediate exploitation possible; remote code execution or complete data exposure.", body_text)
            ],
            [
                Paragraph("<font color='#F97316'><b>HIGH</b></font>", body_text),
                Paragraph(f"<b>{summary.high_count}</b>", body_text),
                Paragraph("Severe impact on confidentiality/integrity (e.g. XSS, Source leak).", body_text)
            ],
            [
                Paragraph("<font color='#F59E0B'><b>MEDIUM</b></font>", body_text),
                Paragraph(f"<b>{summary.medium_count}</b>", body_text),
                Paragraph("Moderate security misconfigurations (e.g. Missing CSP/HSTS).", body_text)
            ],
            [
                Paragraph("<font color='#3B82F6'><b>LOW</b></font>", body_text),
                Paragraph(f"<b>{summary.low_count}</b>", body_text),
                Paragraph("Low impact, clickjacking or minor cookie attribute omissions.", body_text)
            ],
            [
                Paragraph("<font color='#6B7280'><b>INFORMATIONAL</b></font>", body_text),
                Paragraph(f"<b>{summary.info_count}</b>", body_text),
                Paragraph("Banner leaks, robots.txt endpoints, tech discovery.", body_text)
            ]
        ]
        breakdown_table = Table(breakdown_data, colWidths=[120, 100, 320])
        breakdown_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(breakdown_table)
        story.append(Spacer(1, 15))

        # Detected Tech Stack
        if result.technologies:
            story.append(Paragraph("Identified Technologies & Infrastructure", section_heading))
            tech_str = ", ".join([f"<b>{t.name}</b> ({t.category}{f' v{t.version}' if t.version else ''})" for t in result.technologies])
            story.append(Paragraph(tech_str, body_text))
            story.append(Spacer(1, 15))

        # Detailed Findings Section
        story.append(Paragraph("Detailed Security Findings & Remediation Roadmap", section_heading))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=10))

        if not result.vulnerabilities:
            story.append(Paragraph("✓ No vulnerabilities detected for the configured scan profile.", body_text))
        else:
            for idx, vuln in enumerate(result.vulnerabilities, 1):
                sev_color = '#EF4444' if vuln.severity == Severity.CRITICAL else '#F97316' if vuln.severity == Severity.HIGH else '#F59E0B' if vuln.severity == Severity.MEDIUM else '#3B82F6' if vuln.severity == Severity.LOW else '#6B7280'
                
                finding_elements = []
                finding_elements.append(Paragraph(f"<b>#{idx}. {vuln.name}</b>", ParagraphStyle('VulnTitle', parent=section_heading, fontSize=11, leading=14)))
                
                # Meta line
                meta_line = f"<b>Severity:</b> <font color='{sev_color}'><b>{vuln.severity.value}</b></font> | <b>CVSS:</b> {vuln.cvss_score} | <b>CWE:</b> {vuln.cwe_id or 'N/A'} | <b>OWASP:</b> {vuln.owasp_category or 'N/A'}"
                finding_elements.append(Paragraph(meta_line, body_text))
                finding_elements.append(Spacer(1, 4))

                # Description & Impact
                finding_elements.append(Paragraph(f"<b>Description:</b> {vuln.description}", body_text))
                finding_elements.append(Paragraph(f"<b>Impact:</b> {vuln.impact}", body_text))
                finding_elements.append(Paragraph(f"<b>Remediation:</b> <font color='#059669'>{vuln.remediation}</font>", body_text))

                # Evidence
                if vuln.evidence:
                    for ev in vuln.evidence:
                        ev_txt = f"URL: {ev.url}"
                        if ev.parameter:
                            ev_txt += f" | Param: {ev.parameter}"
                        if ev.payload:
                            ev_txt += f" | Payload: {ev.payload}"
                        if ev.response_snippet:
                            ev_txt += f"\nEvidence: {ev.response_snippet}"
                        finding_elements.append(Spacer(1, 3))
                        finding_elements.append(Paragraph(ev_txt, code_snippet))

                finding_elements.append(Spacer(1, 8))
                finding_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#E2E8F0'), spaceAfter=8))
                story.append(KeepTogether(finding_elements))

        # Build Document
        doc.build(story)
        return filepath

    def _build_fallback_html(self, result: ScanResult) -> str:
        """Self-contained standalone HTML report fallback"""
        summary = result.summary
        vuln_rows = ""
        for v in result.vulnerabilities:
            sev_class = v.severity.value.lower()
            evidence_html = ""
            for ev in v.evidence:
                evidence_html += f"""
                <div class="evidence-box">
                    <strong>Endpoint:</strong> <code>{ev.url}</code><br>
                    {f'<strong>Parameter:</strong> <code>{ev.parameter}</code><br>' if ev.parameter else ''}
                    {f'<strong>Payload:</strong> <code>{ev.payload}</code><br>' if ev.payload else ''}
                    {f'<strong>Response Snippet:</strong> <pre>{ev.response_snippet}</pre>' if ev.response_snippet else ''}
                </div>
                """
            vuln_rows += f"""
            <div class="card vuln-card sev-{sev_class}">
                <div class="vuln-header">
                    <span class="badge badge-{sev_class}">{v.severity.value}</span>
                    <span class="cvss-badge">CVSS {v.cvss_score}</span>
                    <h3>{v.name}</h3>
                </div>
                <div class="vuln-meta">
                    <span><strong>Category:</strong> {v.category}</span>
                    <span><strong>CWE:</strong> {v.cwe_id or 'N/A'}</span>
                    <span><strong>OWASP:</strong> {v.owasp_category or 'N/A'}</span>
                </div>
                <p><strong>Description:</strong> {v.description}</p>
                <p><strong>Impact:</strong> {v.impact}</p>
                <div class="remediation-box">
                    <strong>Remediation Advice:</strong> {v.remediation}
                </div>
                {evidence_html}
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Inspire Security Audit Report - {result.target_url}</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --border: #1f2937;
            --text: #f3f4f6;
            --text-muted: #9ca3af;
            --cyan: #00f0ff;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #6b7280;
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 40px; margin: 0; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ border-bottom: 2px solid var(--cyan); padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; color: var(--cyan); font-size: 28px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 15px; text-align: center; }}
        .stat-val {{ font-size: 24px; font-weight: bold; color: var(--cyan); }}
        .stat-lbl {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; margin-top: 5px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .vuln-card {{ border-left: 4px solid var(--border); }}
        .vuln-card.sev-critical {{ border-left-color: var(--critical); }}
        .vuln-card.sev-high {{ border-left-color: var(--high); }}
        .vuln-card.sev-medium {{ border-left-color: var(--medium); }}
        .vuln-card.sev-low {{ border-left-color: var(--low); }}
        .vuln-card.sev-info {{ border-left-color: var(--info); }}
        .vuln-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
        .vuln-header h3 {{ margin: 0; font-size: 18px; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); }}
        .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--medium); }}
        .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); }}
        .badge-info {{ background: rgba(107, 114, 128, 0.2); color: var(--info); }}
        .cvss-badge {{ background: #1e293b; color: #94a3b8; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-family: monospace; }}
        .vuln-meta {{ display: flex; gap: 20px; color: var(--text-muted); font-size: 13px; margin-bottom: 12px; }}
        .remediation-box {{ background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 10px 15px; border-radius: 4px; margin: 12px 0; color: #a7f3d0; }}
        .evidence-box {{ background: #070a12; border: 1px solid #1e293b; padding: 10px; border-radius: 4px; font-size: 12px; margin-top: 10px; }}
        pre {{ background: #030712; padding: 8px; border-radius: 4px; overflow-x: auto; color: #38bdf8; margin: 5px 0 0 0; }}
        code {{ color: var(--cyan); font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>INSPIRE Security Audit Report</h1>
            <p style="color: var(--text-muted); margin: 5px 0 0 0;">Target: <strong>{result.target_url}</strong> | Scan ID: {result.scan_id} | Completed: {result.end_time}</p>
        </div>

        <div class="grid">
            <div class="stat-card">
                <div class="stat-val">{summary.security_grade}</div>
                <div class="stat-lbl">Security Grade</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{summary.risk_score} / 100</div>
                <div class="stat-lbl">Risk Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{summary.total_findings}</div>
                <div class="stat-lbl">Total Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{summary.duration_seconds}s</div>
                <div class="stat-lbl">Scan Duration</div>
            </div>
        </div>

        <h2>Security Findings ({summary.total_findings})</h2>
        {vuln_rows if vuln_rows else '<p style="color: var(--text-muted);">No security issues identified.</p>'}
    </div>
</body>
</html>"""

    # =========================================================================
    # MALWARE & THREAT REPORTS
    # =========================================================================

    def generate_malware_json_report(self, result: MalwareScanResult, filename: Optional[str] = None) -> str:
        filename = filename or f"inspire_malware_report_{result.scan_id}.json"
        filepath = os.path.join(self.reports_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))
        return filepath

    def generate_malware_csv_report(self, result: MalwareScanResult, filename: Optional[str] = None) -> str:
        filename = filename or f"inspire_malware_report_{result.scan_id}.csv"
        filepath = os.path.join(self.reports_dir, filename)
        
        headers = [
            "Threat ID",
            "Threat Name",
            "Category",
            "Severity",
            "Threat Score",
            "Affected URL",
            "Description",
            "Impact",
            "Remediation",
            "Evidence"
        ]

        with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for f_item in result.findings:
                writer.writerow([
                    f_item.id,
                    f_item.name,
                    f_item.category.value if hasattr(f_item.category, "value") else str(f_item.category),
                    f_item.severity.value if hasattr(f_item.severity, "value") else str(f_item.severity),
                    f_item.threat_score,
                    f_item.affected_url,
                    f_item.description,
                    f_item.impact,
                    f_item.remediation,
                    f_item.evidence_snippet or ""
                ])

        return filepath

    def generate_malware_html_report(self, result: MalwareScanResult, filename: Optional[str] = None) -> str:
        filename = filename or f"inspire_malware_report_{result.scan_id}.html"
        filepath = os.path.join(self.reports_dir, filename)
        summary = result.summary

        verdict_color = "#10b981" if summary.is_clean else "#ef4444" if summary.overall_threat_score >= 80 else "#f59e0b"

        finding_rows = ""
        for idx, f in enumerate(result.findings, 1):
            sev_val = f.severity.value.upper()
            sev_color = "#ef4444" if sev_val == "CRITICAL" else "#f97316" if sev_val == "HIGH" else "#f59e0b"
            cat_val = f.category.value if hasattr(f.category, "value") else str(f.category)
            evidence = f"""<div style="background:#030712;border:1px solid #1f2937;padding:10px;border-radius:6px;font-family:monospace;font-size:12px;color:#38bdf8;margin-top:10px;">{html.escape(f.evidence_snippet or '')}</div>""" if f.evidence_snippet else ""

            finding_rows += f"""
            <div style="background:#111827;border:1px solid #1f2937;border-left:4px solid {sev_color};border-radius:8px;padding:18px;margin-bottom:16px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                    <h3 style="color:#fff;font-size:16px;margin:0;">#{idx}. {html.escape(f.name)}</h3>
                    <div>
                        <span style="background:rgba(255,255,255,0.08);padding:3px 8px;border-radius:4px;color:{sev_color};font-weight:bold;font-size:11px;">{sev_val}</span>
                        <span style="background:rgba(0,240,255,0.1);color:#00f0ff;padding:3px 8px;border-radius:4px;font-size:11px;margin-left:6px;">Score {f.threat_score}</span>
                    </div>
                </div>
                <div style="font-size:12px;color:#9ca3af;margin-bottom:10px;">
                    <span>Category: <strong>{html.escape(cat_val)}</strong></span> | <span>Affected: <code>{html.escape(f.affected_url)}</code></span>
                </div>
                <p style="color:#d1d5db;font-size:13px;margin-bottom:8px;"><strong>Description:</strong> {html.escape(f.description)}</p>
                <p style="color:#d1d5db;font-size:13px;margin-bottom:8px;"><strong>Impact:</strong> {html.escape(f.impact)}</p>
                <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);border-radius:6px;padding:10px;color:#6ee7b7;font-size:13px;margin-top:10px;">
                    <strong>Remediation:</strong> {html.escape(f.remediation)}
                </div>
                {evidence}
            </div>
            """

        cat_cards = ""
        for cat in result.categories:
            status_color = "#ef4444" if cat.is_infected else "#10b981"
            cat_name = cat.category.value if hasattr(cat.category, "value") else str(cat.category)
            status_text = "THREAT DETECTED" if cat.is_infected else "CLEAN"
            cat_cards += f"""
            <div style="background:#111827;border:1px solid #1f2937;border-radius:8px;padding:14px;display:flex;justify-content:space-between;align-items:center;">
                <span style="font-weight:600;font-size:13px;color:#f3f4f6;">{cat_name}</span>
                <span style="font-size:11px;font-weight:bold;color:{status_color};background:rgba(255,255,255,0.05);padding:3px 8px;border-radius:4px;">{status_text}</span>
            </div>
            """

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Inspire Malware & Threat Report - {result.target_url}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f3f4f6; padding: 30px 20px; }}
        .container {{ max-width: 950px; margin: 0 auto; }}
        .header {{ background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .verdict-badge {{ font-size: 16px; font-weight: 800; padding: 8px 16px; border-radius: 8px; color: {verdict_color}; border: 1px solid {verdict_color}; background: rgba(255,255,255,0.04); text-transform: uppercase; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }}
        .stat-card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; text-align: center; }}
        .stat-val {{ font-size: 22px; font-weight: 800; color: #00f0ff; }}
        .stat-lbl {{ font-size: 11px; text-transform: uppercase; color: #9ca3af; margin-top: 4px; }}
        .cat-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 24px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0;font-size:22px;color:#fff;">INSPIRE Threat & Malware Audit Report</h1>
                <p style="color:#9ca3af;font-size:13px;margin:5px 0 0 0;">Target: <strong>{result.target_url}</strong> | Scan ID: {result.scan_id} | Completed: {result.end_time}</p>
            </div>
            <div class="verdict-badge">{summary.verdict}</div>
        </div>

        <div class="grid">
            <div class="stat-card">
                <div class="stat-val" style="color: {verdict_color};">{summary.overall_threat_score} / 100</div>
                <div class="stat-lbl">Overall Threat Score</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{summary.total_threats}</div>
                <div class="stat-lbl">Detected Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{summary.scripts_analyzed}</div>
                <div class="stat-lbl">Scripts Analyzed</div>
            </div>
            <div class="stat-card">
                <div class="stat-val">{summary.duration_seconds}s</div>
                <div class="stat-lbl">Scan Duration</div>
            </div>
        </div>

        <h2 style="font-size:16px;color:#fff;margin-bottom:12px;">Threat Category Breakdown</h2>
        <div class="cat-grid">
            {cat_cards}
        </div>

        <h2 style="font-size:16px;color:#fff;margin-bottom:12px;">Detailed Findings ({summary.total_threats})</h2>
        {finding_rows if finding_rows else '<p style="color:#10b981;font-size:14px;">✓ No malware signatures, cryptominers, or backdoors identified on this target.</p>'}
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return filepath

