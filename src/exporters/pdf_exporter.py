import os
from datetime import datetime
from typing import List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)

from src.exporters.base_exporter import BaseExporter
from src.models.vulnerability import ScanReport, Severity


class PDFExporter(BaseExporter):
    """Generates standalone professional PDF reports using ReportLab"""

    def export(self, report: ScanReport, output_path: str) -> str:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom Styles
        title_style = ParagraphStyle(
            'CoverTitle',
            parent=styles['Heading1'],
            fontSize=24,
            leading=28,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=10,
            alignment=0
        )

        subtitle_style = ParagraphStyle(
            'CoverSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#64748B'),
            spaceAfter=20
        )

        h1_style = ParagraphStyle(
            'Heading1_Custom',
            parent=styles['Heading1'],
            fontSize=16,
            leading=20,
            textColor=colors.HexColor('#0F172A'),
            spaceBefore=15,
            spaceAfter=8
        )

        h2_style = ParagraphStyle(
            'Heading2_Custom',
            parent=styles['Heading2'],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=10,
            spaceAfter=4
        )

        body_style = ParagraphStyle(
            'Body_Custom',
            parent=styles['Normal'],
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor('#334155'),
            spaceAfter=6
        )

        code_style = ParagraphStyle(
            'Code_Custom',
            parent=styles['Code'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0284C7'),
            backColor=colors.HexColor('#F1F5F9'),
            borderPadding=6,
            spaceAfter=6
        )

        story = []

        # Header Title Banner
        story.append(Paragraph(report.title, title_style))
        story.append(Paragraph(f"<b>Client:</b> {report.client_name} &nbsp;|&nbsp; <b>Project:</b> {report.project_name} &nbsp;|&nbsp; <b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#6366F1'), spaceAfter=15))

        # Executive Dashboard Grid Table
        story.append(Paragraph("Executive Dashboard Summary", h1_style))

        avg_comp = round(sum(d['compliance_score'] for d in report.compliance_summary.values()) / max(1, len(report.compliance_summary)), 1)

        metrics_data = [
            [
                Paragraph("<b>Health Grade</b>", body_style),
                Paragraph("<b>Total Findings</b>", body_style),
                Paragraph("<b>Overall Risk</b>", body_style),
                Paragraph("<b>Compliance Avg</b>", body_style)
            ],
            [
                Paragraph(f"<font size=18 color='#DC2626'><b>{report.security_health_grade}</b></font>", body_style),
                Paragraph(f"<font size=16><b>{report.total_vulnerabilities}</b></font>", body_style),
                Paragraph(f"<font size=16><b>{report.overall_risk_score} / 10</b></font>", body_style),
                Paragraph(f"<font size=16><b>{avg_comp}%</b></font>", body_style)
            ]
        ]

        metrics_table = Table(metrics_data, colWidths=[130, 130, 130, 130])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 15))

        # Executive Summary Paragraph
        story.append(Paragraph("Executive Overview", h2_style))
        story.append(Paragraph(report.executive_summary.replace('\n', '<br/>'), body_style))
        story.append(Spacer(1, 15))

        # Compliance Table
        story.append(Paragraph("Regulatory Compliance Posture", h1_style))
        comp_data = [[Paragraph("<b>Standard Framework</b>", body_style), Paragraph("<b>Violations</b>", body_style), Paragraph("<b>Pass Score</b>", body_style), Paragraph("<b>Status</b>", body_style)]]

        for fw, d in report.compliance_summary.items():
            status_color = "#16A34A" if d['status'] == "COMPLIANT" else "#DC2626"
            comp_data.append([
                Paragraph(fw, body_style),
                Paragraph(str(d['violations_count']), body_style),
                Paragraph(f"{d['compliance_score']}%", body_style),
                Paragraph(f"<font color='{status_color}'><b>{d['status']}</b></font>", body_style)
            ])

        comp_table = Table(comp_data, colWidths=[160, 100, 120, 140])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(comp_table)
        story.append(Spacer(1, 15))

        # Detailed Findings Section
        story.append(Paragraph(f"Detailed Vulnerability Findings ({report.total_vulnerabilities})", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0'), spaceAfter=10))

        for idx, vuln in enumerate(report.get_all_findings(), start=1):
            sev_color = "#DC2626" if vuln.severity == Severity.CRITICAL else ("#EA580C" if vuln.severity == Severity.HIGH else "#D97706")
            
            finding_content = []
            finding_content.append(Paragraph(f"<b>#{idx}. {vuln.name}</b> &nbsp;&nbsp; [<font color='{sev_color}'><b>{vuln.severity.value.upper()}</b></font>]", h2_style))
            finding_content.append(Paragraph(f"<b>Location:</b> {vuln.url or vuln.host or 'N/A'} &nbsp;|&nbsp; <b>CVSS:</b> {vuln.cvss_score} &nbsp;|&nbsp; <b>OWASP:</b> {vuln.owasp_category}", body_style))
            finding_content.append(Paragraph(f"<b>Description:</b> {vuln.description}", body_style))

            if vuln.proof_of_concept:
                poc_snippet = vuln.proof_of_concept[:300] + ("..." if len(vuln.proof_of_concept) > 300 else "")
                finding_content.append(Paragraph(f"<b>Evidence / PoC:</b>", body_style))
                finding_content.append(Paragraph(poc_snippet.replace('<', '&lt;').replace('>', '&gt;'), code_style))

            finding_content.append(Paragraph(f"<b>Remediation ({vuln.priority}):</b> {vuln.remediation}", body_style))
            finding_content.append(Spacer(1, 10))

            story.append(KeepTogether(finding_content))

        doc.build(story)
        return output_path
