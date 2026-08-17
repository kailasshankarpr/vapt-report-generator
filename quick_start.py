#!/usr/bin/env python3
"""
Quick Start Demonstration Script for VAPT Report Generator
Executes the full report generation pipeline using sample scanner data.
"""

import os
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from src.core.report_engine import ReportEngine
from src.exporters import HTMLExporter, PDFExporter, DOCXExporter, JSONExporter


def main():
    print("=" * 70)
    print("VAPT REPORT GENERATOR - QUICK START DEMONSTRATION")
    print("=" * 70)

    # Input scan sources
    sources = [
        {'path': 'samples/burp_sample.xml', 'type': 'burp'},
        {'path': 'samples/nmap_sample.xml', 'type': 'nmap'},
        {'path': 'samples/nuclei_sample.json', 'type': 'nuclei'},
        {'path': 'samples/nessus_sample.xml', 'type': 'nessus'},
        {'path': 'samples/custom_sample.json', 'type': 'custom'}
    ]

    engine = ReportEngine()

    print("\n1. Parsing multi-scanner inputs (Burp, Nmap, Nuclei, Nessus, Custom)...")
    raw_findings = engine.load_sources(sources)

    print("\n2. Executing normalization, deduplication, OWASP 2025, MITRE & Compliance mapping...")
    report = engine.create_report(
        raw_findings,
        client_name="Global Enterprise Bank",
        project_name="Q3 Full Scope VAPT & Regulatory Compliance Audit",
        scope="Core Banking APIs, Web Applications, and External Perimeter",
        previous_report_path="samples/previous_report.json" if os.path.exists("samples/previous_report.json") else None
    )

    print("\n3. Generating multi-format output reports...")
    os.makedirs("output", exist_ok=True)

    html_out = HTMLExporter().export(report, "output/vapt_report.html")
    pdf_out = PDFExporter().export(report, "output/vapt_report.pdf")
    docx_out = DOCXExporter().export(report, "output/vapt_report.docx")
    json_out = JSONExporter().export(report, "output/vapt_report.json")

    print("\n" + "=" * 70)
    print("REPORT GENERATION COMPLETE!")
    print("=" * 70)
    print(f" • Security Health Grade:   {report.security_health_grade}")
    print(f" • Overall Risk Rating:     {report.overall_risk_rating} ({report.overall_risk_score}/10)")
    print(f" • Total Unique Findings:   {report.total_vulnerabilities}")
    print(f"   - Critical: {report.vulnerabilities_by_severity.get('Critical', 0)}")
    print(f"   - High:     {report.vulnerabilities_by_severity.get('High', 0)}")
    print(f"   - Medium:   {report.vulnerabilities_by_severity.get('Medium', 0)}")
    print(f"   - Low:      {report.vulnerabilities_by_severity.get('Low', 0)}")
    print(f"   - Info:     {report.vulnerabilities_by_severity.get('Info', 0)}")

    print("\nOutput Report Files Created:")
    print(f"   - HTML (Interactive): {os.path.abspath(html_out)}")
    print(f"   - PDF (Standalone):  {os.path.abspath(pdf_out)}")
    print(f"   - DOCX (Editable):   {os.path.abspath(docx_out)}")
    print(f"   - JSON (Data):       {os.path.abspath(json_out)}")
    print("=" * 70)


if __name__ == "__main__":
    main()
