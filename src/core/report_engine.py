import os
import yaml
from datetime import datetime
from typing import List, Dict, Any, Optional

from src.models.vulnerability import ScanReport, Vulnerability, Severity
from src.parsers import BurpParser, NmapParser, NucleiParser, NessusParser, CustomParser
from src.core.data_processor import DataProcessor
from src.core.classifier import VulnerabilityClassifier
from src.core.compliance import ComplianceMapper
from src.core.trend_analyzer import TrendAnalyzer
from src.core.risk_scorer import RiskScorer


class ReportEngine:
    """Main VAPT Report Engine Orchestrator"""

    def __init__(self, config_path: str = "config/report_config.yaml"):
        self.config = self._load_config(config_path)
        self.parsers = {
            'burp': BurpParser(),
            'nmap': NmapParser(),
            'nuclei': NucleiParser(),
            'nessus': NessusParser(),
            'custom': CustomParser(),
            'csv': CustomParser(),
            'flowgraph': CustomParser()
        }
        self.processor = DataProcessor()
        self.classifier = VulnerabilityClassifier()
        self.compliance_mapper = ComplianceMapper()
        self.trend_analyzer = TrendAnalyzer()
        self.scorer = RiskScorer()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"[ReportEngine] Warning loading config {config_path}: {e}")
        return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        return {
            'company': {
                'name': 'FlowGraph Security',
                'logo_url': '',
                'website': 'https://flowgraph.security'
            },
            'report': {
                'title': 'Vulnerability Assessment Report',
                'template': 'executive_professional'
            }
        }

    def load_sources(self, input_sources: List[Dict[str, str]]) -> List[Vulnerability]:
        """Load and parse scan findings from multiple input sources"""
        all_raw = []
        for src in input_sources:
            path = src['path']
            stype = src['type'].lower()

            parser = self.parsers.get(stype)
            if not parser:
                print(f"[ReportEngine] Warning: Unsupported parser type '{stype}' for file {path}")
                continue

            print(f"  [+] Parsing {stype.upper()} output: {path}")
            parsed = parser.parse(path)
            print(f"      Extracted {len(parsed)} findings.")
            all_raw.extend(parsed)

        return all_raw

    def create_report(
        self,
        vulnerabilities: List[Vulnerability],
        client_name: str = "Target Client",
        project_name: str = "Security Assessment",
        scope: str = "Perimeter & Web Application Scope",
        methodology: str = "OWASP Testing Guide v4.2, PTES, NIST SP 800-115",
        previous_report_path: Optional[str] = None
    ) -> ScanReport:
        """Run complete processing pipeline and construct ScanReport"""

        print("  [+] Normalizing and deduplicating findings...")
        processed_vulns = self.processor.process(vulnerabilities)
        print(f"      Total unique findings after deduplication: {len(processed_vulns)}")

        print("  [+] Classifying vulnerabilities (OWASP Top 10:2025 & MITRE ATT&CK)...")
        self.classifier.classify_all(processed_vulns)

        print("  [+] Mapping regulatory compliance (PCI-DSS 4.0, HIPAA, GDPR, ISO 27001)...")
        compliance_summary = self.compliance_mapper.map_vulnerabilities(processed_vulns)

        print("  [+] Computing CVSS risk scores, business impact, and remediation SLAs...")
        self.scorer.score_vulnerabilities(processed_vulns)

        # Trend Analysis if previous report provided
        trend_summary = {}
        if previous_report_path and os.path.exists(previous_report_path):
            print(f"  [+] Performing trend analysis against previous report: {previous_report_path}...")
            trend_summary = self.trend_analyzer.analyze(processed_vulns, previous_report_path)

        # Construct ScanReport object
        report = ScanReport(
            title=self.config.get('report', {}).get('title', 'Vulnerability Assessment & Penetration Testing Report'),
            client_name=client_name,
            project_name=project_name,
            scope=scope,
            methodology=methodology,
            start_date=datetime.now(),
            end_date=datetime.now(),
            critical_findings=[v for v in processed_vulns if v.severity == Severity.CRITICAL],
            high_findings=[v for v in processed_vulns if v.severity == Severity.HIGH],
            medium_findings=[v for v in processed_vulns if v.severity == Severity.MEDIUM],
            low_findings=[v for v in processed_vulns if v.severity == Severity.LOW],
            info_findings=[v for v in processed_vulns if v.severity == Severity.INFO],
            compliance_summary=compliance_summary,
            trend_summary=trend_summary,
            company_logo=self.config.get('company', {}).get('logo_url')
        )

        report.calculate_statistics()
        report.executive_summary = self._generate_executive_summary(report)
        report.key_findings = self._generate_key_findings(report)
        report.recommendations = self._generate_recommendations(report)

        return report

    def _generate_executive_summary(self, report: ScanReport) -> str:
        stats = report.vulnerabilities_by_severity
        summary = (
            f"During the security assessment conducted for {report.client_name} under project '{report.project_name}', "
            f"a total of {report.total_vulnerabilities} unique security vulnerabilities were identified across the target scope.\n\n"
            f"Overall Security Posture Rating: {report.overall_risk_rating} (Health Grade: {report.security_health_grade})\n"
            f"Breakdown: {stats.get('Critical', 0)} Critical, {stats.get('High', 0)} High, "
            f"{stats.get('Medium', 0)} Medium, {stats.get('Low', 0)} Low, and {stats.get('Info', 0)} Informational issues.\n\n"
        )
        if report.critical_findings or report.high_findings:
            summary += "Immediate executive intervention is strongly advised to address high-severity vulnerabilities before production exposure."
        else:
            summary += "No critical vulnerabilities were detected. Maintain routine patch cycles and continuous monitoring."
        return summary

    def _generate_key_findings(self, report: ScanReport) -> List[str]:
        keys = []
        top_vulns = (report.critical_findings + report.high_findings + report.medium_findings)[:5]
        for v in top_vulns:
            keys.append(f"[{v.severity.value}] {v.name} at {v.url or v.host or 'Target'}")
        return keys

    def _generate_recommendations(self, report: ScanReport) -> List[str]:
        recs = set()
        for v in report.get_all_findings():
            if v.remediation and len(v.remediation) < 200:
                recs.add(v.remediation)

        defaults = [
            "Enforce strict input validation, parameterized queries, and output encoding across all endpoints.",
            "Implement modern multi-factor authentication (MFA) and granular role-based access control (RBAC).",
            "Establish automated patch management for application dependencies and host operating systems.",
            "Perform quarterly penetration testing and maintain continuous vulnerability monitoring."
        ]
        for d in defaults:
            recs.add(d)

        return list(recs)[:8]
