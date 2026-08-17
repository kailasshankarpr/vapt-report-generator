from typing import List
from src.models.vulnerability import Vulnerability, Severity


class RiskScorer:
    """Calculate CVSS scores, Business Impact, Exploitability, and Remediation SLA windows"""

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.INFO: 0.5
    }

    SLA_MAP = {
        Severity.CRITICAL: ("Immediate (within 24 hours)", 1),
        Severity.HIGH: ("High Priority (within 7 days)", 7),
        Severity.MEDIUM: ("Medium Priority (within 14 days)", 14),
        Severity.LOW: ("Low Priority (within 30 days)", 30),
        Severity.INFO: ("Informational (within 90 days)", 90)
    }

    def score_vulnerabilities(self, vulnerabilities: List[Vulnerability]):
        """Compute scores and assign priority for all vulnerabilities"""
        for vuln in vulnerabilities:
            # 1. Base Score
            if vuln.cvss_score is None:
                base = self.SEVERITY_WEIGHTS.get(vuln.severity, 5.0)
                vuln.cvss_score = base
            else:
                base = vuln.cvss_score

            # 2. Business Impact
            impact = 5.0
            desc = f"{vuln.name} {vuln.description}".lower()
            if any(k in desc for k in ['rce', 'sql', 'auth', 'admin', 'credit card', 'pii', 'database', 'password']):
                impact += 3.0
            if vuln.severity == Severity.CRITICAL:
                impact += 2.0
            elif vuln.severity == Severity.HIGH:
                impact += 1.0
            vuln.business_impact = min(10.0, round(impact, 1))

            # 3. Exploitability
            exploitability = 5.0
            if vuln.cve_ids:
                exploitability += 2.0
            if any(k in desc for k in ['public', 'poc', 'exploit', 'easy', 'unauthenticated']):
                exploitability += 2.0
            vuln.exploitability = min(10.0, round(exploitability, 1))

            # 4. Overall Weighted Risk Score
            overall = (base * 0.5) + (vuln.business_impact * 0.3) + (vuln.exploitability * 0.2)
            vuln.risk_score = round(min(10.0, overall), 1)

            # 5. SLA & Priority
            priority_str, days = self.SLA_MAP.get(vuln.severity, ("Medium Priority (within 14 days)", 14))
            vuln.priority = priority_str
            vuln.sla_days = days
