from typing import List, Dict, Any
from src.models.vulnerability import Vulnerability, ComplianceMapping


class ComplianceMapper:
    """Map vulnerabilities to PCI-DSS 4.0, HIPAA, GDPR, and ISO/IEC 27001:2022 standards"""

    COMPLIANCE_MATRIX = [
        # OWASP A01 / Access Control / BOLA / IDOR
        (["access control", "authorization", "bola", "idor", "privilege escalation", "path traversal"], [
            ComplianceMapping("PCI-DSS 4.0", "Req 6.4.1", "Web Application Protection", "Public-facing web applications must be protected against attacks."),
            ComplianceMapping("PCI-DSS 4.0", "Req 7.2.1", "Access Control System", "Access is restricted to authorized individuals."),
            ComplianceMapping("HIPAA", "§ 164.312(a)(1)", "Access Control", "Implement technical policies to allow access only to authorized persons."),
            ComplianceMapping("GDPR", "Article 32", "Security of Processing", "Ensure a level of security appropriate to the risk."),
            ComplianceMapping("ISO 27001", "A.8.2", "Privileged Access Rights", "Allocation and use of privileged access rights shall be restricted.")
        ]),
        # OWASP A02 / Misconfigurations
        (["misconfiguration", "default password", "header", "directory listing", "open port"], [
            ComplianceMapping("PCI-DSS 4.0", "Req 2.2.1", "System Configuration Standards", "Develop configuration standards for all system components."),
            ComplianceMapping("HIPAA", "§ 164.308(a)(1)", "Risk Management", "Implement security measures to reduce risks and vulnerabilities."),
            ComplianceMapping("ISO 27001", "A.8.9", "Configuration Management", "Configurations of hardware, software, services shall be established.")
        ]),
        # OWASP A04 / Cryptographic Failures
        (["crypto", "ssl", "tls", "cipher", "plaintext", "encryption"], [
            ComplianceMapping("PCI-DSS 4.0", "Req 4.2.1", "Strong Cryptography", "Protect cardholder data during transmission over open networks."),
            ComplianceMapping("HIPAA", "§ 164.312(e)(1)", "Transmission Security", "Implement technical security measures for electronic health data."),
            ComplianceMapping("GDPR", "Article 32(1)(a)", "Pseudonymisation and Encryption", "Encryption of personal data."),
            ComplianceMapping("ISO 27001", "A.8.24", "Use of Cryptography", "Rules for effective use of cryptography shall be defined.")
        ]),
        # OWASP A05 / Injection (SQLi, XSS, RCE)
        (["sqli", "sql injection", "xss", "command injection", "rce", "injection"], [
            ComplianceMapping("PCI-DSS 4.0", "Req 6.2.4", "Software Security Flaws", "Prevent common coding vulnerabilities in software development."),
            ComplianceMapping("HIPAA", "§ 164.312(c)(1)", "Data Integrity", "Protect data from unauthorized alteration or destruction."),
            ComplianceMapping("GDPR", "Article 32", "Security of Processing", "Prevent unauthorized disclosure or access to personal data."),
            ComplianceMapping("ISO 27001", "A.8.8", "Management of Technical Vulnerabilities", "Information about technical vulnerabilities shall be evaluated.")
        ]),
        # OWASP A07 / Authentication
        (["authentication", "login", "password", "brute force", "session"], [
            ComplianceMapping("PCI-DSS 4.0", "Req 8.2.1", "User Authentication", "All access to system components requires unique identification."),
            ComplianceMapping("HIPAA", "§ 164.312(d)", "Person/Entity Authentication", "Implement procedures to verify that a person is authorized."),
            ComplianceMapping("ISO 27001", "A.8.5", "Secure Authentication", "Secure authentication technologies and procedures shall be used.")
        ])
    ]

    def map_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Dict[str, Any]]:
        """Map vulnerabilities and calculate overall compliance breakdown percentages"""
        for vuln in vulnerabilities:
            vuln.compliance_mappings = self._get_mappings(vuln)

        return self._generate_compliance_summary(vulnerabilities)

    def _get_mappings(self, vuln: Vulnerability) -> List[ComplianceMapping]:
        text = f"{vuln.name} {vuln.description} {vuln.owasp_category}".lower()
        mappings = []

        for keywords, map_list in self.COMPLIANCE_MATRIX:
            if any(kw in text for kw in keywords):
                for m in map_list:
                    if m not in mappings:
                        mappings.append(m)

        if not mappings:
            # Default general mapping
            mappings.append(ComplianceMapping("PCI-DSS 4.0", "Req 11.3.1", "Vulnerability Management", "Identify and resolve technical security vulnerabilities."))
            mappings.append(ComplianceMapping("ISO 27001", "A.8.8", "Vulnerability Management", "Manage technical security vulnerabilities."))

        return mappings

    def _generate_compliance_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Dict[str, Any]]:
        frameworks = ["PCI-DSS 4.0", "HIPAA", "GDPR", "ISO 27001"]
        summary = {}

        crit_high_count = sum(1 for v in vulnerabilities if v.severity.value in ["Critical", "High"])
        med_low_count = sum(1 for v in vulnerabilities if v.severity.value in ["Medium", "Low"])

        for fw in frameworks:
            violations = sum(1 for v in vulnerabilities if any(c.framework == fw for c in v.compliance_mappings))
            if crit_high_count > 0:
                pass_rate = max(35.0, round(100.0 - (crit_high_count * 12.0 + med_low_count * 4.0), 1))
            elif med_low_count > 0:
                pass_rate = max(75.0, round(100.0 - (med_low_count * 5.0), 1))
            else:
                pass_rate = 100.0

            summary[fw] = {
                "violations_count": violations,
                "compliance_score": pass_rate,
                "status": "NON-COMPLIANT" if pass_rate < 80.0 else "COMPLIANT"
            }

        return summary
