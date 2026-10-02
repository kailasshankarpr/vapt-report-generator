from typing import List, Tuple
from src.models.vulnerability import Vulnerability


class VulnerabilityClassifier:
    """Classify vulnerabilities using OWASP Top 10:2025 and MITRE ATT&CK Frameworks"""

    OWASP_2025_RULES = [
        ("A01:2025 - Broken Access Control", [
            "access control", "authorization", "bola", "idor", "privilege escalation",
            "path traversal", "directory traversal", "ssrf", "server-side request forgery",
            "cors", "cross-origin", "unauthorized access", "cwe-22", "cwe-284", "cwe-639", "cwe-918"
        ]),
        ("A02:2025 - Security Misconfiguration", [
            "misconfiguration", "default password", "debug mode", "missing header",
            "directory listing", "open port", "banner", "cwe-16", "cwe-2"
        ]),
        ("A03:2025 - Software Supply Chain Failures", [
            "supply chain", "vulnerable dependency", "outdated library", "third-party",
            "package", "cve", "cwe-1395", "cwe-1104"
        ]),
        ("A04:2025 - Cryptographic Failures", [
            "crypto", "ssl", "tls", "certificate", "cipher", "plaintext",
            "encryption", "cwe-310", "cwe-319", "cwe-327"
        ]),
        ("A05:2025 - Injection", [
            "injection", "sqli", "sql injection", "xss", "cross-site scripting",
            "command injection", "rce", "template injection", "ssti", "cwe-89", "cwe-79", "cwe-78"
        ]),
        ("A06:2025 - Insecure Design", [
            "insecure design", "business logic", "rate limit", "csrf", "cross-site request forgery",
            "cwe-352", "cwe-1059"
        ]),
        ("A07:2025 - Authentication Failures", [
            "authentication", "login", "password", "brute force", "session",
            "credential", "cwe-287", "cwe-307", "cwe-798"
        ]),
        ("A08:2025 - Software or Data Integrity Failures", [
            "integrity", "deserialization", "untrusted code", "integrity failure",
            "cwe-502", "cwe-345", "cwe-829"
        ]),
        ("A09:2025 - Security Logging & Alerting Failures", [
            "logging", "alerting", "audit log", "monitoring", "cwe-778", "cwe-117"
        ]),
        ("A10:2025 - Mishandling of Exceptional Conditions", [
            "exception", "error handling", "stack trace", "null pointer",
            "verbose error", "cwe-209", "cwe-754", "cwe-390"
        ])
    ]

    MITRE_ATTACK_MAPPING = [
        (["sqli", "sql injection", "rce", "command injection", "exploit", "cve"],
         ["Initial Access", "Execution"], ["T1190 - Exploit Public-Facing Application", "T1059 - Command and Scripting Interpreter"]),
        (["xss", "cross-site scripting", "csrf"],
         ["Initial Access"], ["T1189 - Drive-by Compromise", "T1059.007 - JavaScript"]),
        (["bola", "idor", "privilege escalation", "path traversal"],
         ["Privilege Escalation", "Lateral Movement"], ["T1068 - Exploitation for Privilege Escalation", "T1083 - File and Directory Discovery"]),
        (["brute force", "authentication", "credential"],
         ["Credential Access"], ["T1110 - Brute Force", "T1078 - Valid Accounts"]),
        (["ssrf", "server-side request forgery"],
         ["Discovery", "Lateral Movement"], ["T1046 - Network Service Discovery", "T1557 - Adversary-in-the-Middle"])
    ]

    def classify_all(self, vulnerabilities: List[Vulnerability]):
        """Classify each vulnerability into OWASP 2025, OWASP 2021, and MITRE ATT&CK"""
        for vuln in vulnerabilities:
            vuln.owasp_category = self._get_owasp_2025(vuln)
            vuln.owasp_2021_category = self._get_owasp_2021(vuln.owasp_category)
            tactics, tech = self._get_mitre_mapping(vuln)
            vuln.mitre_tactics = tactics
            vuln.mitre_techniques = tech

    def _get_owasp_2025(self, vuln: Vulnerability) -> str:
        text = f"{vuln.name} {vuln.description} {' '.join(vuln.cwe_ids)}".lower()

        for category, keywords in self.OWASP_2025_RULES:
            for kw in keywords:
                if kw in text:
                    return category

        return "A05:2025 - Injection"  # Default fallback

    def _get_owasp_2021(self, owasp_2025: str) -> str:
        # Mapping table from 2025 to 2021
        mapping = {
            "A01:2025 - Broken Access Control": "A01:2021 - Broken Access Control",
            "A02:2025 - Security Misconfiguration": "A05:2021 - Security Misconfiguration",
            "A03:2025 - Software Supply Chain Failures": "A06:2021 - Vulnerable and Outdated Components",
            "A04:2025 - Cryptographic Failures": "A02:2021 - Cryptographic Failures",
            "A05:2025 - Injection": "A03:2021 - Injection",
            "A06:2025 - Insecure Design": "A04:2021 - Insecure Design",
            "A07:2025 - Authentication Failures": "A07:2021 - Identification and Authentication Failures",
            "A08:2025 - Software or Data Integrity Failures": "A08:2021 - Software and Data Integrity Failures",
            "A09:2025 - Security Logging & Alerting Failures": "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2025 - Mishandling of Exceptional Conditions": "A04:2021 - Insecure Design"
        }
        return mapping.get(owasp_2025, "A03:2021 - Injection")

    def _get_mitre_mapping(self, vuln: Vulnerability) -> Tuple[List[str], List[str]]:
        text = f"{vuln.name} {vuln.description}".lower()
        tactics = set()
        techniques = set()

        for keywords, tac_list, tech_list in self.MITRE_ATTACK_MAPPING:
            if any(kw in text for kw in keywords):
                tactics.update(tac_list)
                techniques.update(tech_list)

        if not tactics:
            tactics.add("Initial Access")
            techniques.add("T1190 - Exploit Public-Facing Application")

        return list(tactics), list(techniques)
