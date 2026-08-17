import unittest
from src.core.classifier import VulnerabilityClassifier
from src.core.compliance import ComplianceMapper
from src.models.vulnerability import Vulnerability, Severity


class TestClassifierAndCompliance(unittest.TestCase):

    def test_owasp_2025_classification(self):
        classifier = VulnerabilityClassifier()
        vuln = Vulnerability(
            id="1",
            name="Broken Object Level Authorization (BOLA)",
            description="Unauthorized access to user profile objects via ID parameter.",
            severity=Severity.HIGH
        )
        classifier.classify_all([vuln])
        self.assertEqual(vuln.owasp_category, "A01:2025 - Broken Access Control")
        self.assertEqual(vuln.owasp_2021_category, "A01:2021 - Broken Access Control")
        self.assertIn("Privilege Escalation", vuln.mitre_tactics)

    def test_compliance_mapping(self):
        mapper = ComplianceMapper()
        vuln = Vulnerability(
            id="2",
            name="SQL Injection in Login Parameter",
            description="Unsanitized query input allowing database dump.",
            severity=Severity.CRITICAL,
            owasp_category="A05:2025 - Injection"
        )
        summary = mapper.map_vulnerabilities([vuln])
        self.assertTrue(len(vuln.compliance_mappings) > 0)
        self.assertIn("PCI-DSS 4.0", summary)
        self.assertIn("HIPAA", summary)


if __name__ == "__main__":
    unittest.main()
