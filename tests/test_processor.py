import unittest
from src.core.data_processor import DataProcessor
from src.models.vulnerability import Vulnerability, Severity


class TestDataProcessor(unittest.TestCase):

    def test_deduplication(self):
        processor = DataProcessor()
        v1 = Vulnerability(
            id="V1",
            name="SQL Injection",
            description="Found in search endpoint",
            severity=Severity.HIGH,
            url="https://example.com/search.php",
            parameter="q",
            cve_ids=["CVE-2021-1234"],
            scanner="Burp"
        )
        v2 = Vulnerability(
            id="V2",
            name="SQL Injection",
            description="Found in search endpoint via nuclei",
            severity=Severity.CRITICAL,
            url="https://example.com/search.php",
            parameter="q",
            cve_ids=["CVE-2021-1234"],
            scanner="Nuclei"
        )

        deduped = processor.deduplicate([v1, v2])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, Severity.CRITICAL)
        self.assertIn("Burp", deduped[0].scanner)
        self.assertIn("Nuclei", deduped[0].scanner)


if __name__ == "__main__":
    unittest.main()
