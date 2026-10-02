import unittest
import os
from src.parsers.burp_parser import BurpParser
from src.parsers.nmap_parser import NmapParser
from src.parsers.nuclei_parser import NucleiParser
from src.parsers.nessus_parser import NessusParser
from src.parsers.custom_parser import CustomParser
from src.models.vulnerability import Severity


class TestParsers(unittest.TestCase):

    def test_burp_parser(self):
        parser = BurpParser()
        vulns = parser.parse("samples/burp_sample.xml")
        self.assertTrue(len(vulns) >= 2)
        self.assertEqual(vulns[0].scanner, "Burp Suite Professional")
        self.assertTrue(vulns[0].url.startswith("https://"))

    def test_nmap_parser(self):
        parser = NmapParser()
        vulns = parser.parse("samples/nmap_sample.xml")
        self.assertTrue(len(vulns) >= 1)
        self.assertEqual(vulns[0].host, "192.168.1.50")

    def test_nuclei_parser(self):
        parser = NucleiParser()
        vulns = parser.parse("samples/nuclei_sample.json")
        self.assertTrue(len(vulns) >= 2)
        self.assertEqual(vulns[0].severity, Severity.CRITICAL)
        self.assertIn("CVE-2020-11022", vulns[0].cve_ids)

    def test_nessus_parser(self):
        parser = NessusParser()
        vulns = parser.parse("samples/nessus_sample.xml")
        self.assertTrue(len(vulns) >= 1)
        self.assertEqual(vulns[0].host, "192.168.1.50")

    def test_custom_parser(self):
        parser = CustomParser()
        vulns = parser.parse("samples/custom_sample.json")
        self.assertTrue(len(vulns) >= 1)
        self.assertEqual(vulns[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
