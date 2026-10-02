import html
import re
from typing import List, Dict
from src.models.vulnerability import Vulnerability, Severity


class DataProcessor:
    """Sanitize data, extract metadata, and deduplicate findings across multiple tools"""

    def process(self, raw_vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Normalize text, extract missing CVE/CWEs, and perform smart deduplication"""
        cleaned = []
        for vuln in raw_vulnerabilities:
            self._enrich_metadata(vuln)
            cleaned.append(vuln)

        return self.deduplicate(cleaned)

    def _enrich_metadata(self, vuln: Vulnerability):
        """Sanitize strings & extract regex CVE/CWE if not present"""
        text = f"{vuln.name} {vuln.description} {vuln.remediation}"

        # Extract CVE IDs if missing
        if not vuln.cve_ids:
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
            vuln.cve_ids = list(set([c.upper() for c in cves]))

        # Extract CWE IDs if missing
        if not vuln.cwe_ids:
            cwes = re.findall(r'CWE-\d+', text, re.IGNORECASE)
            vuln.cwe_ids = list(set([c.upper() for c in cwes]))

        # Clean description text
        if vuln.description:
            vuln.description = vuln.description.strip()

    def deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Smart Deduplication: Merge identical/similar findings from multiple tools"""
        dedup_map: Dict[str, Vulnerability] = {}

        for vuln in vulnerabilities:
            # Use deterministic fingerprint
            key = vuln.fingerprint

            if key in dedup_map:
                existing = dedup_map[key]
                # Merge scanners info
                if vuln.scanner and vuln.scanner not in existing.scanner:
                    existing.scanner = f"{existing.scanner}, {vuln.scanner}"

                # Merge CVEs & CWEs
                existing.cve_ids = list(set(existing.cve_ids + vuln.cve_ids))
                existing.cwe_ids = list(set(existing.cwe_ids + vuln.cwe_ids))

                # Merge references
                for ref in vuln.references:
                    if ref not in existing.references:
                        existing.references.append(ref)

                # Keep higher severity if different
                sev_order = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
                if sev_order.get(vuln.severity, 0) > sev_order.get(existing.severity, 0):
                    existing.severity = vuln.severity

                # Retain evidence if existing is missing
                if not existing.proof_of_concept and vuln.proof_of_concept:
                    existing.proof_of_concept = vuln.proof_of_concept
                if not existing.request and vuln.request:
                    existing.request = vuln.request
                    existing.response = vuln.response
            else:
                dedup_map[key] = vuln

        return list(dedup_map.values())
