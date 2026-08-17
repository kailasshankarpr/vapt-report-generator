import csv
import json
from typing import List, Dict, Any
from src.parsers.base_parser import BaseParser
from src.models.vulnerability import Vulnerability, Severity, Confidence


class CustomParser(BaseParser):
    """Parse custom JSON/CSV vulnerability data or FlowGraph-VAPT export format"""

    def parse(self, file_path: str) -> List[Vulnerability]:
        if file_path.endswith('.csv'):
            return self._parse_csv(file_path)
        return self._parse_json(file_path)

    def _parse_json(self, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            items = data if isinstance(data, list) else data.get('findings', data.get('vulnerabilities', [data]))

            for idx, item in enumerate(items, start=1):
                if not isinstance(item, dict):
                    continue

                vid = item.get('id') or item.get('log_id') or item.get('finding_id') or f"CUSTOM-{idx}"
                name = item.get('name') or item.get('title') or item.get('vulnerability') or f"Finding {idx}"
                desc = item.get('description') or item.get('details') or item.get('summary') or name
                sev = item.get('severity') or item.get('risk') or "Medium"

                url = item.get('url') or item.get('target') or item.get('endpoint') or ""
                method = item.get('method')
                param = item.get('parameter') or item.get('param')
                remediation = item.get('remediation') or item.get('solution') or item.get('fix') or "Apply secure configuration and access controls."

                # Handles FlowGraph-VAPT specific findings format
                poc = item.get('proof_of_concept') or item.get('poc') or item.get('evidence')
                if not poc and method and url:
                    poc = f"FlowGraph API Trace: {method} {url}"

                cve = item.get('cve_ids') or item.get('cve') or []
                if isinstance(cve, str):
                    cve = [cve]

                cwe = item.get('cwe_ids') or item.get('cwe') or []
                if isinstance(cwe, str):
                    cwe = [cwe]

                vuln = Vulnerability(
                    id=str(vid),
                    name=name,
                    description=desc,
                    severity=Severity.from_str(sev),
                    confidence=Confidence.from_str(item.get('confidence', 'Firm')),
                    cvss_score=float(item['cvss_score']) if item.get('cvss_score') else None,
                    cve_ids=[str(c).upper() for c in cve],
                    cwe_ids=[str(c).upper() for c in cwe],
                    url=url,
                    parameter=param,
                    method=method,
                    request=item.get('request'),
                    response=item.get('response'),
                    proof_of_concept=poc,
                    remediation=remediation,
                    references=item.get('references') if isinstance(item.get('references'), list) else [],
                    scanner=item.get('scanner') or item.get('source') or "Custom Audit Input"
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            print(f"[CustomParser] Failed to parse custom JSON {file_path}: {e}")

        return vulnerabilities

    def _parse_csv(self, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader, start=1):
                    vid = row.get('id') or row.get('ID') or f"CSV-{idx}"
                    name = row.get('name') or row.get('Title') or row.get('Vulnerability') or f"CSV Finding {idx}"
                    desc = row.get('description') or row.get('Description') or name
                    sev = row.get('severity') or row.get('Severity') or "Medium"

                    vuln = Vulnerability(
                        id=str(vid),
                        name=name,
                        description=desc,
                        severity=Severity.from_str(sev),
                        url=row.get('url') or row.get('URL') or row.get('Target') or "",
                        parameter=row.get('parameter') or row.get('Parameter'),
                        remediation=row.get('remediation') or row.get('Remediation') or "Remediate finding.",
                        scanner="CSV Ingestion"
                    )
                    vulnerabilities.append(vuln)
        except Exception as e:
            print(f"[CustomParser] Failed to parse CSV file {file_path}: {e}")

        return vulnerabilities
