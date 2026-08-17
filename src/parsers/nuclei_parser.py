import json
from typing import List, Dict, Any
from src.parsers.base_parser import BaseParser
from src.models.vulnerability import Vulnerability, Severity, Confidence


class NucleiParser(BaseParser):
    """Parse Nuclei vulnerability scanner outputs (JSON array or JSON lines format)"""

    def parse(self, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        raw_items = self._load_json(file_path)

        for idx, item in enumerate(raw_items, start=1):
            if not isinstance(item, dict):
                continue

            template_id = item.get('template-id') or item.get('templateID') or f"NUCLEI-{idx}"
            info = item.get('info', {})

            name = info.get('name') or template_id
            description = info.get('description') or f"Nuclei template {template_id} triggered."
            severity_str = info.get('severity') or "Medium"

            matched_at = item.get('matched-at') or item.get('matched') or item.get('host') or ""
            curl_cmd = item.get('curl-command') or item.get('curl') or ""
            extracted = item.get('extracted-results') or item.get('extracted_results') or ""

            # PoC construction
            poc = ""
            if curl_cmd:
                poc += f"Curl Command:\n{curl_cmd}\n\n"
            if extracted:
                poc += f"Extracted Findings:\n{extracted}"

            # References
            refs = info.get('reference') or info.get('references') or []
            if isinstance(refs, str):
                refs = [refs]

            # Classification
            classif = info.get('classification', {})
            cve_ids = classif.get('cve-id') or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            
            cwe_ids = classif.get('cwe-id') or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]

            cvss_score = classif.get('cvss-score') or classif.get('cvss_score')

            remediation = info.get('remediation') or info.get('solution') or "Remediate according to template guidelines."

            vuln = Vulnerability(
                id=template_id,
                name=name,
                description=description,
                severity=Severity.from_str(severity_str),
                confidence=Confidence.CERTAIN if item.get('type') == 'http' else Confidence.FIRM,
                cvss_score=float(cvss_score) if cvss_score else None,
                cve_ids=[str(c).upper() for c in cve_ids],
                cwe_ids=[str(c).upper() for c in cwe_ids],
                url=matched_at,
                host=item.get('host', ''),
                proof_of_concept=poc.strip() or None,
                request=item.get('request'),
                response=item.get('response'),
                remediation=remediation,
                references=refs,
                scanner="Nuclei Vulnerability Scanner",
                tags=info.get('tags', []) if isinstance(info.get('tags'), list) else []
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _load_json(self, file_path: str) -> List[Dict[str, Any]]:
        items = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content.startswith('['):
                    items = json.loads(content)
                else:
                    for line in content.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                items.append(json.loads(line))
                            except Exception:
                                pass
        except Exception as e:
            print(f"[NucleiParser] Failed to load JSON file {file_path}: {e}")
        return items
