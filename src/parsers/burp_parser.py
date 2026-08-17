import base64
import xml.etree.ElementTree as ET
from typing import List, Optional
from src.parsers.base_parser import BaseParser
from src.models.vulnerability import Vulnerability, Severity, Confidence


class BurpParser(BaseParser):
    """Parse Burp Suite XML vulnerability report exports"""

    def parse(self, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as e:
            print(f"[BurpParser] Error parsing XML file {file_path}: {e}")
            return []

        issues = root.findall('.//issue') if root.tag != 'issue' else [root]

        for idx, issue in enumerate(issues, start=1):
            serial = self._get_text(issue, 'serialNumber') or f"BURP-{idx}"
            name = self._get_text(issue, 'name') or "Burp Suite Finding"
            severity_str = self._get_text(issue, 'severity') or "Medium"
            confidence_str = self._get_text(issue, 'confidence') or "Firm"

            host_elem = issue.find('host')
            host_val = host_elem.text if host_elem is not None else ""
            ip_val = host_elem.get('ip') if host_elem is not None else ""
            path_val = self._get_text(issue, 'path') or ""
            location_val = self._get_text(issue, 'location') or f"{host_val}{path_val}"

            # Text content fields with possible base64 encoding
            issue_bg = self._get_decoded_text(issue, 'issueBackground')
            issue_detail = self._get_decoded_text(issue, 'issueDetail')
            remediation_bg = self._get_decoded_text(issue, 'remediationBackground')
            remediation_detail = self._get_decoded_text(issue, 'remediationDetail')

            description = f"{issue_detail}\n\n{issue_bg}".strip() if (issue_detail or issue_bg) else name
            remediation = f"{remediation_detail}\n\n{remediation_bg}".strip()

            # Requests / Responses
            request_str = None
            response_str = None
            reqresp = issue.find('.//requestresponse')
            if reqresp is not None:
                request_str = self._get_decoded_text(reqresp, 'request')
                response_str = self._get_decoded_text(reqresp, 'response')

            cwe_id = self._get_text(issue, 'cweId')
            cwe_list = [f"CWE-{cwe_id}"] if cwe_id else []

            vuln = Vulnerability(
                id=serial,
                name=name,
                description=description,
                severity=Severity.from_str(severity_str),
                confidence=Confidence.from_str(confidence_str),
                url=location_val,
                host=host_val or ip_val,
                parameter=self._get_text(issue, 'parameter'),
                method=self._get_text(issue, 'method'),
                cwe_ids=cwe_list,
                request=request_str,
                response=response_str,
                remediation=remediation or "Refer to Burp Suite vulnerability remediation guidelines.",
                references=self._parse_references(issue.find('references')),
                scanner="Burp Suite Professional"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_text(self, elem: ET.Element, tag: str) -> str:
        sub = elem.find(tag)
        return sub.text.strip() if sub is not None and sub.text else ""

    def _get_decoded_text(self, parent: ET.Element, tag: str) -> str:
        sub = parent.find(tag)
        if sub is None or sub.text is None:
            return ""
        content = sub.text.strip()
        if sub.get('base64') == 'true':
            try:
                return base64.b64decode(content).decode('utf-8', errors='ignore')
            except Exception:
                return content
        return content

    def _parse_references(self, ref_elem: Optional[ET.Element]) -> List[str]:
        if ref_elem is None:
            return []
        refs = []
        for ref in ref_elem.findall('ref'):
            if ref.text and ref.text.strip():
                refs.append(ref.text.strip())
        return refs
