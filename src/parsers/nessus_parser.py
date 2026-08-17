import xml.etree.ElementTree as ET
from typing import List, Optional
from src.parsers.base_parser import BaseParser
from src.models.vulnerability import Vulnerability, Severity, Confidence


class NessusParser(BaseParser):
    """Parse Tenable Nessus v2 XML (.nessus) scan files"""

    SEVERITY_MAP = {
        '4': Severity.CRITICAL,
        '3': Severity.HIGH,
        '2': Severity.MEDIUM,
        '1': Severity.LOW,
        '0': Severity.INFO
    }

    def parse(self, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as e:
            print(f"[NessusParser] Error parsing .nessus file {file_path}: {e}")
            return []

        for host in root.findall('.//ReportHost'):
            host_name = host.get('name', 'Unknown Host')

            # Extract IP tag if present
            ip_tag = host.find(".//tag[@name='host-ip']")
            ip_addr = ip_tag.text if ip_tag is not None else host_name

            for item in host.findall('ReportItem'):
                plugin_id = item.get('pluginID', '0')
                plugin_name = item.get('pluginName', 'Nessus Finding')
                port = item.get('port', '0')
                protocol = item.get('protocol', 'tcp')
                svc_name = item.get('svc_name', 'general')
                severity_val = item.get('severity', '2')

                description = self._get_text(item, 'description') or self._get_text(item, 'synopsis') or plugin_name
                solution = self._get_text(item, 'solution') or "Apply vendor patch or resolution."
                output = self._get_text(item, 'plugin_output')
                see_also = self._get_text(item, 'see_also')

                cvss3_score = self._get_text(item, 'cvss3_base_score') or self._get_text(item, 'cvss_base_score')
                cvss3_vector = self._get_text(item, 'cvss3_vector') or self._get_text(item, 'cvss_vector')

                # Extract CVEs
                cve_list = [cve.text.strip().upper() for cve in item.findall('cve') if cve.text]
                cwe_list = [f"CWE-{cwe.text.strip()}" for cwe in item.findall('cwe') if cwe.text]

                refs = see_also.splitlines() if see_also else []
                refs = [r.strip() for r in refs if r.strip().startswith('http')]

                poc = f"Nessus Plugin Output:\n{output}" if output else None

                target_url = f"{svc_name}://{ip_addr}:{port}" if port != '0' else f"http://{ip_addr}"

                vuln = Vulnerability(
                    id=f"NESSUS-{plugin_id}",
                    name=plugin_name,
                    description=description,
                    severity=self.SEVERITY_MAP.get(severity_val, Severity.MEDIUM),
                    confidence=Confidence.CERTAIN,
                    cvss_score=float(cvss3_score) if cvss3_score else None,
                    cvss_vector=cvss3_vector or None,
                    cve_ids=cve_list,
                    cwe_ids=cwe_list,
                    url=target_url,
                    host=ip_addr,
                    port=int(port) if port.isdigit() else None,
                    proof_of_concept=poc,
                    remediation=solution,
                    references=refs,
                    scanner="Tenable Nessus Scanner"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_text(self, elem: ET.Element, tag: str) -> str:
        sub = elem.find(tag)
        return sub.text.strip() if sub is not None and sub.text else ""
