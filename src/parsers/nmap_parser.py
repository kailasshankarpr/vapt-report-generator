import re
import xml.etree.ElementTree as ET
from typing import List
from src.parsers.base_parser import BaseParser
from src.models.vulnerability import Vulnerability, Severity, Confidence


class NmapParser(BaseParser):
    """Parse Nmap XML output files including port scans, service banners, and NSE vulnerability scripts"""

    def parse(self, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except Exception as e:
            print(f"[NmapParser] Error parsing XML file {file_path}: {e}")
            return []

        for host in root.findall('.//host'):
            # Extract Host IP / Name
            addr_elem = host.find(".//address[@addrtype='ipv4']")
            if addr_elem is None:
                addr_elem = host.find(".//address")
            ip_addr = addr_elem.get('addr') if addr_elem is not None else "127.0.0.1"

            hostname_elem = host.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else ip_addr

            # Process Ports & Services
            for port in host.findall('.//port'):
                state_elem = port.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue

                port_id = port.get('portid')
                protocol = port.get('protocol', 'tcp')
                service_elem = port.find('service')

                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                service_prod = service_elem.get('product', '') if service_elem is not None else ''
                service_ver = service_elem.get('version', '') if service_elem is not None else ''

                target_url = f"{protocol}://{hostname}:{port_id}"

                # Parse NSE Scripts attached to port
                scripts = port.findall('script')
                if not scripts:
                    # Informational finding for exposed service
                    vulnerabilities.append(Vulnerability(
                        id=f"NMAP-PORT-{port_id}",
                        name=f"Open Port Discovered: {service_name.upper()} ({port_id}/{protocol})",
                        description=f"Port {port_id}/{protocol} is open running service '{service_name}' ({service_prod} {service_ver}).",
                        severity=Severity.INFO,
                        confidence=Confidence.CERTAIN,
                        url=target_url,
                        host=ip_addr,
                        port=int(port_id),
                        remediation="Verify if this service is required to be exposed publicly.",
                        scanner="Nmap Network Mapper"
                    ))
                else:
                    for script in scripts:
                        script_id = script.get('id', 'script-vuln')
                        output = script.get('output', '')

                        # Extract CVEs from script output
                        cves = re.findall(r'CVE-\d{4}-\d{4,7}', output, re.IGNORECASE)
                        cves = list(set([c.upper() for c in cves]))

                        severity = Severity.MEDIUM
                        if any(k in output.lower() for k in ['critical', '9.', '10.']):
                            severity = Severity.CRITICAL
                        elif any(k in output.lower() for k in ['high', '7.', '8.']):
                            severity = Severity.HIGH
                        elif any(k in output.lower() for k in ['low', '1.', '2.', '3.']):
                            severity = Severity.LOW

                        vulnerabilities.append(Vulnerability(
                            id=f"NMAP-NSE-{script_id}-{port_id}",
                            name=f"Nmap NSE [{script_id}]: {service_name} on Port {port_id}",
                            description=f"Script output for '{script_id}' on {ip_addr}:{port_id}:\n\n{output[:1000]}",
                            severity=severity,
                            confidence=Confidence.FIRM,
                            url=target_url,
                            host=ip_addr,
                            port=int(port_id),
                            cve_ids=cves,
                            remediation="Patch or upgrade the service component to the latest supported release.",
                            scanner="Nmap NSE Scripts"
                        ))

        return vulnerabilities
