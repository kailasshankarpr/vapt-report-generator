import json
from datetime import datetime
from src.exporters.base_exporter import BaseExporter
from src.models.vulnerability import ScanReport


class JSONExporter(BaseExporter):
    """Exports ScanReport as structured machine-readable JSON"""

    def export(self, report: ScanReport, output_path: str) -> str:
        data = {
            'title': report.title,
            'client': report.client_name,
            'project': report.project_name,
            'scope': report.scope,
            'methodology': report.methodology,
            'generated_at': datetime.now().isoformat(),
            'generated_by': report.generated_by,
            'report_version': report.report_version,
            'overall_risk_rating': report.overall_risk_rating,
            'overall_risk_score': report.overall_risk_score,
            'security_health_grade': report.security_health_grade,
            'statistics': {
                'total_vulnerabilities': report.total_vulnerabilities,
                'by_severity': report.vulnerabilities_by_severity,
                'by_status': report.vulnerabilities_by_status,
                'by_owasp': report.vulnerabilities_by_owasp
            },
            'compliance_summary': report.compliance_summary,
            'trend_summary': report.trend_summary,
            'executive_summary': report.executive_summary,
            'key_findings': report.key_findings,
            'recommendations': report.recommendations,
            'findings': [v.to_dict() for v in report.get_all_findings()]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        return output_path
