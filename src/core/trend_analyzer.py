import json
from typing import List, Dict, Any, Tuple
from src.models.vulnerability import Vulnerability, FindingStatus


class TrendAnalyzer:
    """Historical Report Comparison & Delta Analysis Engine"""

    def analyze(self, current_vulnerabilities: List[Vulnerability], previous_report_path: str) -> Dict[str, Any]:
        """Compare current scan against a previous JSON report and calculate delta metrics"""
        prev_findings, prev_risk_score = self._load_previous_report(previous_report_path)

        prev_fingerprints = {f.get('fingerprint', ''): f for f in prev_findings if f.get('fingerprint')}

        new_count = 0
        recurring_count = 0
        resolved_count = 0
        regressed_count = 0

        # Match current against previous
        current_fingerprints = set()

        for curr in current_vulnerabilities:
            fp = curr.fingerprint
            current_fingerprints.add(fp)

            if fp in prev_fingerprints:
                prev_sev = prev_fingerprints[fp].get('severity', 'Medium')
                curr_sev = curr.severity.value

                # If previously resolved or lower severity that escalated
                if prev_sev in ['Low', 'Info'] and curr_sev in ['Critical', 'High']:
                    curr.status = FindingStatus.REGRESSED
                    regressed_count += 1
                else:
                    curr.status = FindingStatus.RECURRING
                    recurring_count += 1
            else:
                curr.status = FindingStatus.NEW
                new_count += 1

        # Check for resolved
        for fp, prev_f in prev_fingerprints.items():
            if fp not in current_fingerprints:
                resolved_count += 1

        curr_risk_score = sum(v.risk_score for v in current_vulnerabilities) / max(1, len(current_vulnerabilities))
        risk_score_delta = round(curr_risk_score - prev_risk_score, 1)

        trend_summary = {
            'has_previous_comparison': True,
            'previous_report_path': previous_report_path,
            'new_findings': new_count,
            'recurring_findings': recurring_count,
            'resolved_findings': resolved_count,
            'regressed_findings': regressed_count,
            'risk_score_delta': risk_score_delta,
            'direction': "IMPROVED" if risk_score_delta < 0 else ("DEGRADED" if risk_score_delta > 0 else "UNCHANGED")
        }

        return trend_summary

    def _load_previous_report(self, path: str) -> Tuple[List[Dict[str, Any]], float]:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                findings = data.get('findings', [])
                risk_score = float(data.get('overall_risk_score', 5.0))
                return findings, risk_score
        except Exception as e:
            print(f"[TrendAnalyzer] Warning: Unable to parse previous report {path}: {e}")
            return [], 5.0
