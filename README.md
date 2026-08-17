# 🛡️ VAPT Report Generator

An enterprise-grade, modular Python tool and library designed to ingest, normalize, deduplicate, classify, risk-score, and generate professional security assessment reports (**HTML**, **PDF**, **DOCX**, **JSON**) from multiple vulnerability scanner sources.

---

## 🌟 Key Features

- **Multi-Scanner Ingestion**: Built-in support for:
  - **Burp Suite XML** *(with automatic base64 payload decoding)*
  - **Nmap XML** *(open ports, services, banners, and NSE scripts like `vulners`)*
  - **Nuclei JSON / JSONL** *(matches, extracted findings, curl PoCs)*
  - **Tenable Nessus XML** *(`.nessus` v2 format)*
  - **Custom JSON / CSV & FlowGraph-VAPT** format
- **Smart Deduplication Engine**: Automatically merges overlapping findings across multiple tool outputs based on fingerprint hashing (Host/URL + Vulnerability Vector + CVE/CWE).
- **OWASP Top 10:2025 Framework**: Standardized taxonomy mapping to the official **OWASP Top 10:2025** categories (including `A03:2025 Software Supply Chain Failures` & `A10:2025 Mishandling of Exceptional Conditions`), with OWASP 2021 backward compatibility.
- **MITRE ATT&CK Mapping**: Automatic tagging of MITRE ATT&CK Tactics *(Initial Access, Privilege Escalation, Credential Access, etc.)* and Techniques *(T1190, T1059, T1557, T1110, T1078)*.
- **Compliance Mapping Engine**: Automated rule-based cross-referencing against:
  - **PCI-DSS 4.0** *(Req 6.2, 6.4, 8.2, 11.3)*
  - **HIPAA Security Rule** *(§ 164.312 Access/Transmission Controls, § 164.308 Risk Management)*
  - **GDPR** *(Article 32 Security of Processing)*
  - **ISO/IEC 27001:2022** *(Control A.8.8 Technical Vulnerabilities, A.8.20 Network Security, A.8.24 Cryptography)*
- **Historical Trend Analysis & Delta Engine**: Compares current findings against a previous scan JSON report to track `NEW`, `RECURRING`, `RESOLVED`, and `REGRESSED` issues over time.
- **C-Level Executive Dashboard**: Computes overall security posture letter grade (A+ to F), CVSS risk scores, compliance readiness percentages, and remediation SLAs (24h to 90d).
- **Multi-Format Exporters**:
  - **HTML**: Standalone interactive single-file dashboard with dark/light mode toggle, search bar, filter tabs, and responsive UI.
  - **PDF**: Pixel-perfect standalone PDF generation powered by `reportlab` (no external `wkhtmltopdf` binaries required).
  - **DOCX**: Editable Microsoft Word document with styled tables and callout boxes.
  - **JSON**: Machine-readable format for automation & CI/CD pipeline integration.

---

## 📁 Project Architecture

```
vapt-report-generator/
├── config/
│   └── report_config.yaml         # Branding, colors, thresholds, SLA rules
├── samples/
│   ├── burp_sample.xml            # Sample Burp Suite XML report
│   ├── nmap_sample.xml            # Sample Nmap XML scan output
│   ├── nuclei_sample.json         # Sample Nuclei scan results (JSON/JSONL)
│   ├── nessus_sample.xml          # Sample Nessus XML scan
│   ├── custom_sample.json         # Custom vulnerability array
│   └── previous_report.json       # Historical scan JSON for trend testing
├── src/
│   ├── cli.py                     # Command-line interface
│   ├── core/
│   │   ├── report_engine.py       # Main pipeline orchestrator
│   │   ├── data_processor.py      # Normalizer, deduplicator & text sanitizer
│   │   ├── classifier.py          # OWASP Top 10:2025, MITRE ATT&CK tagger
│   │   ├── compliance.py          # Regulatory Compliance Mapper
│   │   ├── trend_analyzer.py      # Historical Report Comparator & Delta Engine
│   │   └── risk_scorer.py         # CVSS, Impact, Exploitability & SLA calculator
│   ├── models/
│   │   └── vulnerability.py       # Core data models: Vulnerability, ScanReport, Severity
│   ├── parsers/
│   │   ├── burp_parser.py         # Burp XML parser (base64 supported)
│   │   ├── nmap_parser.py         # Nmap XML & NSE script parser
│   │   ├── nuclei_parser.py       # Nuclei JSON / JSONL parser
│   │   ├── nessus_parser.py       # Nessus v2 XML parser
│   │   └── custom_parser.py       # Custom JSON/CSV parser
│   ├── exporters/
│   │   ├── html_exporter.py       # Interactive Jinja2 HTML exporter
│   │   ├── pdf_exporter.py        # ReportLab standalone PDF exporter
│   │   ├── docx_exporter.py       # Microsoft Word exporter
│   │   └── json_exporter.py       # Machine-readable JSON exporter
│   └── templates/
│       ├── report.html            # Main HTML report Jinja2 template
│       └── styles.css             # Embedded CSS stylesheet
├── tests/                         # Unit tests
├── quick_start.py                 # Quick demonstration script
├── requirements.txt               # Dependencies
└── setup.py                       # Package installation script
```

---

## ⚡ Quick Start

### 1. Installation

```bash
# Clone or navigate to directory
cd C:\Users\kaila\.gemini\antigravity\scratch\vapt-report-generator

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Demo Report Generation

Generate full interactive HTML, PDF, DOCX, and JSON reports instantly using sample scan data:

```bash
python quick_start.py
```

Outputs will be saved to `output/vapt_report.html`, `output/vapt_report.pdf`, etc.

---

## 🚀 CLI Usage Guide

### Generate Report from Single Tool

```bash
python -m src.cli generate -i samples/burp_sample.xml -t burp -o report.html -f html
```

### Generate PDF Report from Multiple Tool Scans

```bash
python -m src.cli generate \
  -i samples/burp_sample.xml -t burp \
  -i samples/nmap_sample.xml -t nmap \
  -i samples/nuclei_sample.json -t nuclei \
  --client "Acme Corp" \
  --project "Q3 Pentest Audit" \
  -o report.pdf -f pdf
```

### Generate Report with Historical Trend Comparison

```bash
python -m src.cli generate \
  -i samples/burp_sample.xml -t burp \
  -p samples/previous_report.json \
  -o trend_report.html -f html
```

### CLI Options Reference

| Flag | Long Flag | Description | Default |
| --- | --- | --- | --- |
| `-i` | `--input` | Input scanner file path (can be passed multiple times) | **Required** |
| `-t` | `--type` | Scanner format (`burp`, `nmap`, `nuclei`, `nessus`, `custom`, `csv`) | **Required** |
| `-o` | `--output` | Destination output file path | `vapt_report.html` |
| `-f` | `--format` | Output format (`html`, `pdf`, `docx`, `json`) | `html` |
| `-p` | `--previous`| Path to previous report JSON for trend comparison | `None` |
| `--client` | `--client` | Target client organization name | `Acme Enterprise Corp` |
| `--project`| `--project`| Project / Assessment title | `Q3 Security Audit` |

---

## 🐍 Python API Integration (e.g. FlowGraph-VAPT)

You can import `ReportEngine` directly into your Python security tools:

```python
from src.core.report_engine import ReportEngine
from src.exporters import HTMLExporter, PDFExporter

engine = ReportEngine()

# 1. Parse raw scanner outputs
raw_vulnerabilities = engine.load_sources([
    {'path': 'scans/burp.xml', 'type': 'burp'},
    {'path': 'scans/nuclei.json', 'type': 'nuclei'}
])

# 2. Process pipeline & construct report
report = engine.create_report(
    raw_vulnerabilities,
    client_name="Acme Corp",
    project_name="API Pentest"
)

# 3. Export to desired format
HTMLExporter().export(report, "final_report.html")
PDFExporter().export(report, "final_report.pdf")
```
