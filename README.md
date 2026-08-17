# VAPT Report Generator

A modular Python framework and CLI tool for parsing, deduplicating, classifying, and reporting vulnerability assessment & penetration testing (VAPT) scan results.

Supports multi-scanner data ingestion (**Burp Suite**, **Nmap**, **Nuclei**, **Nessus**, and **Custom JSON/CSV**), mapping to **OWASP Top 10:2025** and **MITRE ATT&CK**, risk scoring, compliance auditing, and multi-format report exports (**HTML**, **PDF**, **DOCX**, **JSON**).

Includes both a CLI tool and a browser-based Web UI dashboard for drag-and-drop report generation.

---

## Features

- **Multi-Scanner Parser Support**:
  - **Burp Suite XML**: Parses issue details, request/response pairs, and decodes base64 payloads.
  - **Nmap XML**: Normalizes open ports, service banners, and NSE vulnerability scripts (`vulners`).
  - **Nuclei JSON / JSONL**: Ingests template IDs, target URLs, severity, and curl PoC commands.
  - **Tenable Nessus XML**: Native `.nessus` v2 file parsing.
  - **Custom JSON / CSV**: Standardized schema for custom scripts or internal scanner exports.
- **Smart Fingerprint Deduplication**: Hashes Host/URL + Vulnerability Title + Target Vector to merge overlapping findings across scanners.
- **OWASP Top 10:2025 Standard**: Maps findings against the OWASP Top 10:2025 taxonomy (`A01:2025` through `A10:2025`) with legacy 2021 cross-referencing.
- **MITRE ATT&CK Tagging**: Tags findings with relevant Tactics (*Initial Access*, *Execution*, *Privilege Escalation*) and Techniques (`T1190`, `T1059.007`, `T1189`, `T1110`).
- **Regulatory Compliance Auditing**: Rule-based mapping against **PCI-DSS 4.0**, **HIPAA Security Rule**, **GDPR Article 32**, and **ISO/IEC 27001:2022**.
- **Historical Scan Trend Delta**: Compares current assessment results against a previous scan JSON to mark findings as `NEW`, `RECURRING`, `RESOLVED`, or `REGRESSED`.
- **Multi-Format Deliverables**:
  - **HTML**: Self-contained responsive dashboard with dark/light mode, live search, and filter tabs.
  - **PDF**: Standalone PDF reports generated via `reportlab` (no external `wkhtmltopdf` binary dependency).
  - **DOCX**: Formatted Word document for manual editing and executive delivery.
  - **JSON**: Machine-readable JSON output for Jira / DefectDojo / CI-CD pipeline integration.

---

## Installation

```bash
git clone https://github.com/kailasshankarpr/vapt-report-generator.git
cd vapt-report-generator

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Quick Usage

### Option 1: Web UI Dashboard

Launch the local web dashboard server:

```bash
python3 quick_web.py
# or: python3 -m src.cli serve
```

Open **`http://localhost:8000`** in your browser, drag and drop scanner files, enter target details, and generate reports live.

### Option 2: Command Line Interface (CLI)

Generate an HTML report from a single scanner file:

```bash
python3 -m src.cli generate -i samples/burp_sample.xml -t burp -o report.html -f html
```

Combine multiple scanner outputs into a single PDF report:

```bash
python3 -m src.cli generate \
  -i samples/burp_sample.xml -t burp \
  -i samples/nmap_sample.xml -t nmap \
  -i samples/nuclei_sample.json -t nuclei \
  --client "Acme Corp" \
  --project "Q3 Full Scope VAPT Audit" \
  -o executive_report.pdf -f pdf
```

Generate a report with trend comparison against a previous scan:

```bash
python3 -m src.cli generate \
  -i samples/nuclei_sample.json -t nuclei \
  -p samples/previous_report.json \
  -o trend_report.html -f html
```

---

## CLI Options

| Flag | Argument | Description | Default |
| --- | --- | --- | --- |
| `-i` | `--input` | Path to scanner output file (can be specified multiple times) | **Required** |
| `-t` | `--type` | Scanner format (`burp`, `nmap`, `nuclei`, `nessus`, `custom`, `csv`) | **Required** |
| `-o` | `--output` | Destination output file path | `vapt_report.html` |
| `-f` | `--format` | Output format (`html`, `pdf`, `docx`, `json`) | `html` |
| `-p` | `--previous` | Path to previous report JSON for trend delta analysis | `None` |
| `--client` | `--client` | Target client or organization name | `Acme Enterprise Corp` |
| `--project` | `--project` | Assessment project title | `Q3 Security Audit` |

---

## Python API Usage

You can import `ReportEngine` directly into your custom tools or automation scripts:

```python
from src.core.report_engine import ReportEngine
from src.exporters import HTMLExporter, PDFExporter

engine = ReportEngine()

# Load raw scanner files
vulnerabilities = engine.load_sources([
    {'path': 'scans/burp.xml', 'type': 'burp'},
    {'path': 'scans/nuclei.json', 'type': 'nuclei'}
])

# Execute pipeline (normalize, deduplicate, classify, compliance, trend)
report = engine.create_report(
    vulnerabilities,
    client_name="Acme Corp",
    project_name="Web Application Security Audit"
)

# Export deliverables
HTMLExporter().export(report, "report.html")
PDFExporter().export(report, "report.pdf")
```

---

## Project Structure

```
vapt-report-generator/
├── config/
│   └── report_config.yaml         # Branding, SLA rules, and compliance mappings
├── samples/                       # Test sample scanner files
│   ├── burp_sample.xml
│   ├── nmap_sample.xml
│   ├── nuclei_sample.json
│   ├── nessus_sample.xml
│   └── previous_report.json
├── src/
│   ├── cli.py                     # CLI entrypoint
│   ├── core/                      # Core processing pipeline engine
│   │   ├── report_engine.py       # Main orchestrator
│   │   ├── data_processor.py      # Normalizer & deduplicator
│   │   ├── classifier.py          # OWASP 2025 & MITRE ATT&CK tagger
│   │   ├── compliance.py          # Regulatory mapper (PCI-DSS, HIPAA, GDPR, ISO)
│   │   ├── trend_analyzer.py      # Trend delta comparator
│   │   └── risk_scorer.py         # CVSS & SLA calculator
│   ├── models/                    # Data models (Pydantic / dataclasses)
│   ├── parsers/                   # Scanner output parsers
│   ├── exporters/                 # Output exporters (HTML, PDF, DOCX, JSON)
│   └── web/                       # FastAPI web dashboard UI
├── tests/                         # Unit test suite
├── quick_start.py                 # Quick CLI test script
├── quick_web.py                   # Web dashboard launcher script
└── requirements.txt               # Dependencies
```

---

## Running Unit Tests

Run the test suite to verify parsers and pipeline functionality:

```bash
python3 -m unittest discover -s tests
```

---

## License

Distributed under the MIT License. See `LICENSE` for details.
