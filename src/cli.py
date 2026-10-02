import argparse
import sys
import os

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from typing import List

from src.core.report_engine import ReportEngine
from src.exporters import HTMLExporter, PDFExporter, DOCXExporter, JSONExporter


def main():
    parser = argparse.ArgumentParser(
        description="VAPT Report Generator - Enterprise Security Report Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Launch Web UI Dashboard server at http://localhost:8000
  python -m src.cli serve
  
  # Generate HTML report from Burp Suite XML
  python -m src.cli generate -i samples/burp_sample.xml -t burp -o report.html
  
  # Generate PDF report from multiple scanner sources
  python -m src.cli generate -i samples/burp_sample.xml -t burp -i samples/nmap_sample.xml -t nmap -o report.pdf -f pdf
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Launch Web UI Dashboard web server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")

    # Command: generate
    gen_parser = subparsers.add_parser("generate", help="Generate VAPT security report")
    gen_parser.add_argument("-i", "--input", action="append", required=True, help="Input scanner file path")
    gen_parser.add_argument("-t", "--type", action="append", required=True, choices=["burp", "nmap", "nuclei", "nessus", "custom", "csv", "flowgraph"], help="Scanner output type")
    gen_parser.add_argument("-o", "--output", default="vapt_report.html", help="Output destination filepath")
    gen_parser.add_argument("-f", "--format", default="html", choices=["html", "pdf", "docx", "json"], help="Output format")
    gen_parser.add_argument("-p", "--previous", default=None, help="Path to previous scan JSON report for trend analysis")
    gen_parser.add_argument("--client", default="Acme Enterprise Corp", help="Client name")
    gen_parser.add_argument("--project", default="Q3 Infrastructure Security Audit", help="Project name")
    gen_parser.add_argument("--scope", default="Web Application & Perimeter Network", help="Assessment Scope")
    gen_parser.add_argument("--config", default="config/report_config.yaml", help="Configuration file path")

    # Command: demo
    subparsers.add_parser("demo", help="Run instant demonstration using sample scanner data")

    # Command: version
    subparsers.add_parser("version", help="Show version information")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print("VAPT Report Generator Engine v1.0.0 (OWASP Top 10:2025 Standard)")
        sys.exit(0)

    if args.command == "serve":
        run_serve(args.host, args.port)
        sys.exit(0)

    if args.command == "demo":
        run_demo()
        sys.exit(0)

    if args.command == "generate":
        run_generate(args)


def run_serve(host: str, port: int):
    try:
        import uvicorn
        print("=" * 70)
        print("🌐 LAUNCHING VAPT REPORT GENERATOR WEB UI DASHBOARD")
        print("=" * 70)
        print(f" • Server listening at: http://localhost:{port}")
        print(f" • Network address:     http://{host}:{port}")
        print(" • Features: Drag-and-drop ingestion, live preview, multi-format download")
        print("=" * 70 + "\n")
        uvicorn.run("src.web.app:app", host=host, port=port, reload=False)
    except ImportError:
        print("❌ Error: uvicorn is required for web UI. Install via: pip install uvicorn fastapi python-multipart")
        sys.exit(1)


def run_generate(args):
    if len(args.input) != len(args.type):
        print("❌ Error: The number of --input files must match the number of --type arguments.")
        sys.exit(1)

    sources = []
    for path, stype in zip(args.input, args.type):
        if not os.path.exists(path):
            print(f"❌ Error: Input file not found: {path}")
            sys.exit(1)
        sources.append({'path': path, 'type': stype})

    engine = ReportEngine(args.config)

    print("🚀 Ingesting scanner findings...")
    raw_findings = engine.load_sources(sources)

    if not raw_findings:
        print("⚠️ Warning: No vulnerabilities were parsed from the input files.")

    print("\n⚡ Processing report pipeline...")
    report = engine.create_report(
        raw_findings,
        client_name=args.client,
        project_name=args.project,
        scope=args.scope,
        previous_report_path=args.previous
    )

    exporters = {
        'html': HTMLExporter(),
        'pdf': PDFExporter(),
        'docx': DOCXExporter(),
        'json': JSONExporter()
    }

    exporter = exporters.get(args.format.lower())
    if not exporter:
        print(f"❌ Error: Unsupported format '{args.format}'")
        sys.exit(1)

    print(f"\n📤 Exporting report as [{args.format.upper()}] to: {args.output}...")
    exporter.export(report, args.output)

    print(f"\n✅ Report generated successfully!")
    print(f"   Summary: Health Grade: {report.security_health_grade} | Total Findings: {report.total_vulnerabilities} ({report.vulnerabilities_by_severity.get('Critical', 0)} Critical, {report.vulnerabilities_by_severity.get('High', 0)} High)")
    print(f"   Destination: {os.path.abspath(args.output)}")


def run_demo():
    print("🚀 Running VAPT Report Generator Demo Mode...")

    sample_files = [
        ('samples/burp_sample.xml', 'burp'),
        ('samples/nmap_sample.xml', 'nmap'),
        ('samples/nuclei_sample.json', 'nuclei')
    ]

    for sf, _ in sample_files:
        if not os.path.exists(sf):
            print(f"❌ Error: Sample file missing: {sf}. Run setup first.")
            sys.exit(1)

    engine = ReportEngine()

    raw_findings = engine.load_sources([{'path': sf, 'type': st} for sf, st in sample_files])
    
    prev_path = 'samples/previous_report.json' if os.path.exists('samples/previous_report.json') else None

    report = engine.create_report(
        raw_findings,
        client_name="Acme Financial Corp",
        project_name="Annual Pentest & Compliance Audit",
        scope="Core Banking APIs & Public Web Infrastructure",
        previous_report_path=prev_path
    )

    os.makedirs('output', exist_ok=True)

    HTMLExporter().export(report, "output/demo_report.html")
    PDFExporter().export(report, "output/demo_report.pdf")
    DOCXExporter().export(report, "output/demo_report.docx")
    JSONExporter().export(report, "output/demo_report.json")

    print("\n🎉 Demo reports generated in output/ directory:")
    print("   • HTML: output/demo_report.html")
    print("   • PDF:  output/demo_report.pdf")
    print("   • DOCX: output/demo_report.docx")
    print("   • JSON: output/demo_report.json")


if __name__ == "__main__":
    main()
