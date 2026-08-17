import os
import shutil
import uuid
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.core.report_engine import ReportEngine
from src.exporters import HTMLExporter, PDFExporter, DOCXExporter, JSONExporter

app = FastAPI(title="VAPT Report Generator Web Server", version="1.0.0")

SESSION_DIR = "output/sessions"
os.makedirs(SESSION_DIR, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    tmpl_path = "src/web/templates/dashboard.html"
    if os.path.exists(tmpl_path):
        with open(tmpl_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>VAPT Report Generator API Dashboard</h1>"


@app.post("/api/generate")
async def generate_report(
    client_name: str = Form("Acme Enterprise Corp"),
    project_title: str = Form("Security Assessment"),
    scope: str = Form("Perimeter Scope"),
    files: List[UploadFile] = File(...),
    prev_report: Optional[UploadFile] = File(None)
):
    if not files:
        raise HTTPException(status_code=400, detail="No scan files uploaded.")

    session_id = str(uuid.uuid4())[:8]
    session_path = os.path.join(SESSION_DIR, session_id)
    os.makedirs(session_path, exist_ok=True)

    input_sources = []
    for uploaded in files:
        fname = uploaded.filename
        dest_path = os.path.join(session_path, fname)
        with open(dest_path, "wb") as buffer:
            shutil.copyfileobj(uploaded.file, buffer)

        # Detect tool type from extension / name
        stype = "custom"
        flower = fname.lower()
        if "burp" in flower or (flower.endswith(".xml") and "issue" in flower):
            stype = "burp"
        elif "nmap" in flower or (flower.endswith(".xml") and "nmap" in flower):
            stype = "nmap"
        elif "nuclei" in flower or flower.endswith(".json") or flower.endswith(".jsonl"):
            stype = "nuclei"
        elif flower.endswith(".nessus"):
            stype = "nessus"
        elif flower.endswith(".csv"):
            stype = "csv"

        input_sources.append({'path': dest_path, 'type': stype})

    prev_path = None
    if prev_report:
        prev_dest = os.path.join(session_path, "previous_scan.json")
        with open(prev_dest, "wb") as buffer:
            shutil.copyfileobj(prev_report.file, buffer)
        prev_path = prev_dest

    engine = ReportEngine()
    raw_vulns = engine.load_sources(input_sources)

    report = engine.create_report(
        raw_vulns,
        client_name=client_name,
        project_name=project_title,
        scope=scope,
        previous_report_path=prev_path
    )

    # Export formats
    html_path = os.path.join(session_path, "report.html")
    pdf_path = os.path.join(session_path, "report.pdf")
    docx_path = os.path.join(session_path, "report.docx")
    json_path = os.path.join(session_path, "report.json")

    HTMLExporter().export(report, html_path)
    PDFExporter().export(report, pdf_path)
    DOCXExporter().export(report, docx_path)
    json_export_path = JSONExporter().export(report, json_path)

    import json
    with open(json_export_path, "r", encoding="utf-8") as f:
        json_data = json.load(f)

    avg_comp = round(sum(d['compliance_score'] for d in report.compliance_summary.values()) / max(1, len(report.compliance_summary)), 1)

    return {
        'report_id': session_id,
        'summary': {
            'security_health_grade': report.security_health_grade,
            'overall_risk_rating': report.overall_risk_rating,
            'overall_risk_score': report.overall_risk_score,
            'total_vulnerabilities': report.total_vulnerabilities,
            'compliance_avg': avg_comp
        },
        'json_data': json_data
    }


@app.get("/api/download/{format}/{report_id}")
async def download_report(format: str, report_id: str):
    ext_map = {'html': 'report.html', 'pdf': 'report.pdf', 'docx': 'report.docx', 'json': 'report.json'}
    fname = ext_map.get(format.lower())
    if not fname:
        raise HTTPException(status_code=400, detail="Invalid format")

    file_path = os.path.join(SESSION_DIR, report_id, fname)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report not found")

    media_types = {
        'html': 'text/html',
        'pdf': 'application/pdf',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'json': 'application/json'
    }

    return FileResponse(file_path, media_type=media_types.get(format.lower()), filename=f"VAPT_Report_{report_id}.{format}")
