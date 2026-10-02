#!/usr/bin/env python3
"""
Launcher script for VAPT Report Generator Web UI Dashboard Server
"""
import sys
import uvicorn

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

if __name__ == "__main__":
    print("=" * 70)
    print("🌐 LAUNCHING VAPT REPORT GENERATOR WEB UI DASHBOARD SERVER")
    print("=" * 70)
    print(" • Access Web UI at: http://localhost:8000")
    print(" • Network Access:   http://0.0.0.0:8000")
    print(" • Press Ctrl+C to stop the server.")
    print("=" * 70 + "\n")
    uvicorn.run("src.web.app:app", host="0.0.0.0", port=8000, reload=False)
