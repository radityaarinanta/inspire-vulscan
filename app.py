import os
import asyncio
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from pydantic import BaseModel

from core.models import ScanConfig, ScanProfile, ScanResult
from core.engine import scanner_engine
from core.reporter import ReportGenerator

app = FastAPI(
    title="Inspire - Web Vulnerability Scanner & Security Audit Suite",
    description="Enterprise-grade OWASP-aligned Web Security Audit Platform",
    version="1.0.0"
)

# Ensure directories exist
os.makedirs("reports", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("static/img", exist_ok=True)

# Mount static and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
reporter = ReportGenerator(template_dir="templates", reports_dir="reports")

class StartScanRequest(BaseModel):
    target_url: str
    profile: ScanProfile = ScanProfile.STANDARD
    max_depth: Optional[int] = 2
    max_pages: Optional[int] = 15

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/scan/start")
async def start_scan(payload: StartScanRequest, background_tasks: BackgroundTasks):
    target = payload.target_url.strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urlparse(target)
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid target URL provided.")

    config = ScanConfig(
        target_url=target,
        profile=payload.profile,
        max_crawl_depth=payload.max_depth or 2,
        max_pages=payload.max_pages or 15
    )

    import uuid
    scan_id = str(uuid.uuid4())[:8]

    # Launch scan in background task
    background_tasks.add_task(scanner_engine.run_scan, config, scan_id)

    return {"scan_id": scan_id, "status": "started", "target_url": target}

@app.get("/api/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    if scan_id in scanner_engine.active_scans:
        result = scanner_engine.active_scans[scan_id]
        return result.model_dump()
    elif scan_id in scanner_engine.scan_progress:
        return scanner_engine.scan_progress[scan_id].model_dump()
    raise HTTPException(status_code=404, detail="Scan ID not found.")

@app.get("/api/scan/report/pdf/{scan_id}")
async def download_pdf_report(scan_id: str):
    if scan_id not in scanner_engine.active_scans:
        raise HTTPException(status_code=404, detail="Scan result not found.")
    
    result = scanner_engine.active_scans[scan_id]
    pdf_path = reporter.generate_pdf_report(result)
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"Inspire_Report_{scan_id}.pdf"
    )

@app.get("/api/scan/report/html/{scan_id}")
async def download_html_report(scan_id: str):
    if scan_id not in scanner_engine.active_scans:
        raise HTTPException(status_code=404, detail="Scan result not found.")
    
    result = scanner_engine.active_scans[scan_id]
    html_path = reporter.generate_html_report(result)
    
    return FileResponse(
        html_path,
        media_type="text/html",
        filename=f"Inspire_Report_{scan_id}.html"
    )

@app.get("/api/scan/report/json/{scan_id}")
async def download_json_report(scan_id: str):
    if scan_id not in scanner_engine.active_scans:
        raise HTTPException(status_code=404, detail="Scan result not found.")
    
    result = scanner_engine.active_scans[scan_id]
    json_path = reporter.generate_json_report(result)
    
    return FileResponse(
        json_path,
        media_type="application/json",
        filename=f"Inspire_Report_{scan_id}.json"
    )

@app.get("/api/scan/report/sarif/{scan_id}")
async def download_sarif_report(scan_id: str):
    if scan_id not in scanner_engine.active_scans:
        raise HTTPException(status_code=404, detail="Scan result not found.")
    
    result = scanner_engine.active_scans[scan_id]
    sarif_path = reporter.generate_sarif_report(result)
    
    return FileResponse(
        sarif_path,
        media_type="application/json",
        filename=f"Inspire_Report_{scan_id}.sarif"
    )

@app.get("/api/scan/report/csv/{scan_id}")
async def download_csv_report(scan_id: str):
    if scan_id not in scanner_engine.active_scans:
        raise HTTPException(status_code=404, detail="Scan result not found.")
    
    result = scanner_engine.active_scans[scan_id]
    csv_path = reporter.generate_csv_report(result)
    
    return FileResponse(
        csv_path,
        media_type="text/csv",
        filename=f"Inspire_Report_{scan_id}.csv"
    )

@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    async def event_listener(message: dict):
        try:
            await websocket.send_json(message)
        except Exception:
            pass

    scanner_engine.subscribe(scan_id, event_listener)

    # Send initial status if exists
    if scan_id in scanner_engine.scan_progress:
        await websocket.send_json({
            "event": "progress",
            "scan_id": scan_id,
            "data": scanner_engine.scan_progress[scan_id].model_dump()
        })

    try:
        while True:
            # Keep alive and receive client signals
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        scanner_engine.unsubscribe(scan_id, event_listener)
    except Exception:
        scanner_engine.unsubscribe(scan_id, event_listener)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
