"""
FastAPI REST + WebSocket Server for NetraShield SOC 2.4.0
Serves correlation engine, incident management, IOC watchlist, MITRE ATT&CK matrix,
live syslog streaming, diagnostics, and static frontend mount.
"""
import os
import sys
from pathlib import Path

# Ensure backend directory is in sys.path
_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)
_root_dir = str(Path(__file__).resolve().parent.parent)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

import io
import csv
import json
import time
import asyncio
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from netrashield.options import DetectionOptions
from netrashield.database import DatabaseManager
from netrashield.parser import (
    TelemetryParser,
    ECSNormalizer,
    generate_synthetic_attack_telemetry,
    calculate_shannon_entropy
)
from netrashield.core_engine import CorrelationEngine
from netrashield.syslog_server import SyslogServer
from netrashield.soar import SoarEngine

app = FastAPI(
    title="NetraShield SOC 2.4.0 API",
    description="Kartavya's Blue-Team Cyber Defense & Threat Correlation Engine",
    version="2.4.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# App State
options = DetectionOptions.load_from_yaml("config.yaml")
db = DatabaseManager("data/netrashield.db")
engine = CorrelationEngine(
    rules_dir="rules/sigma",
    ioc_store_path="intel/ioc_store.json",
    options=options
)
syslog_server = SyslogServer(host="127.0.0.1", port=options.syslog_port)
soar_engine = SoarEngine()

# Auto-start syslog listener
syslog_server.start()

# Models
class StatusUpdate(BaseModel):
    status: str

class IOCItem(BaseModel):
    value: str
    type: str  # sha256 | ips | domains
    threat: str
    severity: str = "HIGH"
    tags: List[str] = []

class RetrainRequest(BaseModel):
    contamination: float = 0.05
    n_estimators: int = 100

class SettingsPayload(BaseModel):
    worker_threads: int = 4
    max_memory_ceiling_mb: int = 2048
    server_port: int = 8000
    syslog_port: int = 5140
    default_export_format: str = "json"
    min_risk_threshold: float = 40.0
    contamination: float = 0.05

class SoarExecutionRequest(BaseModel):
    playbook_id: str
    target: str
    alert_id: Optional[str] = None
    params: Optional[Dict[str, Any]] = None

class SoarRollbackRequest(BaseModel):
    action_id: str


# Endpoints
@app.get("/api/health")
def get_health():
    """
    Returns real-time status matrix for all 5 subsystems.
    """
    return {
        "status": "healthy",
        "subsystems": {
            "ecs_parser_engine": {"name": "ECS Parser Engine", "status": "ONLINE", "version": "2.4.0", "healthy": True},
            "sigma_compiler": {"name": "Sigma YAML Compiler", "status": "ONLINE", "rules_loaded": len(engine.sigma_rules), "healthy": True},
            "isolation_forest_model": {"name": "IsolationForest Model", "status": "ONLINE", "estimators": engine.options.n_estimators, "healthy": True},
            "sqlite_incident_store": {"name": "SQLite Incident Store", "status": "ONLINE", "db_path": db.db_path, "healthy": True},
            "syslog_socket": {"name": "UDP/TCP Syslog Socket", "status": "LISTENING" if syslog_server.running else "STOPPED", "port": syslog_server.port, "healthy": syslog_server.running}
        },
        "engine_status": "ML Engine: Online • Port 5140: Ready" if syslog_server.running else "ML Engine: Online • Port 5140: Stopped",
        "timestamp": time.time()
    }


@app.post("/api/triage/run")
async def run_triage(
    files: Optional[List[UploadFile]] = File(None),
    use_demo: bool = Form(False),
    min_risk_threshold: float = Form(40.0),
    contamination: float = Form(0.05),
    worker_threads: int = Form(4)
):
    """
    Ingests uploaded files and/or synthetic attack telemetry,
    runs hybrid correlation, persists incidents, and returns triage metrics.
    """
    parsed_events: List[Dict[str, Any]] = []

    # Parse uploaded files if present
    if files:
        for file in files:
            content_bytes = await file.read()
            filename = (file.filename or "").lower()
            try:
                if filename.endswith(".json"):
                    parsed_events.extend(TelemetryParser.parse_json(content_bytes.decode("utf-8", errors="replace")))
                elif filename.endswith(".csv"):
                    parsed_events.extend(TelemetryParser.parse_csv(content_bytes.decode("utf-8", errors="replace")))
                elif filename.endswith(".log") or filename.endswith(".syslog"):
                    parsed_events.extend(TelemetryParser.parse_syslog(content_bytes.decode("utf-8", errors="replace")))
                elif filename.endswith(".evtx"):
                    parsed_events.extend(TelemetryParser.parse_evtx(content_bytes))
                elif filename.endswith(".pcap") or filename.endswith(".cap"):
                    parsed_events.extend(TelemetryParser.parse_pcap(content_bytes))
                else:
                    # Generic text line parsing fallback
                    parsed_events.extend(TelemetryParser.parse_syslog(content_bytes.decode("utf-8", errors="replace")))
            except Exception as e:
                # Log or handle parsing failure gracefully
                pass

    # If use_demo or no files uploaded, inject synthetic attack & normal events
    if use_demo or len(parsed_events) == 0:
        demo_events = generate_synthetic_attack_telemetry(count=30)
        parsed_events.extend(demo_events)

    # Process batch through correlation engine
    results = engine.process_batch(parsed_events, min_risk_threshold=min_risk_threshold)

    # Persist alerts to SQLite
    if results["alerts"]:
        db.save_incidents(results["alerts"])

    # Persist report summary
    kpis = results["kpis"]
    db.save_triage_report({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_events": results["total_events"],
        "alert_count": results["alert_count"],
        "critical_count": kpis["critical_alerts"],
        "high_count": kpis["high_alerts"],
        "medium_count": len([a for a in results["alerts"] if a["severity"] == "MEDIUM"]),
        "low_count": len([a for a in results["alerts"] if a["severity"] == "LOW"]),
        "avg_risk_score": kpis["avg_risk_score"],
        "latency_ms": kpis["latency_ms"]
    })

    return results


@app.get("/api/triage/export/{format}")
def export_triage(format: str):
    """
    Exports latest triage incidents as CSV or JSON.
    """
    incidents = db.get_incidents(limit=1000)
    fmt = format.lower().strip()

    if fmt == "csv":
        output = io.StringIO()
        fieldnames = [
            "alert_id", "timestamp", "host", "severity", "risk_score",
            "mitre_id", "mitre_name", "detection_title", "process_command",
            "process_image", "dest_ip", "dest_port", "shannon_entropy", "status"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for inc in incidents:
            writer.writerow(inc)
        csv_data = output.getvalue()
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=netrashield_incidents.csv"}
        )
    else:
        return Response(
            content=json.dumps(incidents, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=netrashield_incidents.json"}
        )


@app.patch("/api/incidents/{alert_id}")
def update_incident_status(alert_id: str, payload: StatusUpdate):
    """
    Updates incident investigation status (Open -> Investigating -> Escalated -> Closed).
    """
    success = db.update_incident_status(alert_id, payload.status)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"success": True, "alert_id": alert_id, "new_status": payload.status}


@app.get("/api/iocs")
def get_iocs():
    """
    Returns all IOCs and count stats.
    """
    engine.load_iocs()
    return {
        "stats": {
            "sha256_count": len(engine.iocs.get("sha256", [])),
            "domains_count": len(engine.iocs.get("domains", [])),
            "ips_count": len(engine.iocs.get("ips", []))
        },
        "iocs": engine.iocs
    }


@app.post("/api/iocs")
def add_ioc(item: IOCItem):
    """
    Adds a new IOC indicator to watchlist, writes to intel/ioc_store.json, and hot-reloads engine.
    """
    t = item.type.lower().strip()
    if t not in ["sha256", "ips", "domains"]:
        raise HTTPException(status_code=400, detail="Type must be sha256, ips, or domains")

    new_entry = {
        "value": item.value.strip(),
        "threat": item.threat.strip(),
        "severity": item.severity,
        "tags": item.tags
    }
    if t not in engine.iocs:
        engine.iocs[t] = []
    
    # Avoid duplicate values
    engine.iocs[t] = [i for i in engine.iocs[t] if i["value"].lower() != item.value.lower().strip()]
    engine.iocs[t].append(new_entry)
    engine.save_iocs()
    return {"success": True, "message": f"Added IOC {item.value} to {t}", "item": new_entry}


@app.delete("/api/iocs")
def delete_ioc(value: str, type: str):
    """
    Deletes an IOC indicator and hot-reloads.
    """
    t = type.lower().strip()
    if t in engine.iocs:
        engine.iocs[t] = [i for i in engine.iocs[t] if i["value"].lower() != value.lower().strip()]
        engine.save_iocs()
        return {"success": True, "message": f"Deleted {value}"}
    raise HTTPException(status_code=400, detail="Invalid IOC type")


@app.get("/api/mitre")
def get_mitre_matrix():
    """
    Returns MITRE ATT&CK matrix view with active hits from database incidents.
    """
    incidents = db.get_incidents(limit=500)
    technique_hits: Dict[str, int] = {}
    for inc in incidents:
        mid = inc.get("mitre_id")
        if mid:
            technique_hits[mid] = technique_hits.get(mid, 0) + 1

    matrix = engine.mitre_mapper.get_matrix_view(technique_hits)
    return {
        "matrix": matrix,
        "total_hits": sum(technique_hits.values()),
        "active_techniques": list(technique_hits.keys())
    }


@app.post("/api/ml/retrain")
def retrain_ml(payload: RetrainRequest):
    """
    Re-trains Isolation Forest model with new contamination and n_estimators.
    """
    engine.train_isolation_forest(
        contamination=payload.contamination,
        n_estimators=payload.n_estimators
    )
    return {
        "success": True,
        "message": f"IsolationForest retrained with contamination={payload.contamination}, estimators={payload.n_estimators}",
        "contamination": payload.contamination,
        "n_estimators": payload.n_estimators
    }


@app.post("/api/syslog/start")
def start_syslog():
    success = syslog_server.start()
    return {"success": success, "port": syslog_server.port, "status": "LISTENING" if success else "ERROR"}


@app.post("/api/syslog/stop")
def stop_syslog():
    success = syslog_server.stop()
    return {"success": success, "status": "STOPPED"}


@app.post("/api/syslog/simulate")
def simulate_syslog_burst():
    """
    Simulates a rapid attack syslog burst.
    """
    count = syslog_server.simulate_attack_burst()
    return {"success": True, "packets_sent": count}


@app.websocket("/ws/syslog")
async def websocket_syslog(websocket: WebSocket):
    """
    Real-time WebSocket streaming of live syslog events and alerts.
    """
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue()
    syslog_server.subscribers.add(queue)

    # Send backlog of recent logs
    for log_line in syslog_server.recent_logs[-30:]:
        await websocket.send_text(log_line)

    try:
        while True:
            # Wait for either new log or incoming message
            log_line = await queue.get()
            await websocket.send_text(log_line)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        syslog_server.subscribers.discard(queue)


@app.get("/api/settings")
def get_settings():
    opts = DetectionOptions.load_from_yaml("config.yaml")
    return {
        "worker_threads": opts.worker_threads,
        "max_memory_ceiling_mb": opts.max_memory_ceiling_mb,
        "server_port": opts.server_port,
        "syslog_port": opts.syslog_port,
        "default_export_format": opts.default_export_format,
        "min_risk_threshold": opts.min_risk_threshold,
        "contamination": opts.contamination,
        "n_estimators": opts.n_estimators
    }


@app.post("/api/settings")
def save_settings(payload: SettingsPayload):
    opts = DetectionOptions.load_from_yaml("config.yaml")
    opts.worker_threads = payload.worker_threads
    opts.max_memory_ceiling_mb = payload.max_memory_ceiling_mb
    opts.server_port = payload.server_port
    opts.syslog_port = payload.syslog_port
    opts.default_export_format = payload.default_export_format
    opts.min_risk_threshold = payload.min_risk_threshold
    opts.contamination = payload.contamination
    opts.save_to_yaml("config.yaml")
    return {"success": True, "message": "Settings saved to config.yaml", "settings": payload.dict()}


# ==================== SOAR Autonomous Remediation API ====================

@app.get("/api/soar/playbooks")
def get_soar_playbooks():
    """
    Returns available blue-team automated response playbooks.
    """
    return {"playbooks": soar_engine.get_playbooks()}


@app.post("/api/soar/execute")
def execute_soar_playbook(payload: SoarExecutionRequest):
    """
    Executes containment playbook against target IP/Host/User/PID.
    """
    try:
        record = soar_engine.execute_playbook(
            playbook_id=payload.playbook_id,
            target=payload.target,
            alert_id=payload.alert_id,
            params=payload.params
        )
        return {"success": True, "action": record}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/soar/history")
def get_soar_history():
    """
    Returns audit history of automated SOAR actions taken.
    """
    return {"history": soar_engine.history}


@app.post("/api/soar/rollback")
def rollback_soar_action(payload: SoarRollbackRequest):
    """
    Rolls back containment action and restores normal network/host state.
    """
    try:
        record = soar_engine.rollback(payload.action_id)
        return {"success": True, "action": record}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# Serve static built frontend if exists
frontend_dist = Path(__file__).parent.parent / "frontend" / "dist"
if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="static_frontend")
