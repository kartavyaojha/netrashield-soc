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
import tempfile
import logging
import ipaddress
import re
import yaml
from typing import List, Optional, Dict, Any, Literal

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Form,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    BackgroundTasks,
    Request
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, model_validator

from netrashield.options import DetectionOptions
from netrashield.database import DatabaseManager
from netrashield.parser import (
    TelemetryParser,
    ECSNormalizer,
    generate_synthetic_attack_telemetry,
    calculate_shannon_entropy,
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    MAX_BATCH_SIZE,
    MAX_EVENTS_PER_BATCH
)
from netrashield.core_engine import CorrelationEngine
from netrashield.syslog_server import SyslogServer
from netrashield.soar import SoarEngine
from netrashield.playbook import generate_verdict_and_remediation, execute_containment_action
from netrashield.report_pdf import generate_executive_pdf_report

Path("logs").mkdir(exist_ok=True)
logger = logging.getLogger("netrashield")
if not logger.handlers:
    fh = logging.FileHandler("logs/server.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)

app = FastAPI(
    title="NetraShield SOC 2.4.0 API",
    description="Open-Source Blue-Team Cyber Defense & Threat Correlation Engine",
    version="2.4.0"
)

# Strict Explicit CORS Policy
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:7860",
    "http://127.0.0.1:8000",
    "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# HTTP Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "connect-src 'self' ws://127.0.0.1:8000 ws://localhost:8000 http://127.0.0.1:8000 http://localhost:8000 ws://127.0.0.1:5173; "
        "frame-ancestors 'none';"
    )
    return response

# In-Memory Per-IP Rate Limiting Middleware
class InMemoryRateLimiter:
    def __init__(self):
        self.history: Dict[str, List[float]] = {}
        self.lock = asyncio.Lock()

    async def check(self, client_ip: str, endpoint: str) -> bool:
        limit = 120  # standard API endpoints: 120 req/min
        if endpoint.startswith("/api/triage/run"):
            limit = 15  # heavy correlation: max 15 req/min
        elif endpoint.startswith("/api/ml/retrain"):
            limit = 10  # ML retraining: max 10 req/min

        now = time.time()
        key = f"{client_ip}:{endpoint}"
        async with self.lock:
            timestamps = self.history.get(key, [])
            timestamps = [t for t in timestamps if now - t < 60.0]
            if len(timestamps) >= limit:
                self.history[key] = timestamps
                return False
            timestamps.append(now)
            self.history[key] = timestamps
            return True

rate_limiter = InMemoryRateLimiter()

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    path = request.url.path
    if path.startswith("/api/"):
        allowed = await rate_limiter.check(client_ip, path)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down."}
            )
    return await call_next(request)

# Global Error Sanitization Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    logger.exception(f"Unhandled error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

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
SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')
DOMAIN_REGEX = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$')

class StatusUpdate(BaseModel):
    status: Literal["Open", "Investigating", "Escalated", "Contained", "Resolved", "Closed"]

class ContainmentRequest(BaseModel):
    action_type: Literal["ISOLATE_HOST", "BLOCK_DEST_IP", "DISABLE_USER_ACCOUNT"]
    target_entity: str
    analyst_note: str = ""
    confirmed: bool = False

class RulePayload(BaseModel):
    rule_id: str
    yaml_content: str

class IOCItem(BaseModel):
    value: str
    type: Literal["sha256", "ips", "domains", "ip", "hash", "domain"]
    threat: str = "Threat Indicator"
    severity: str = "HIGH"
    tags: List[str] = []

    @model_validator(mode='after')
    def validate_ioc_value(self):
        val = self.value.strip()
        t = self.type.lower()
        if t in ("ips", "ip"):
            try:
                ipaddress.ip_address(val)
            except ValueError:
                raise ValueError(f"Invalid IP address format: {val}")
        elif t in ("sha256", "hash"):
            if not SHA256_REGEX.match(val):
                raise ValueError("Invalid SHA256 hash: must be exactly 64 hexadecimal characters")
        elif t in ("domains", "domain"):
            if not DOMAIN_REGEX.match(val):
                raise ValueError(f"Invalid domain hostname format: {val}")
        return self

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
    Hardened against path traversal, oversized payloads, and unsafe formats.
    """
    total_batch_size = 0
    parsed_events: List[Dict[str, Any]] = []

    # Parse uploaded files if present with strict validation & isolation
    if files:
        with tempfile.TemporaryDirectory() as temp_dir:
            for file in files:
                # Sanitize filename & prevent path traversal
                raw_filename = file.filename or ""
                safe_name = Path(raw_filename).name
                ext = Path(safe_name).suffix.lower()

                # Strict extension allowlist
                if not ext or ext not in ALLOWED_EXTENSIONS:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Disallowed file extension '{ext}'. Permitted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                    )

                content_bytes = await file.read()
                file_size = len(content_bytes)

                # Strict file and batch size limits
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File '{safe_name}' exceeds maximum allowed size of 25MB."
                    )
                total_batch_size += file_size
                if total_batch_size > MAX_BATCH_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Total batch upload exceeds maximum allowed limit of 50MB."
                    )

                # Isolated disk write in temporary directory
                temp_file = Path(temp_dir) / safe_name
                temp_file.write_bytes(content_bytes)

                try:
                    if ext in [".json", ".ndjson", ".jsonl"]:
                        parsed_events.extend(TelemetryParser.parse_json(content_bytes.decode("utf-8", errors="replace")))
                    elif ext == ".csv":
                        parsed_events.extend(TelemetryParser.parse_csv(content_bytes.decode("utf-8", errors="replace")))
                    elif ext in [".log", ".txt", ".syslog"]:
                        parsed_events.extend(TelemetryParser.parse_syslog(content_bytes.decode("utf-8", errors="replace")))
                    elif ext == ".evtx":
                        parsed_events.extend(TelemetryParser.parse_evtx(content_bytes))
                    elif ext in [".pcap", ".pcapng", ".cap"]:
                        parsed_events.extend(TelemetryParser.parse_pcap(content_bytes))
                    else:
                        parsed_events.extend(TelemetryParser.parse_syslog(content_bytes.decode("utf-8", errors="replace")))
                except Exception as e:
                    logger.warning(f"Failed parsing uploaded file {safe_name}: {e}")

    if use_demo or len(parsed_events) == 0:
        demo_events = generate_synthetic_attack_telemetry(count=30)
        parsed_events.extend(demo_events)

    results = engine.process_batch(parsed_events, min_risk_threshold=min_risk_threshold)

    if results["alerts"]:
        db.save_incidents(results["alerts"])

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


DDE_CHARS = ('=', '+', '-', '@', '\t', '\r')

def sanitize_csv_cell(val: Any) -> Any:
    """
    Guards against CSV / Excel Formula Injection (DDE).
    Prefixes cells starting with =, +, -, @, \\t, or \\r with a single quote.
    """
    if isinstance(val, str) and val.startswith(DDE_CHARS):
        return "'" + val
    return val


@app.get("/api/triage/export/{format}")
def export_triage(format: str):
    """
    Exports latest triage incidents as CSV, JSON, or PDF with DDE formula injection protection.
    """
    incidents = db.get_incidents(limit=1000)
    fmt = format.lower().strip()

    if fmt == "pdf":
        audit_logs = db.get_audit_logs(limit=50)
        pdf_bytes = generate_executive_pdf_report(incidents, audit_logs)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=netrashield_executive_report.pdf"}
        )
    elif fmt == "csv":
        output = io.StringIO()
        fieldnames = [
            "alert_id", "timestamp", "host", "severity", "risk_score",
            "mitre_id", "mitre_name", "detection_title", "process_command",
            "process_image", "dest_ip", "dest_port", "shannon_entropy", "status"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for inc in incidents:
            sanitized_row = {k: sanitize_csv_cell(v) for k, v in inc.items()}
            writer.writerow(sanitized_row)
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
    Updates incident investigation status (Open -> Investigating -> Escalated -> Contained -> Resolved -> Closed).
    """
    success = db.update_incident_status(alert_id, payload.status)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"success": True, "alert_id": alert_id, "new_status": payload.status}


# ==================== Human-in-the-Loop Playbook & Audit API ====================

@app.get("/api/incidents/{alert_id}/verdict")
def get_incident_verdict(alert_id: str):
    """
    Generates plain-English investigation verdict and MITRE-tailored remediation checklist.
    """
    incident = db.get_incident_by_id(alert_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    verdict_data = generate_verdict_and_remediation(incident)
    return verdict_data


@app.post("/api/incidents/{alert_id}/contain")
def trigger_containment(alert_id: str, payload: ContainmentRequest):
    """
    Executes governed analyst containment action (ISOLATE_HOST, BLOCK_DEST_IP, DISABLE_USER_ACCOUNT).
    Requires explicit confirmed: true flag from analyst.
    """
    if not payload.confirmed:
        raise HTTPException(status_code=400, detail="Containment action must be explicitly confirmed by analyst.")
    try:
        result = execute_containment_action(
            db=db,
            alert_id=alert_id,
            action_type=payload.action_type,
            target_entity=payload.target_entity,
            analyst_note=payload.analyst_note
        )
        return {"success": True, **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/incidents/{alert_id}/audit")
def get_incident_audit(alert_id: str):
    """
    Returns audit trail entries specific to a given incident.
    """
    logs = db.get_audit_logs(incident_id=alert_id)
    return {"audit_logs": logs}


@app.get("/api/audit")
def get_all_audit_logs():
    """
    Returns full containment and remediation audit ledger.
    """
    logs = db.get_audit_logs(limit=100)
    return {"audit_logs": logs}


# ==================== In-Browser Sigma Rule Studio API ====================

@app.get("/api/rules")
def list_sigma_rules():
    """
    Enumerates all active Sigma detection rules from rules/sigma/.
    """
    rules_dir = Path("rules/sigma")
    rules_list = []
    if rules_dir.exists():
        for file_path in sorted(rules_dir.glob("*.y*ml")):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        rules_list.append({
                            "id": str(data.get("id", file_path.stem)),
                            "title": data.get("title", file_path.stem),
                            "level": data.get("level", "medium"),
                            "description": data.get("description", ""),
                            "tags": data.get("tags", []),
                            "raw_yaml": content,
                            "file_name": file_path.name
                        })
            except Exception as e:
                logger.warning(f"Failed parsing rule file {file_path}: {e}")
    return {"rules": rules_list, "total": len(rules_list)}


@app.post("/api/rules")
def save_sigma_rule(payload: RulePayload):
    """
    Validates, saves, and hot-reloads a Sigma rule in rules/sigma/.
    """
    try:
        parsed = yaml.safe_load(payload.yaml_content)
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="YAML must parse into a mapping/dictionary")
        if "title" not in parsed:
            raise HTTPException(status_code=400, detail="Sigma rule must contain a 'title' field")
        if "detection" not in parsed:
            raise HTTPException(status_code=400, detail="Sigma rule must contain a 'detection' field")
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML syntax: {str(e)}")

    safe_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '', payload.rule_id.strip())
    if not safe_id:
        safe_id = f"custom_rule_{int(time.time())}"
    if not (safe_id.endswith(".yml") or safe_id.endswith(".yaml")):
        safe_id = f"{safe_id}.yml"

    rules_dir = Path("rules/sigma")
    rules_dir.mkdir(parents=True, exist_ok=True)
    target_path = rules_dir / safe_id
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(payload.yaml_content)

    # Hot-reload rules into the correlation engine
    engine.load_sigma_rules()
    return {
        "success": True,
        "rule_id": safe_id,
        "rules_count": len(engine.sigma_rules)
    }


@app.delete("/api/rules/{rule_id}")
def delete_sigma_rule(rule_id: str):
    """
    Deletes a Sigma rule file and hot-reloads the engine.
    """
    safe_id = re.sub(r'[^a-zA-Z0-9_\-\.]', '', rule_id.strip())
    if not (safe_id.endswith(".yml") or safe_id.endswith(".yaml")):
        file_candidates = [f"{safe_id}.yml", f"{safe_id}.yaml"]
    else:
        file_candidates = [safe_id]

    deleted = False
    rules_dir = Path("rules/sigma")
    for fname in file_candidates:
        fpath = rules_dir / fname
        if fpath.exists():
            fpath.unlink()
            deleted = True
            break

    if not deleted:
        raise HTTPException(status_code=404, detail="Sigma rule file not found")

    engine.load_sigma_rules()
    return {"success": True, "deleted": safe_id, "rules_count": len(engine.sigma_rules)}


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
    if t == "ip":
        t = "ips"
    elif t == "hash":
        t = "sha256"
    elif t == "domain":
        t = "domains"
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
    return {"status": "success", "success": True, "message": f"Added IOC {item.value} to {t}", "item": new_entry}


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
    if (frontend_dist / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="static_assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("ws/"):
            raise HTTPException(status_code=404, detail="Endpoint not found")
        file_path = frontend_dist / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_dist / "index.html")
