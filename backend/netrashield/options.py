from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
import yaml

@dataclass
class DetectionOptions:
    min_risk_threshold: float = 40.0
    contamination: float = 0.05
    worker_threads: int = 4
    max_memory_ceiling_mb: int = 2048
    default_export_format: str = "json"
    server_port: int = 8000
    syslog_port: int = 5140
    n_estimators: int = 100

    @classmethod
    def load_from_yaml(cls, path: str = "config.yaml") -> "DetectionOptions":
        p = Path(path)
        if not p.exists():
            return cls()
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            server = data.get("server", {})
            det = data.get("detection", {})
            ml = data.get("ml", {})
            return cls(
                min_risk_threshold=float(det.get("min_risk_threshold", 40.0)),
                contamination=float(det.get("contamination", 0.05)),
                worker_threads=int(det.get("worker_threads", 4)),
                max_memory_ceiling_mb=int(det.get("max_memory_ceiling_mb", 2048)),
                default_export_format=str(det.get("default_export_format", "json")),
                server_port=int(server.get("port", 8000)),
                syslog_port=int(server.get("syslog_port", 5140)),
                n_estimators=int(ml.get("n_estimators", 100)),
            )
        except Exception:
            return cls()

    def save_to_yaml(self, path: str = "config.yaml") -> None:
        p = Path(path)
        existing = {}
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    existing = yaml.safe_load(f) or {}
            except Exception:
                existing = {}

        if "server" not in existing:
            existing["server"] = {}
        existing["server"]["port"] = self.server_port
        existing["server"]["syslog_port"] = self.syslog_port

        if "detection" not in existing:
            existing["detection"] = {}
        existing["detection"]["min_risk_threshold"] = self.min_risk_threshold
        existing["detection"]["contamination"] = self.contamination
        existing["detection"]["worker_threads"] = self.worker_threads
        existing["detection"]["max_memory_ceiling_mb"] = self.max_memory_ceiling_mb
        existing["detection"]["default_export_format"] = self.default_export_format

        if "ml" not in existing:
            existing["ml"] = {}
        existing["ml"]["contamination"] = self.contamination
        existing["ml"]["n_estimators"] = self.n_estimators

        with open(p, "w", encoding="utf-8") as f:
            yaml.dump(existing, f, default_flow_style=False)
