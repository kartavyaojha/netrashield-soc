"""
Core Correlation and Detection Engine for NetraShield SOC 2.4.0
Hybrid detection combining Sigma YAML rules, IOC Watchlist, and IsolationForest ML.
"""
import os
import json
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import yaml
import numpy as np
from sklearn.ensemble import IsolationForest

from .parser import calculate_shannon_entropy, ECSNormalizer
from .mitre import MitreAttackMapper
from .options import DetectionOptions


class CorrelationEngine:
    def __init__(
        self,
        rules_dir: str = "rules/sigma",
        ioc_store_path: str = "intel/ioc_store.json",
        options: Optional[DetectionOptions] = None
    ):
        self.rules_dir = rules_dir
        self.ioc_store_path = ioc_store_path
        self.options = options or DetectionOptions()
        self.mitre_mapper = MitreAttackMapper()
        self.sigma_rules: List[Dict[str, Any]] = []
        self.iocs: Dict[str, List[Dict[str, Any]]] = {"sha256": [], "ips": [], "domains": []}
        self.ioc_lookup_sets: Dict[str, Dict[str, Dict[str, Any]]] = {"sha256": {}, "ips": {}, "domains": {}}
        
        self.load_rules()
        self.load_iocs()
        self.model: Optional[IsolationForest] = None
        self.train_isolation_forest(
            contamination=self.options.contamination,
            n_estimators=self.options.n_estimators
        )

    def load_rules(self) -> None:
        self.sigma_rules.clear()
        p = Path(self.rules_dir)
        if not p.exists():
            return
        for file in p.glob("*.yml"):
            try:
                with open(file, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    if rule and isinstance(rule, dict):
                        self.sigma_rules.append(rule)
            except Exception:
                continue

    def load_iocs(self) -> None:
        p = Path(self.ioc_store_path)
        if not p.exists():
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.iocs = {
                    "sha256": data.get("sha256", []),
                    "ips": data.get("ips", []),
                    "domains": data.get("domains", [])
                }
        except Exception:
            return

        # Build fast lookup sets
        self.ioc_lookup_sets = {
            "sha256": {item["value"].lower(): item for item in self.iocs.get("sha256", [])},
            "ips": {item["value"].strip(): item for item in self.iocs.get("ips", [])},
            "domains": {item["value"].lower().strip(): item for item in self.iocs.get("domains", [])}
        }

    def save_iocs(self) -> None:
        p = Path(self.ioc_store_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(self.iocs, f, indent=2)
        # Re-build lookup sets
        self.load_iocs()

    def train_isolation_forest(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42
    ) -> None:
        """
        Trains baseline model on 600 synthetic normal telemetry samples:
        Features: [cmd_len, shannon_entropy, proc_depth, dst_port_norm]
        """
        np.random.seed(random_state)
        n_samples = 600

        # Normal telemetry feature distributions
        # cmd_len: normal commands are typically 25 to 70 chars
        cmd_lens = np.clip(np.random.normal(loc=45.0, scale=12.0, size=n_samples), 10.0, 150.0)
        # shannon_entropy: normal commands 2.4 - 3.4
        entropies = np.clip(np.random.normal(loc=2.95, scale=0.25, size=n_samples), 1.5, 3.6)
        # proc_depth: directory depth 2 to 5
        depths = np.clip(np.random.normal(loc=3.5, scale=0.8, size=n_samples), 1.0, 6.0)
        # dst_port_norm: common ports 0, 80, 443 normalized
        ports_choice = np.array([0, 80, 443, 53, 8080]) / 65535.0
        dst_ports = np.random.choice(ports_choice, size=n_samples)

        X_train = np.column_stack([cmd_lens, entropies, depths, dst_ports])

        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1
        )
        self.model.fit(X_train)

    @staticmethod
    def extract_features(event: Dict[str, Any]) -> Tuple[float, float, float, float]:
        cmd = event.get("CommandLine") or event.get("process", {}).get("command_line", "") or ""
        ent = float(event.get("shannon_entropy") or event.get("process", {}).get("entropy") or calculate_shannon_entropy(cmd))
        img = event.get("Image") or event.get("process", {}).get("executable", "") or ""
        depth = float(len([p for p in img.replace("\\", "/").split("/") if p]))
        port = float(event.get("DestinationPort") or event.get("destination", {}).get("port") or 0)
        port_norm = min(max(port / 65535.0, 0.0), 1.0)
        return (float(len(cmd)), ent, depth, port_norm)

    def match_sigma(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matched_rules = []
        cmd = (event.get("CommandLine") or "").lower()
        img = (event.get("Image") or "").lower()
        evt_action = str(event.get("event.action") or event.get("event", {}).get("action", "")).lower()

        for rule in self.sigma_rules:
            det = rule.get("detection", {})
            sel = det.get("selection", {})
            rule_matched = True

            # Image|endswith check
            if "Image|endswith" in sel:
                suffixes = [s.lower() for s in sel["Image|endswith"]]
                if not any(img.endswith(s) for s in suffixes):
                    rule_matched = False

            # CommandLine|contains check
            if rule_matched and "CommandLine|contains" in sel:
                terms = [t.lower() for t in sel["CommandLine|contains"]]
                if not any(term in cmd for term in terms):
                    rule_matched = False

            # event.action|contains check
            if rule_matched and "event.action|contains" in sel:
                terms = [t.lower() for t in sel["event.action|contains"]]
                if not any(term in evt_action or term in cmd for term in terms):
                    rule_matched = False

            if rule_matched:
                matched_rules.append(rule)

        return matched_rules

    def match_iocs(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        hits = []
        # Check IP
        dst_ip = str(event.get("DestinationIp") or event.get("destination", {}).get("ip") or "").strip()
        if dst_ip and dst_ip in self.ioc_lookup_sets["ips"]:
            hits.append(self.ioc_lookup_sets["ips"][dst_ip])

        src_ip = str(event.get("SourceIp") or event.get("source", {}).get("ip") or "").strip()
        if src_ip and src_ip in self.ioc_lookup_sets["ips"] and src_ip != dst_ip:
            hits.append(self.ioc_lookup_sets["ips"][src_ip])

        # Check Hashes
        hashes_str = str(event.get("Hashes") or "").lower()
        proc_hashes = event.get("process", {}).get("hash", {})
        if isinstance(proc_hashes, dict):
            for h_val in proc_hashes.values():
                h_val_clean = str(h_val).lower().strip()
                if h_val_clean in self.ioc_lookup_sets["sha256"]:
                    hits.append(self.ioc_lookup_sets["sha256"][h_val_clean])
        for sha_val, ioc_obj in self.ioc_lookup_sets["sha256"].items():
            if sha_val in hashes_str and ioc_obj not in hits:
                hits.append(ioc_obj)

        # Check Domains in CommandLine
        cmd = str(event.get("CommandLine") or "").lower()
        for domain, ioc_obj in self.ioc_lookup_sets["domains"].items():
            if domain in cmd and ioc_obj not in hits:
                hits.append(ioc_obj)

        return hits

    def correlate_event(
        self,
        event: Dict[str, Any],
        raw_ml_score: float
    ) -> Dict[str, Any]:
        """
        Combines ML risk score with Sigma rules and IOC watchlist.
        """
        matched_rules = self.match_sigma(event)
        matched_iocs = self.match_iocs(event)

        base_risk = raw_ml_score

        # Hybrid Risk Fusion
        if matched_rules:
            # max(base_risk, 78.0 + 6.0 * len(rules))
            sigma_floor = 78.0 + 6.0 * len(matched_rules)
            base_risk = max(base_risk, sigma_floor)

        if matched_iocs:
            # if IOC hit max(base_risk, 92.0)
            base_risk = max(base_risk, 92.0)

        final_risk = min(round(base_risk, 1), 99.9)

        # Severity token assignment
        if final_risk >= 85.0:
            severity = "CRITICAL"
        elif final_risk >= 70.0:
            severity = "HIGH"
        elif final_risk >= 50.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Determine detection title and MITRE mapping
        detection_title = "ML Anomaly: Outlier Process Execution"
        mitre_id = "T1027"
        mitre_name = "Obfuscated / High Entropy Execution"

        if matched_rules:
            primary_rule = matched_rules[0]
            detection_title = primary_rule.get("title", detection_title)
            tags = primary_rule.get("tags", [])
            mapped = self.mitre_mapper.map_tags(tags)
            if mapped:
                mitre_id = mapped[0]["id"]
                mitre_name = mapped[0]["name"]
        elif matched_iocs:
            primary_ioc = matched_iocs[0]
            detection_title = f"IOC Match: {primary_ioc.get('threat', 'Malicious Indicator')}"
            mitre_id = "T1071.001"
            mitre_name = "Web Protocols C2"
        elif final_risk >= 70.0:
            detection_title = "ML Anomaly: High-Entropy Outlier"
            mitre_id = "T1027"
            mitre_name = "Obfuscated Files or Information"

        host = event.get("Computer") or event.get("host", {}).get("name") or "WORKSTATION-01"
        cmd = event.get("CommandLine") or event.get("process", {}).get("command_line") or ""
        img = event.get("Image") or event.get("process", {}).get("executable") or ""
        dst_ip = event.get("DestinationIp") or event.get("destination", {}).get("ip") or ""
        dst_port = event.get("DestinationPort") or event.get("destination", {}).get("port") or 0
        entropy = event.get("shannon_entropy") or event.get("process", {}).get("entropy") or calculate_shannon_entropy(cmd)

        alert_id = f"ALT-{uuid.uuid4().hex[:8].upper()}"

        return {
            "alert_id": alert_id,
            "timestamp": event.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": host,
            "severity": severity,
            "risk_score": final_risk,
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "detection_title": detection_title,
            "process_command": cmd,
            "process_image": img,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "shannon_entropy": round(entropy, 4),
            "status": "Open",
            "matched_rules": [r.get("id") for r in matched_rules],
            "matched_iocs": [i.get("value") for i in matched_iocs],
            "raw_ecs": event
        }

    def process_batch(
        self,
        events: List[Dict[str, Any]],
        min_risk_threshold: float = 40.0
    ) -> Dict[str, Any]:
        """
        Processes batch of events with sub-3s high-throughput vectorized ML inference.
        """
        start_time = time.time()
        n_events = len(events)
        if n_events == 0:
            return {
                "total_events": 0,
                "alerts": [],
                "kpis": {
                    "total_events": 0,
                    "critical_alerts": 0,
                    "high_alerts": 0,
                    "avg_risk_score": 0.0,
                    "latency_ms": 0.0
                },
                "distributions": {"severity": {}, "mitre": {}}
            }

        # Vectorized feature matrix extraction
        feature_matrix = np.empty((n_events, 4), dtype=np.float32)
        for i, ev in enumerate(events):
            cmd = ev.get("CommandLine") or ev.get("process", {}).get("command_line", "") or ""
            ent = ev.get("shannon_entropy") or ev.get("process", {}).get("entropy")
            if ent is None:
                ent = calculate_shannon_entropy(cmd)
                ev["shannon_entropy"] = ent
            img = ev.get("Image") or ev.get("process", {}).get("executable", "") or ""
            # fast depth count
            depth = img.count("\\") + img.count("/") + 1
            port = ev.get("DestinationPort") or ev.get("destination", {}).get("port") or 0
            feature_matrix[i, 0] = len(cmd)
            feature_matrix[i, 1] = ent
            feature_matrix[i, 2] = depth
            feature_matrix[i, 3] = (float(port) / 65535.0) if port else 0.0

        # Batch ML decision function
        raw_scores = self.model.decision_function(feature_matrix)
        # Convert decision function to 0-100: np.clip((0.25 - raw_scores) * 160.0, 0.0, 100.0)
        ml_scores = np.clip((0.25 - raw_scores) * 160.0, 0.0, 100.0)

        # Correlate
        alerts = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        mitre_counts: Dict[str, int] = {}
        total_risk = 0.0

        for i, ev in enumerate(events):
            alert = self.correlate_event(ev, float(ml_scores[i]))
            risk = alert["risk_score"]
            total_risk += risk

            if risk >= min_risk_threshold:
                alerts.append(alert)
                sev = alert["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                m_id = alert["mitre_id"]
                if m_id:
                    mitre_counts[m_id] = mitre_counts.get(m_id, 0) + 1

        latency_ms = round((time.time() - start_time) * 1000.0, 2)
        avg_risk = round(total_risk / n_events, 1) if n_events > 0 else 0.0

        # Sort alerts descending by risk score
        alerts.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "total_events": n_events,
            "alert_count": len(alerts),
            "alerts": alerts,
            "kpis": {
                "total_events": n_events,
                "critical_alerts": severity_counts.get("CRITICAL", 0),
                "high_alerts": severity_counts.get("HIGH", 0),
                "avg_risk_score": avg_risk,
                "latency_ms": latency_ms
            },
            "distributions": {
                "severity": [
                    {"name": "CRITICAL", "count": severity_counts.get("CRITICAL", 0), "color": "#F43F5E"},
                    {"name": "HIGH", "count": severity_counts.get("HIGH", 0), "color": "#F59E0B"},
                    {"name": "MEDIUM", "count": severity_counts.get("MEDIUM", 0), "color": "#0EA5E9"},
                    {"name": "LOW", "count": severity_counts.get("LOW", 0), "color": "#10B981"}
                ],
                "mitre": [
                    {"technique": k, "count": v} for k, v in sorted(mitre_counts.items(), key=lambda x: x[1], reverse=True)
                ]
            }
        }
