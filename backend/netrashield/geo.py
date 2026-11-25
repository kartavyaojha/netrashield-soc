"""
NetraShield Geo-IP Threat Telemetry Engine
Maps live attack vectors to global coordinates for the 3D Interactive Threat Globe.
"""

from typing import List, Dict, Any
import random

PRIMARY_ENCLAVE = {
    "name": "NetraShield Primary Enclave (AWS us-west-1)",
    "city": "San Francisco",
    "country": "USA",
    "lat": 37.7749,
    "lon": -122.4194
}

GLOBAL_ADVERSARIES: List[Dict[str, Any]] = [
    {
        "id": "adv-001",
        "city": "Moscow",
        "country": "Russia",
        "country_code": "RU",
        "lat": 55.7558,
        "lon": 37.6173,
        "ip": "185.220.101.5",
        "attack_type": "SSH Brute-force & LSASS Memory Dump",
        "technique": "T1003.001",
        "severity": "CRITICAL",
        "risk_score": 96,
        "bandwidth": "48.2 MB/s"
    },
    {
        "id": "adv-002",
        "city": "Beijing",
        "country": "China",
        "country_code": "CN",
        "lat": 39.9042,
        "lon": 116.4074,
        "ip": "202.108.22.5",
        "attack_type": "Log4j RCE & Web Shell Dropper",
        "technique": "T1190",
        "severity": "CRITICAL",
        "risk_score": 92,
        "bandwidth": "112.5 MB/s"
    },
    {
        "id": "adv-003",
        "city": "Pyongyang",
        "country": "North Korea",
        "country_code": "KP",
        "lat": 39.0392,
        "lon": 125.7625,
        "ip": "175.45.176.8",
        "attack_type": "Cobalt Strike C2 Beacon Infiltration",
        "technique": "T1071.001",
        "severity": "HIGH",
        "risk_score": 88,
        "bandwidth": "14.8 MB/s"
    },
    {
        "id": "adv-004",
        "city": "Bucharest",
        "country": "Romania",
        "country_code": "RO",
        "lat": 44.4268,
        "lon": 26.1025,
        "ip": "193.106.191.24",
        "attack_type": "DNS Tunneling Exfiltration",
        "technique": "T1071.004",
        "severity": "HIGH",
        "risk_score": 81,
        "bandwidth": "6.4 MB/s"
    },
    {
        "id": "adv-005",
        "city": "São Paulo",
        "country": "Brazil",
        "country_code": "BR",
        "lat": -23.5505,
        "lon": -46.6333,
        "ip": "177.18.204.11",
        "attack_type": "Mirai Distributed SYN Amplification",
        "technique": "T1498.001",
        "severity": "MEDIUM",
        "risk_score": 68,
        "bandwidth": "890.0 MB/s"
    },
    {
        "id": "adv-006",
        "city": "Tehran",
        "country": "Iran",
        "country_code": "IR",
        "lat": 35.6892,
        "lon": 51.3890,
        "ip": "91.240.118.15",
        "attack_type": "Ivanti Connect Secure Zero-Day Exploit",
        "technique": "T1212",
        "severity": "CRITICAL",
        "risk_score": 94,
        "bandwidth": "31.0 MB/s"
    },
    {
        "id": "adv-007",
        "city": "Lagos",
        "country": "Nigeria",
        "country_code": "NG",
        "lat": 6.5244,
        "lon": 3.3792,
        "ip": "102.134.42.19",
        "attack_type": "OAuth Credential Stuffing & Spray",
        "technique": "T1110.003",
        "severity": "MEDIUM",
        "risk_score": 62,
        "bandwidth": "2.1 MB/s"
    },
    {
        "id": "adv-008",
        "city": "Frankfurt",
        "country": "Germany",
        "country_code": "DE",
        "lat": 50.1109,
        "lon": 8.6821,
        "ip": "141.98.10.42",
        "attack_type": "Tor Exit Node Ingress Reconnaissance",
        "technique": "T1595.002",
        "severity": "LOW",
        "risk_score": 45,
        "bandwidth": "0.8 MB/s"
    }
]

def get_threat_vectors() -> Dict[str, Any]:
    """
    Returns enriched geo-threat vectors for 3D Globe visualization.
    """
    return {
        "target_enclave": PRIMARY_ENCLAVE,
        "active_vectors": GLOBAL_ADVERSARIES,
        "total_active_sources": len(GLOBAL_ADVERSARIES),
        "critical_vectors_count": len([v for v in GLOBAL_ADVERSARIES if v["severity"] == "CRITICAL"]),
        "global_threat_index": "ELEVATED (DEFCON 2)",
        "inbound_rate_eps": 1420 + random.randint(-80, 150)
    }
