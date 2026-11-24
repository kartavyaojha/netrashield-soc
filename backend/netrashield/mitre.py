"""
MITRE ATT&CK taxonomy catalog & technique mapper for NetraShield SOC 2.4.0
"""
from typing import Dict, List, Optional, Any

TACTICS_CATALOG: Dict[str, Dict[str, Any]] = {
    "TA0002": {
        "id": "TA0002",
        "name": "Execution",
        "description": "Techniques that result in adversary-controlled code running on a local or remote system.",
    },
    "TA0003": {
        "id": "TA0003",
        "name": "Persistence",
        "description": "Techniques that adversaries use to keep access to systems across restarts or credential changes.",
    },
    "TA0005": {
        "id": "TA0005",
        "name": "Defense Evasion",
        "description": "Techniques that adversaries use to avoid detection throughout their compromise.",
    },
    "TA0006": {
        "id": "TA0006",
        "name": "Credential Access",
        "description": "Techniques for stealing credentials like account names and passwords.",
    },
    "TA0011": {
        "id": "TA0011",
        "name": "Command & Control",
        "description": "Techniques that adversaries may use to communicate with systems under their control within a victim network.",
    },
}

TECHNIQUES_CATALOG: Dict[str, Dict[str, Any]] = {
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell Execution",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
    },
    "T1003.001": {
        "id": "T1003.001",
        "name": "LSASS Memory Dump",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries may attempt to access credential material stored in the process memory of LSASS.",
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task Persistence",
        "tactic": "TA0003",
        "tactic_name": "Persistence",
        "description": "Adversaries may use the Windows Task Scheduler to execute programs at system startup or on a scheduled basis.",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force Authentication",
        "tactic": "TA0006",
        "tactic_name": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or spraying.",
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "TA0011",
        "tactic_name": "Command & Control",
        "description": "Adversaries may communicate using application layer protocols (e.g., HTTP/HTTPS) to blend in with normal network traffic.",
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated / High Entropy Files",
        "tactic": "TA0005",
        "tactic_name": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze through encryption, encoding, or packing.",
    },
}


class MitreAttackMapper:
    def __init__(self):
        self.tactics = TACTICS_CATALOG
        self.techniques = TECHNIQUES_CATALOG

    def lookup_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        norm_id = technique_id.upper().strip()
        return self.techniques.get(norm_id)

    def map_tags(self, tags: List[str]) -> List[Dict[str, Any]]:
        mapped = []
        for tag in tags:
            tag_clean = tag.lower().strip()
            # E.g. attack.t1059.001 or attack.t1110
            if "t1059.001" in tag_clean:
                mapped.append(self.techniques["T1059.001"])
            elif "t1003.001" in tag_clean:
                mapped.append(self.techniques["T1003.001"])
            elif "t1053.005" in tag_clean:
                mapped.append(self.techniques["T1053.005"])
            elif "t1110" in tag_clean:
                mapped.append(self.techniques["T1110"])
            elif "t1071.001" in tag_clean or "c2" in tag_clean:
                mapped.append(self.techniques["T1071.001"])
            elif "t1027" in tag_clean or "entropy" in tag_clean:
                mapped.append(self.techniques["T1027"])
        return mapped

    def get_matrix_view(self, hits_by_technique: Optional[Dict[str, int]] = None) -> List[Dict[str, Any]]:
        hits = hits_by_technique or {}
        matrix = []
        for tactic_id, tactic_info in self.tactics.items():
            t_techs = [
                {
                    **tech,
                    "count": hits.get(tech["id"], 0)
                }
                for tech in self.techniques.values()
                if tech["tactic"] == tactic_id
            ]
            matrix.append({
                "tactic_id": tactic_id,
                "tactic_name": tactic_info["name"],
                "description": tactic_info["description"],
                "techniques": t_techs,
                "total_hits": sum(t["count"] for t in t_techs)
            })
        return matrix
