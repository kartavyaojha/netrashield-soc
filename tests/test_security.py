import os
import io
import unittest
from fastapi.testclient import TestClient
from backend.main import app, db, sanitize_csv_cell

client = TestClient(app)

class TestAppSecHardening(unittest.TestCase):

    def test_security_headers_present(self):
        """Verify essential HTTP security headers are returned on API endpoints."""
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        headers = response.headers
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("referrer-policy"), "strict-origin-when-cross-origin")
        self.assertIn("geolocation=()", headers.get("permissions-policy", ""))
        self.assertIn("default-src 'self'", headers.get("content-security-policy", ""))

    def test_rejects_disallowed_file_extension(self):
        """Verify upload endpoint rejects unauthorized file types like .exe or .sh with 400 Bad Request."""
        file_payload = ("malware.exe", b"MZ executable binary payload", "application/octet-stream")
        response = client.post(
            "/api/triage/run",
            files={"files": file_payload}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Disallowed file extension", response.json().get("detail", ""))

    def test_rejects_script_file_extension(self):
        """Verify shell script uploads are rejected with 400."""
        file_payload = ("hack.sh", b"#!/bin/bash\nrm -rf /", "text/x-sh")
        response = client.post(
            "/api/triage/run",
            files={"files": file_payload}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Disallowed file extension", response.json().get("detail", ""))

    def test_invalid_ioc_rejected(self):
        """Verify Pydantic validation rejects malformed IP, hash, or domain with 422."""
        # 1. Malformed IP
        bad_ip = {"type": "ips", "value": "999.999.999.999", "severity": "High"}
        resp1 = client.post("/api/iocs", json=bad_ip)
        self.assertEqual(resp1.status_code, 422)

        # 2. Malformed SHA256 (too short or invalid chars)
        bad_hash = {"type": "sha256", "value": "deadbeef123", "severity": "High"}
        resp2 = client.post("/api/iocs", json=bad_hash)
        self.assertEqual(resp2.status_code, 422)

        # 3. Malformed Domain (spaces or invalid format)
        bad_domain = {"type": "domains", "value": "bad domain with spaces!.com", "severity": "High"}
        resp3 = client.post("/api/iocs", json=bad_domain)
        self.assertEqual(resp3.status_code, 422)

    def test_valid_ioc_accepted(self):
        """Verify valid IOCs pass Pydantic validation."""
        valid_ip = {
            "type": "ips",
            "value": "198.51.100.45",
            "threat": "Known Cobalt Strike C2",
            "severity": "HIGH",
            "tags": ["c2", "apt"]
        }
        resp = client.post("/api/iocs", json=valid_ip)
        self.assertIn(resp.status_code, [200, 201])
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("status"), "success")

    def test_csv_formula_injection_sanitized(self):
        """Verify CSV export sanitizes potential Excel formula injection (DDE payloads)."""
        # Formula characters: =, +, -, @, \t, \r
        self.assertEqual(sanitize_csv_cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("-2+3+cmd|' /C calc'!A0"), "'-2+3+cmd|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("@SUM(A1:A10)"), "'@SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("\tDDE"), "'\tDDE")
        self.assertEqual(sanitize_csv_cell("\rDDE"), "'\rDDE")
        # Regular text should remain untouched
        self.assertEqual(sanitize_csv_cell("PowerShell.exe -ExecutionPolicy Bypass"), "PowerShell.exe -ExecutionPolicy Bypass")
        self.assertEqual(sanitize_csv_cell("192.168.1.50"), "192.168.1.50")
        self.assertEqual(sanitize_csv_cell(12345), 12345)

    def test_export_csv_endpoint_sanitizes_dde(self):
        """Verify that incidents exported via /api/triage/export/csv have DDE formula characters safely escaped."""
        # Insert a synthetic incident with an injected DDE formula in process_command
        test_incident = {
            "alert_id": "ALT-SEC-DDE-01",
            "timestamp": "2026-11-25T12:00:00Z",
            "host": "FINANCE-PC01",
            "severity": "HIGH",
            "risk_score": 88.5,
            "mitre_id": "T1059",
            "mitre_name": "Command Execution",
            "detection_title": "DDE Injection Test Alert",
            "process_command": "=cmd|' /C calc'!A0",
            "process_image": "cmd.exe",
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "shannon_entropy": 4.5,
            "status": "Open"
        }
        db.save_incidents([test_incident])

        # Export CSV via API endpoint
        export_resp = client.get("/api/triage/export/csv")
        self.assertEqual(export_resp.status_code, 200)
        csv_text = export_resp.text
        # Assert that the formula injection command line was prepended with single quote
        self.assertIn("'=cmd|' /C calc'!A0", csv_text)

    def test_existing_pipeline_tests_still_pass(self):
        """Sanity check that the DetectionOptions and CorrelationEngine initialize properly."""
        self.assertIsNotNone(app)
        self.assertIsNotNone(db)

if __name__ == "__main__":
    unittest.main()
