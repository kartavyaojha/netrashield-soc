import os
import sys
import unittest
import json
import tempfile
from pathlib import Path

# Add backend to sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from fastapi.testclient import TestClient
from backend.main import app, db, engine
from backend.netrashield.playbook import generate_verdict_and_remediation, execute_containment_action
from backend.netrashield.report_pdf import generate_executive_pdf_report


class TestPlaybookAndFlagshipFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Seed an incident for testing
        cls.test_alert_id = "ALERT-TEST-PLAYBOOK-01"
        cls.test_incident = {
            "alert_id": cls.test_alert_id,
            "timestamp": "2026-11-26T12:00:00Z",
            "host": "WIN-DC-01",
            "severity": "CRITICAL",
            "risk_score": 92.5,
            "mitre_id": "T1059.001",
            "mitre_name": "PowerShell Execution",
            "detection_title": "Suspicious PowerShell Download Cradle",
            "process_command": "powershell.exe -nop -enc JABjAGwAaQBlAG4AdAA...",
            "process_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "dest_ip": "185.220.101.5",
            "dest_port": 443,
            "shannon_entropy": 5.82,
            "status": "Open",
            "raw_ecs": {
                "process": {
                    "name": "powershell.exe",
                    "parent": {"name": "services.exe", "pid": 780}
                }
            },
            "rule_ids": ["sigma-ps-cradle-01"]
        }
        db.save_incidents([cls.test_incident])

    def test_verdict_generation_mitre_tailored(self):
        """Verifies plain-English verdict and remediation checklist for T1059.001."""
        verdict = generate_verdict_and_remediation(self.test_incident)
        self.assertEqual(verdict["alert_id"], self.test_alert_id)
        self.assertIn("PowerShell", verdict["verdict"])
        self.assertIn("recommendation", verdict)
        checklist = verdict["remediation_checklist"]
        self.assertIsInstance(checklist, list)
        self.assertGreaterEqual(len(checklist), 3)
        self.assertTrue(any("ScriptBlock Logging" in s or "PowerShell" in s for s in checklist))

    def test_containment_isolate_host(self):
        """Verifies host isolation updates status to Contained and records audit entry."""
        res = execute_containment_action(
            db=db,
            alert_id=self.test_alert_id,
            action_type="ISOLATE_HOST",
            target_entity="WIN-DC-01",
            analyst_note="Quarantining infected domain controller per SOP-BLUE-4."
        )
        self.assertEqual(res["action_type"], "ISOLATE_HOST")
        self.assertEqual(res["new_status"], "Contained")

        # Verify in DB
        inc = db.get_incident_by_id(self.test_alert_id)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["status"], "Contained")

        # Verify audit logs
        logs = db.get_audit_logs(incident_id=self.test_alert_id)
        self.assertGreaterEqual(len(logs), 1)
        latest = logs[0]
        self.assertEqual(latest["action_type"], "ISOLATE_HOST")
        self.assertEqual(latest["target_entity"], "WIN-DC-01")

    def test_containment_block_dest_ip(self):
        """Verifies IP blocking checks format and records audit entry."""
        res = execute_containment_action(
            db=db,
            alert_id=self.test_alert_id,
            action_type="BLOCK_DEST_IP",
            target_entity="198.51.100.99",
            analyst_note="Blacklisting active C2 address."
        )
        self.assertEqual(res["action_type"], "BLOCK_DEST_IP")
        self.assertEqual(res["target_entity"], "198.51.100.99")

        # Verify invalid IP is rejected
        with self.assertRaises(ValueError):
            execute_containment_action(
                db=db,
                alert_id=self.test_alert_id,
                action_type="BLOCK_DEST_IP",
                target_entity="invalid-ip-address"
            )

    def test_api_verdict_endpoint(self):
        """GET /api/incidents/{alert_id}/verdict returns verdict JSON."""
        resp = self.client.get(f"/api/incidents/{self.test_alert_id}/verdict")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("verdict", data)
        self.assertIn("remediation_checklist", data)

    def test_api_contain_endpoint_governance(self):
        """POST /api/incidents/{alert_id}/contain rejects unconfirmed and accepts confirmed."""
        # Unconfirmed request must fail with 400
        unconfirmed = self.client.post(
            f"/api/incidents/{self.test_alert_id}/contain",
            json={
                "action_type": "DISABLE_USER_ACCOUNT",
                "target_entity": "admin_svc",
                "analyst_note": "Unconfirmed test",
                "confirmed": False
            }
        )
        self.assertEqual(unconfirmed.status_code, 400)

        # Confirmed request succeeds with 200
        confirmed = self.client.post(
            f"/api/incidents/{self.test_alert_id}/contain",
            json={
                "action_type": "DISABLE_USER_ACCOUNT",
                "target_entity": "admin_svc",
                "analyst_note": "Confirmed account lock",
                "confirmed": True
            }
        )
        self.assertEqual(confirmed.status_code, 200)
        data = confirmed.json()
        self.assertTrue(data.get("success"))

    def test_api_audit_endpoints(self):
        """GET /api/incidents/{alert_id}/audit and GET /api/audit return records."""
        inc_audit = self.client.get(f"/api/incidents/{self.test_alert_id}/audit")
        self.assertEqual(inc_audit.status_code, 200)
        self.assertIn("audit_logs", inc_audit.json())

        all_audit = self.client.get("/api/audit")
        self.assertEqual(all_audit.status_code, 200)
        self.assertIn("audit_logs", all_audit.json())

    def test_api_rules_crud(self):
        """Tests GET /api/rules, POST /api/rules, and DELETE /api/rules/{id}."""
        # 1. List rules
        resp = self.client.get("/api/rules")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("rules", resp.json())

        # 2. Add rule
        rule_yaml = """
title: Automated Test Rule
id: test-auto-sigma-01
description: Test detection rule
level: high
detection:
  selection:
    process_command|contains:
      - 'whoami'
  condition: selection
"""
        save_resp = self.client.post(
            "/api/rules",
            json={
                "rule_id": "test_auto_rule",
                "yaml_content": rule_yaml
            }
        )
        self.assertEqual(save_resp.status_code, 200)
        self.assertTrue(save_resp.json().get("success"))

        # 3. Delete rule
        del_resp = self.client.delete("/api/rules/test_auto_rule.yml")
        self.assertEqual(del_resp.status_code, 200)
        self.assertTrue(del_resp.json().get("success"))

    def test_pdf_export_generation(self):
        """Verifies ReportLab PDF generation and GET /api/triage/export/pdf."""
        incidents = [self.test_incident]
        audit_logs = db.get_audit_logs(limit=10)
        pdf_bytes = generate_executive_pdf_report(incidents, audit_logs)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

        # Test endpoint
        resp = self.client.get("/api/triage/export/pdf")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-type"), "application/pdf")
        self.assertTrue(resp.content.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
