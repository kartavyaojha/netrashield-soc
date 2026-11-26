# Kartavya's NetraShield SOC 2.4.0

NetraShield SOC is a local-first security operations workbench engineered for high-throughput cyber defense and threat triage. It normalizes multi-format telemetry into Elastic Common Schema (ECS), calculates real-time Shannon entropy, and fuses deterministic SigmaHQ detection rules with unsupervised Isolation Forest anomaly scoring. The entire engine executes inside an offline perimeter enclave, ensuring zero cloud telemetry leakage while evaluating 10,000 events in under 0.35 seconds.

---

## Architecture Overview

NetraShield decouples high-speed log ingestion from real-time analytics and presentation:

- **FastAPI Core Engine (`backend/`):** Asynchronous ASGI server providing REST endpoints, WebSocket event streaming, in-memory rate limiting, and HTTP security headers middleware.
- **ECS Parser & Shannon Math (`backend/netrashield/parser.py`):** Multi-format parser ingesting Windows Sysmon (EVTX/JSON), Linux Syslog (RFC-5424), Raw PCAP, and CSV records. Computes byte-level Shannon entropy ($H(X) = -\sum p_i \log_2 p_i$) to isolate Base64 and high-entropy download cradles.
- **Hybrid Correlation (`backend/netrashield/core_engine.py`):** Fuses deterministic Sigma YAML conditions (`rules/sigma/`) with a Scikit-Learn Isolation Forest ensemble (`[cmd_len, entropy, depth, port]`) and local IOC watchlists (`intel/ioc_store.json`) into a normalized 0–100 risk score.
- **Autonomous SOAR Subsystem (`backend/netrashield/soar.py`):** Five containment playbooks executing atomic IP quarantine, host loopback isolation, process termination, IAM session revocation, and DNS sinkholing with full rollback audit logging.
- **Editorial React Workbench (`frontend/`):** Vite, TypeScript, and Tailwind CSS client inspired by the Bonanza Studios Swiss-editorial design system. Features dual-mode display (Showcase vs. Full-Screen SOC Console), SVG attack graph visualizer, raw hex dump dossier, and Web Audio haptic feedback.

---

## Local Setup & Quick Start

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ and npm

### 1. Backend Setup
```bash
# From repository root:
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run build    # Produces production bundle in frontend/dist/
cd ..
```

### 3. Run the Development Environment

Start the backend and frontend in separate terminal sessions:

```bash
# Terminal 1: Backend API & UDP/TCP Syslog listener (port 5140)
uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Frontend Vite dev server
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) in your browser.

---

## Security Controls & Test Verification

NetraShield has undergone comprehensive Application Security (AppSec) hardening:

1. **Ingestion Validation:** Strict file extension allowlist (`.json`, `.ndjson`, `.jsonl`, `.csv`, `.evtx`, `.pcap`, `.pcapng`, `.log`, `.txt`, `.syslog`), 25MB single file / 50MB batch caps, 50,000 event caps, and path traversal sanitization inside isolated temporary directories.
2. **XXE Defense:** Integrated `defusedxml` and explicit entity detection blocking external entity resolution in `.evtx` records.
3. **CSV Formula Injection (DDE) Protection:** String cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r` are prefixed with `'` on CSV export to prevent spreadsheet execution vulnerabilities.
4. **API Security:** Custom middleware enforcing `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and restrictive `Content-Security-Policy`. Sliding-window in-memory per-IP rate limiting (120 req/min general, 15 req/min on heavy triage).
5. **Database & Syslog Hardening:** 100% parameterized SQLite statements (`?`), strict Pydantic input validation on IOCs (IPv4 regex, SHA256 length, hostname regex), and syslog socket control character / ANSI escape code stripping.

### Running Automated Tests

Run the full unit and security test suite:
```bash
python -m unittest discover -s tests -v
```

Expected output:
```text
test_batch_throughput_benchmark (test_netrashield.TestNetraShield) ... ok
test_ecs_normalization (test_netrashield.TestNetraShield) ... ok
test_isolation_forest_outlier (test_netrashield.TestNetraShield) ... ok
test_shannon_entropy_distinction (test_netrashield.TestNetraShield) ... ok
test_sigma_and_ioc_correlation (test_netrashield.TestNetraShield) ... ok
test_csv_formula_injection_sanitized (test_security.TestAppSecHardening) ... ok
test_existing_pipeline_tests_still_pass (test_security.TestAppSecHardening) ... ok
test_export_csv_endpoint_sanitizes_dde (test_security.TestAppSecHardening) ... ok
test_invalid_ioc_rejected (test_security.TestAppSecHardening) ... ok
test_rejects_disallowed_file_extension (test_security.TestAppSecHardening) ... ok
test_rejects_script_file_extension (test_security.TestAppSecHardening) ... ok
test_security_headers_present (test_security.TestAppSecHardening) ... ok
test_valid_ioc_accepted (test_security.TestAppSecHardening) ... ok

----------------------------------------------------------------------
Ran 13 tests in 0.45s - OK
```

---

## Author & Credits

Engineered by **Kartavya Ojha**.
Published under the MIT License.
