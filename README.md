# NetraShield SOC 2.4.0 🛡️
> **Kartavya's Blue-Team Cyber Defense & Threat Correlation Engine**
> *FastAPI REST/WebSocket Backend + Bonanza Studios Dark Editorial Design System (React + Vite + Tailwind CSS + Recharts + Framer Motion)*

[![Python 3.14](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.165-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-Enterprise-red.svg)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚡ Overview

**NetraShield SOC 2.4.0** is an enterprise-grade, local security operations workbench designed to evaluate, normalize, and correlate large volumes of multi-vendor telemetry under 3 seconds with zero cloud data leakage.

### Key Capabilities
- **Hybrid Risk Fusion:** Fuses deterministic **SigmaHQ YAML rules** (`NS-SIG-1001` through `1004`), unsupervised **Isolation Forest anomaly detection**, and an **offline Threat Intelligence watchlist** (SHA256, IPv4, C2 Domains) into a unified 0–100 risk score.
- **ECS Normalizer & Shannon Entropy:** Converts Windows Sysmon (EID 1/3), Linux Syslog, PCAP packets, and EVTX files into standardized Elastic Common Schema (ECS) fields with realtime Shannon entropy computation ($H(X) = -\sum p_i \log_2 p_i$).
- **Sub-3s Throughput Benchmark:** Vectorized NumPy & Scikit-Learn inference evaluates **10,000 events in ~0.33 seconds** in memory.
- **Two-Mode User Interface:**
  1. **Bonanza Studios Editorial Showcase:** Tight-tracked grotesque typography (`Space Grotesk`), obsidian dot matrix canvas, dual-layer vertical text-roll CTAs, and an embedded interactive application frame (`netrashield.local/triage`).
  2. **Full-Screen Distraction-Free Workbench:** One-click full-screen cyber defense console with 5 interactive views.

---

## 🏗️ Architecture

```text
netrashield-soc/
├── config.yaml                     # Unified server & detection policy configuration
├── requirements.txt                # Python backend dependencies
├── backend/
│   ├── main.py                     # FastAPI REST API, WebSocket server & static frontend mount
│   └── netrashield/
│       ├── core_engine.py          # Vectorized Isolation Forest ML + Sigma YAML + IOC hybrid fusion
│       ├── database.py             # SQLite persistence (TelemetrySource, AlertIncident, TriageReport)
│       ├── parser.py               # Multi-format telemetry parser + ECS normalizer + Shannon entropy
│       ├── options.py              # DetectionOptions dataclass & config.yaml sync
│       ├── mitre.py                # MITRE ATT&CK taxonomy catalog & technique mapper
│       └── syslog_server.py        # Multi-threaded UDP/TCP Syslog listener (Port 5140) + broadcaster
├── frontend/                       # Bonanza-Style React + Vite + Tailwind App
│   ├── src/
│   │   ├── components/             # Showcase & SOC Workbench Views
│   │   │   ├── ThreatTriageView.tsx
│   │   │   ├── LiveSyslogView.tsx
│   │   │   ├── IocManagerView.tsx
│   │   │   ├── MitreMatrixView.tsx
│   │   │   ├── SettingsView.tsx
│   │   │   └── EmbeddedSocWorkbench.tsx
│   │   ├── App.tsx                 # Two-Mode Experience Switcher
│   │   └── types/soc.ts            # TypeScript interfaces
├── rules/sigma/                    # Auto-seeded Sigma rules (NS-SIG-1001..1004)
├── intel/ioc_store.json            # Offline Threat Intelligence store (SHA256, IPv4, Domains)
└── tests/
    ├── test_netrashield.py         # 5 automated unittests
    └── verify_live_system.py       # End-to-end integration verification suite
```

---

## 🚀 Quick Start

### 1. Clone & Set Up Backend
```bash
git clone https://github.com/kartavyaojha/netrashield-soc.git
cd netrashield-soc

# Create virtual environment & install requirements
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Set Up Frontend
```bash
cd frontend
npm install
npm run build   # Or run npm run dev for live hot-reloading
cd ..
```

### 3. Run Backend & Frontend
```bash
# Terminal 1: Start FastAPI REST & WebSocket Server (Port 8000 & Syslog Socket 5140)
uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Start Vite Dev Server (Port 5173)
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) in your browser.

---

## 🧪 Testing & Verification

Run the automated test suite verifying Shannon entropy math, ECS normalization, Sigma/IOC correlation, Isolation Forest outlier flagging, and the sub-3s 10,000-event throughput benchmark:

```bash
python -m unittest discover -s tests -v
```

Run the end-to-end live integration verification test:
```bash
python tests/verify_live_system.py
```

---

## 🛡️ Author

Created by **Kartavya Ojha**
*Autonomous Blue-Team Security Architect*
