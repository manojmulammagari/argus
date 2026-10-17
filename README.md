<div align="center">
  <img src="assets/banner.svg" alt="ARGUS Banner" width="100%">

  <h3>Autonomous DevSecOps Intelligence</h3>

  <p>
    <b>ARGUS</b> is an intelligent swarm of security agents that analyzes code, discovers vulnerabilities, maps business risk, and automatically writes remediation patches—before exploits hit production.

    
  </p>

  <div>
    <img src="https://img.shields.io/badge/Next.js-black?style=for-the-badge&logo=next.js&logoColor=white" alt="Next.js" />
    <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
    <img src="https://img.shields.io/badge/Groq-F55036?style=for-the-badge&logo=groq&logoColor=white" alt="Groq" />
    <img src="https://img.shields.io/badge/Gemini-8E75B2?style=for-the-badge&logo=google&logoColor=white" alt="Gemini" />
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="MIT License" />
  </div>
</div>

<br />

## 📖 Overview

Modern software moves too fast for traditional Static Application Security Testing (SAST). Legacy tools generate overwhelming false positives and lack the context required to actually fix the flaws they find. **ARGUS replaces the legacy scanner.**

By orchestrating **a swarm of 6 specialized AI agents**, ARGUS provides a live, real-time security team. It doesn't just scan; it investigates, exploits, models threats, and writes the patch.

Demo video : https://www.youtube.com/watch?v=3Yq6s_Rh3ys

---

## 🤖 The Swarm Architecture

ARGUS executes its pipeline in parallel, leveraging specialized agents to reduce hallucination and increase depth of analysis.

| Agent | Designation | Core Capability |
| :--- | :--- | :--- |
| 🛡️ **AST Sentinel** | Vulnerability Scanner | Analyzes syntax and data flow to detect low-level flaws (SQLi, XSS, exposed secrets). |
| 📜 **Policy Guard** | Compliance Auditor | Maps flaws to strict regulatory frameworks (SOC2, HIPAA, PCI-DSS) to ensure compliance. |
| 🏗️ **Arch Auditor** | Architecture Reviewer | Identifies systemic design flaws, missing auth checks, and broken topological logic. |
| 🎯 **ThreatMind** | Threat Modeler | Uses STRIDE methodologies to identify spoofing, tampering, and privilege escalation risks. |
| 🔧 **RemedyBot** | Auto-Remediator | Automatically drafts pull requests and Gist patches to neutralize critical findings immediately. |
| 💀 **Red Team Ω** | Exploit Engineer | Simulates an attacker to construct multi-step kill chains and validate true exploitability. |

---

## 🛡️ Enterprise-Grade Defenses

ARGUS is built with defensive engineering to operate safely in zero-trust, high-scale environments:

- **LLM Prompt Injection Defense (XML Boundaries):** Untrusted code diffs are strictly encapsulated within `<untrusted_diff>` XML tags. System prompts heavily instruct the models to treat this boundary purely as literal data, preventing prompt injection payloads from hijacking the analysis.
- **Resilient SSE Streaming:** The dashboard receives live analysis traces via Server-Sent Events (SSE). Our backend features heartbeat client detection to immediately reap resources if a client disconnects, preventing memory leaks and runaway processes.
- **Orchestrated Concurrency:** Using `asyncio.gather`, ARGUS runs Phase 1 agents in parallel, followed by Phase 2 remediation. **Per-agent timeout guards** guarantee that a single hung model or network timeout never freezes the entire pipeline. 

---

## 🔮 The Breach Oracle

To bridge the gap between technical flaws and business risk, ARGUS integrates a **Breach Oracle**. When a vulnerability (e.g., CWE-89) is discovered, the Oracle dynamically cites real-world historical breaches (e.g., *"Equifax 2017, $1.4B impact"*) mapping to that exact CWE, quantifying the financial and regulatory gravity for stakeholders.

---

## ⚡ Quick Start Guide

Experience ARGUS locally in under two minutes.

> **Prerequisites:** Ensure you have **[Node.js](https://nodejs.org/)** (v20+) and **[Python](https://www.python.org/)** (3.11+ / 3.13) installed.

### 1. Zero-Key Instant Demo (No signup needed)
ARGUS includes a built-in **Demo Mode**. If no API keys are configured, ARGUS automatically activates labeled demo data so you can evaluate the complete 6-agent swarm immediately:

```bash
# Clone the repository
git clone https://github.com/manojmulammagari/argus.git
cd argus

# Start backend (:8000)
cd backend
python -m venv venv
# Windows: venv\Scripts\activate | Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main_api:app --reload

# In a second terminal, start dashboard (:3000)
cd ../frontend
npm install
npm run dev
```
Navigate to 👉 **[http://localhost:3000](http://localhost:3000)** and click **"Start Demo Scan"**.

---

### 2. Live LLM Inference Mode (Optional)
To use real live inference across Groq and Google Gemini:

```bash
# In backend/ directory
cp .env.example .env
```
Add your free API keys:
- **Groq API Key:** Free at [console.groq.com](https://console.groq.com) (primary engine, streams at 300+ tok/s)
- **Gemini API Key:** Free at [aistudio.google.com](https://aistudio.google.com) (backup engine)

### Environment Variables

| Variable | Description | Required? | Default |
| :--- | :--- | :--- | :--- |
| `GROQ_API_KEY` | Primary LLM inference key (Groq free tier) | Optional* | None |
| `GEMINI_API_KEY` | Secondary / fallback LLM key (Google AI Studio) | Optional* | None |
| `PORT` | Backend HTTP port | Optional | `8000` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | Optional | `http://localhost:3000,http://127.0.0.1:3000` |
| `NEXT_PUBLIC_API_URL` | Backend URL for frontend Next.js requests | Optional | `http://localhost:8000` |

*\*If neither key is set, ARGUS operates in built-in Demo Mode.*

---

## 📡 API & SSE Streaming Contract

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/demo` | Dispatches an autonomous scan job |
| `GET` | `/api/stream/{scan_id}` | Real-time Server-Sent Events (SSE) event stream |
| `GET` | `/api/scans` | Lists recent scans in memory (bounded by 1-hour TTL) |
| `GET` | `/api/scans/{scan_id}` | Retrieves scan metadata, findings, and kill chain |
| `POST` | `/api/scans/{scan_id}/approve` | Approves remediation and triggers completion |
| `GET` | `/health` | Service healthcheck & LLM provider status |

---

## ⚖️ Architecture Decisions & Limitations

- **In-memory state:** Live demo scans are stored in memory with a 1-hour TTL and admission control (max 3 concurrent scans). Persistent PostgreSQL schema (`backend/schema.sql`) is provided for durable storage deployments.
- **Fail-safe agent isolation:** Each agent runs in a guarded 90-second timeout. If any provider experiences rate limits or network issues, the remaining agents complete normally.

<br />

<div align="center">
  <i>Engineered for the future of autonomous security.</i>
</div>

