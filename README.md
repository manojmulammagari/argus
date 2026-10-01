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

> **Prerequisites:** Ensure you have **[Node.js](https://nodejs.org/)** (v18+) and **[Python](https://www.python.org/)** (3.10+) installed.

### 1. Configure the Environment
ARGUS uses **Groq** for high-speed inference and **Google Gemini** as a structural fallback.
```bash
# Clone the repository (if not already local)
git clone https://github.com/your-org/argus.git
cd argus

# Duplicate the example environment file
cp backend/.env.example backend/.env
```
*(Open `backend/.env` in your text editor and paste in your API keys).*

### 2. Boot the AI Backend (FastAPI)
Open a terminal and start the backend engine. *We strongly recommend using a virtual environment.*
```bash
cd backend
python -m venv venv

# Activate (Windows):
venv\Scripts\activate
# Activate (Mac/Linux):
# source venv/bin/activate

pip install -r requirements.txt
python -m uvicorn main_api:app --reload
```

### 3. Boot the Dashboard (Next.js)
Open a **second, separate terminal** and start the frontend interface:
```bash
cd frontend
npm install
npm run dev
```

### 4. Initiate the Swarm
Navigate to 👉 **[http://localhost:3000](http://localhost:3000)** in your browser. Click **"Start Demo Scan"** to watch the real-time SSE event stream as the agents analyze, exploit, and patch the vulnerable repository.

<br />

<div align="center">
  <i>Engineered for the future of autonomous security.</i>
</div>