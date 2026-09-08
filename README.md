<div align="center">

<!-- Animated Header Banner -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&height=200&section=header&text=ARGUS&fontSize=65&fontAlignY=38&desc=Autonomous%20DevSecOps%20Intelligence&descAlignY=55&descAlign=50" width="100%"/>

### 🛡️ Proactive Security & Automated Remediation

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Groq](https://img.shields.io/badge/Groq-Llama_3-F7931E?style=flat-square)](https://groq.com/)
[![Gemini](https://img.shields.io/badge/Google-Gemini-4285F4?style=flat-square&logo=google&logoColor=white)](https://aistudio.google.com/)

[Watch 120s Demo Video](#) <!-- Add your YouTube/Demo link here -->

</div>

---

## 🎯 Executive Overview

Security tools today are fundamentally broken: they throw a massive list of alerts at developers, but they don't fix the code, and they don't explain the business risk. 

**ARGUS** is an autonomous DevSecOps intelligence platform. When a Pull Request is opened, 6 specialized AI agents are dispatched in parallel to analyze the code diff. Instead of just flagging errors, ARGUS maps vulnerabilities to historical breaches, calculates financial exposure, simulates a Red Team kill chain, and autonomously writes the patch.

---

## 💻 Interactive Dashboard UI

The engine is deployed with a real-time interactive dashboard. Users can watch the AI agents reason and stream their findings character-by-character via Server-Sent Events (SSE).

<div align="center">
  <a href="#">
    <!-- Replace the src below with your actual uploaded screenshot in the repo -->
    <img src="https://raw.githubusercontent.com/manojmulammagari/argus/main/assets/ui-preview.png" alt="ARGUS Dashboard Preview" width="800" style="border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.2);"/>
  </a>
  <br>
  <i>*Note: The application provides dynamic risk scoring, Breach Oracle correlations, and actionable remediation patches.*</i>
</div>

---

## 📈 The 6 Autonomous Agents

ARGUS is powered by six specialized AI agents running concurrently to provide comprehensive security coverage.

<details>
<summary><b>🔍 Click to view agent breakdowns and capabilities</b></summary>
<br>

| Agent | Role / Capability | 
| :--- | :--- | 
| **AST Sentinel** | Parses the AST and scans against CWE pattern families using regex + LLM validation. | 
| **Policy Guard** | Cross-references every added line against SOC2, HIPAA, and PCI-DSS compliance articles. |
| **Arch Auditor** | Analyzes architectural design flaws and exposed boundaries. | 
| **ThreatMind** | Applies structured STRIDE threat modeling against all modified components. | 
| **Red Team Ω** | *Unique:* Constructs a realistic, step-by-step attacker kill chain from the findings. | 
| **RemedyBot** | Generates concrete before/after code patches to automatically secure the PR. | 

*(Metrics and traces are streamed in real-time, mapping every CWE finding to historical breaches like Equifax 2017).*

</details>

---

## ⚙️ Technical Architecture

This project was built to transition static code analysis into a live, multi-agent AI environment with extreme speed.

<details>
<summary><b>🛠️ Click to view the ARGUS Pipeline</b></summary>
<br>

1. **Concurrent Dispatch:** Built on **FastAPI** using `asyncio.gather` for true parallel agent execution.
2. **LLM Inference:** Powered by **Groq (Llama 3)** for blisteringly fast 300+ token/sec reasoning, with **Google Gemini** integrated as a seamless fallback.
3. **Prompt Injection Protection:** Untrusted PR diffs are strictly truncated and wrapped in `<untrusted_diff>` XML tags so malicious code cannot hijack agent instructions.
4. **Real-Time Streaming:** Server-Sent Events (SSE) push agent thoughts and findings instantly to a Vanilla JS/HTML frontend.
5. **Impact Engines:** Features a **Breach Oracle** to correlate findings with real-world hacks and a **Financial Impact Engine** to convert technical severity into regulatory dollar-exposure estimates.

</details>

---

## 🚀 Quick Start Guide

To run the full ARGUS predictive engine and web application on your local machine:

## 🚀 Quick Start Guide

### 1. Start Infrastructure (PostgreSQL & Redis)
```bash
docker compose up -d

cd backend
pip install -r requirements.txt
# Copy backend/.env.example to backend/.env and populate your keys
uvicorn main_api:app --reload --host 0.0.0.0 --port 8000

cd frontend
npm install
npm run dev
# Dashboard runs at http://localhost:3000

