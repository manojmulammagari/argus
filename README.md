# ARGUS: AI-Powered Multi-Agent DevSecOps

> **Static analysis is dead. Enter ARGUS.**  
> ARGUS orchestrates an autonomous swarm of AI agents to detect, validate, and automatically remediate vulnerabilities, compliance violations, and design flaws in milliseconds—stopping breaches before the code ever merges.

## ⚠️ The Problem: Why Legacy SAST Tools Fail

Traditional SAST (Static Application Security Testing) is broken:
- **Too Slow**: Hours to scan large codebases, breaking CI/CD pipelines.
- **No Context**: 90%+ false positive rates due to lack of architectural understanding.
- **Rules, Not Logic**: Regular expressions can't catch logical flaws, authorization bypasses, or novel attack chains.
- **Dead Ends**: Tools tell you *what* is wrong, but rarely show you exactly *how* to fix it.

## 🛡️ The Solution: ARGUS

ARGUS replaces static rules with **context-aware reasoning**. Using a multi-agent swarm architecture, ARGUS streams security intelligence in real-time, mapping exact compliance violations and actively generating the Pull Request to fix the code.

### 🧠 The ARGUS Swarm (6 Specialized Agents)

1. **🛡️ AST Sentinel (The Parser)**
   Scans raw ASTs and regex patterns, extracting suspicious fragments and validating them against CWE patterns to immediately discard false positives.
   
2. **⚖️ Policy Guard (The Auditor)**
   Cross-references code changes with SOC2, HIPAA, and PCI-DSS requirements, identifying compliance risks like hardcoded secrets, missing encryption, or PHI logging.
   
3. **📐 Arch Auditor (The Architect)**
   Reviews the structural integrity of the application. Detects missing rate-limits, insecure CORS configurations, unauthenticated endpoints, and logical flaws.
   
4. **⚔️ ThreatMind (The Modeler)**
   Applies the STRIDE threat model (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege) to identify exploitable attack vectors.

5. **🔧 RemedyBot (The Fixer)**
   Automatically writes the secure replacement code for every vulnerability discovered and generates a complete Remediation Pull Request for human review.

6. **🎯 Red Team Ω (The Attacker)**
   Takes all discovered vulnerabilities and synthesizes an **Attack Chain Narrative**—a step-by-step breakdown of how a real-world attacker would exploit the exact vulnerabilities found in the scan.

## 🏗️ Architecture

- **Frontend (Next.js 14 App Router)**: 
  A stunning, real-time advanced dashboard. Features live Agent Matrices, animated Risk Gauges, the Breach Oracle (historical mapping), and a step-by-step Kill Chain visualizer.
- **Backend (FastAPI)**:
  High-performance Python backend powered by `asyncio`. Connects to Groq (Llama 3 70B) for lightning-fast, parallelized agent generation. 
- **Real-Time Delivery (SSE)**:
  Memory-safe Server-Sent Events (SSE) with heartbeat mechanisms ensure the UI instantly reflects agent thoughts without web-socket overhead.

## 🔒 Security Highlights

ARGUS doesn't just secure your code—it's built securely itself:
- **Prompt Injection Defense**: All untrusted PR diffs undergo a strict 4-layer sanitization process. We implement hard byte truncation, control character stripping, and malicious pattern neutralization, wrapped in strict XML bounds (`<untrusted_diff>`) to mathematically prevent prompt injection attacks against our agents.
- **Resilient SSE Streaming**: The API incorporates client disconnect detection and periodic heartbeats, preventing zombie generators and keeping proxy connections (like Nginx) alive to avoid silent timeouts.
- **Fail-Safe Orchestration**: Agents are bound by strict `asyncio` timeouts. If a single agent is rate-limited or fails, the pipeline safely recovers and continues delivering partial results without crashing.

## 🚀 Quick Start

### 1. Run the Backend
Ensure you have Python 3.10+ installed. Add your Groq API key to a `.env` file (`GROQ_API_KEY=...`).
```bash
cd backend
pip install fastapi uvicorn groq python-dotenv
python -m uvicorn main_api:app --reload --port 8000
```

### 2. Run the Frontend
```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) and dispatch the ARGUS swarm!