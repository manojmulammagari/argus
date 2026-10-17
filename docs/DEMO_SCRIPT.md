# 🎬 ARGUS: 3-Minute Hackathon Demo Video Script
**Project:** ARGUS — Autonomous DevSecOps Intelligence  
**Format:** 3-Minute Live Screen Recording & Voiceover  
**Pacing:** 130–140 WPM (Punchy, energetic, authoritative Silicon Valley pitch tone)

---

## ✈️ Pre-Flight Recording Checklist

Before hitting **Record**, make sure you have the following ready in your browser & environment:

1. **Browser Tab 1 (Main Stage):** `http://localhost:3000`  
   - Clean homepage loaded.  
   - Input pre-filled or ready to paste: `demo/vulnerable-app`, PR `#42` (or your live demo repository & PR number).
2. **Browser Tab 2 (The Target PR):** GitHub Pull Request page  
   - Showing the code changes with the hardcoded AWS secret key and the command/SQL injection flaw.
3. **Browser Tab 3 (Target Destination / Gist):** GitHub Gist profile  
   - Logged in with the account tied to `GITHUB_TOKEN` so RemedyBot's newly created secret Gist appears immediately upon refresh.
4. **Backend & Services Active:**
   - FastAPI backend running on port 8000 (`uvicorn backend.main_api:app --reload`).
   - Next.js frontend running on port 3000 (`npm run dev`).
   - Environment variables loaded: `GITHUB_TOKEN`, `GROQ_API_KEY`, `GEMINI_API_KEY`.
5. **Display & Audio Setup:**
   - Screen resolution: 1080p (1920×1080) with browser zoom set to 100% or 110% for crisp typography.
   - System notifications & Slack muted ("Do Not Disturb" on).
   - Microphone gain calibrated to avoid clipping during emphatic moments.

---

## 🎙️ 3-Minute Master Demo Script

| Timestamp | Visual (What is on screen) | Audio (What I should say) |
| :--- | :--- | :--- |
| **0:00 - 0:15** | **Camera on Speaker / Split with legacy SAST terminal**<br>Display a chaotic slide or terminal snapshot showing thousands of noisy, unprioritized static analysis alerts. | "Every software engineering team faces the same security nightmare: legacy SAST tools take hours to run, spit out ninety percent false positives, and have zero architectural context. Security teams become blockers, developers tune out the noise, and critical vulnerabilities slip straight into production." |
| **0:15 - 0:30** | **Switch to ARGUS Landing Page (`http://localhost:3000`)**<br>Smooth scroll down past the hero headline to the 6 agent cards: *AST Sentinel, Policy Guard, Arch Auditor, ThreatMind, RemedyBot, Red Team Ω*. Hover over the badges. | "Meet **ARGUS** — Autonomous DevSecOps Intelligence. Instead of dumb regex scanners, ARGUS deploys a coordinated swarm of six specialized AI agents that reason about your code in real time, quantify the financial breach exposure, and autonomously write the fix." |
| **0:30 - 0:55** | **Show Home Input & Trigger Scan**<br>Zoom into the repository input card. Enter `demo/vulnerable-app` and PR `#42` (containing a hardcoded AWS key and command injection). Click the glowing **'Start ARGUS Scan'** button. Instant transition to `/scan/[id]`. | "Let’s watch it work live on an incoming pull request containing a hardcoded AWS secret key and an unsanitized command injection flaw. I click **Start ARGUS Scan** — and the autonomous intelligence engine takes over." |
| **0:55 - 1:30** | **Live Scan Stream (`/scan/[id]`)**<br>Agent cards begin pulsing with active gradient borders. Live log traces stream into the card terminals via SSE (Server-Sent Events). Focus on AST Sentinel and ThreatMind logs filling in real time. | "Notice that instantaneous Server-Sent Events stream. Under the hood, FastAPI orchestrates four primary analysis agents — **AST Sentinel**, **Policy Guard**, **Arch Auditor**, and **ThreatMind** — executing in parallel using Python `asyncio`. Every agent is wrapped in strict ninety-second timeout guards, guaranteeing our CI/CD pipeline never hangs on slow upstream calls." |
| **1:30 - 1:55** | **Risk Gauge & Breach Oracle**<br>Point to the circular SVG **Risk Gauge** animating up to **85/100 (CRITICAL)**. Click over to the **Findings** tab. Expand the code injection finding and highlight the **Historical Breach Citation** box. | "Within seconds, the swarm achieves consensus. The Risk Gauge jumps to eighty-five out of one hundred — Critical. But developers don’t speak abstract CVSS scores, and executives don't speak CWEs. That's why ARGUS features the **Breach Oracle**. It maps technical flaws directly to historical enterprise disasters — showing leadership that this exact CWE caused the 2017 Equifax breach, compromising 147 million records and triggering a 575-million-dollar penalty." |
| **1:55 - 2:15** | **Red Team Ω Kill Chain**<br>Click the **Kill Chain** tab. Step-by-step adversarial progression animates sequentially on screen (🔓 Credential Harvest → ☁️ IAM Enumeration → 💉 Command Injection → 💀 Full DB Exfiltration). | "Now, look at **Red Team Ω**. Instead of disconnected warnings, it dynamically chains the vulnerabilities into a step-by-step adversarial attack path. It demonstrates to engineering leads precisely how an external attacker exploits the leaked key to escalate privileges and exfiltrate production data." |
| **2:15 - 2:45** | **RemedyBot & The GitHub Gist**<br>Scan completes. The top-right status displays a green checkmark. Click the glowing **'Fix PR Ready'** button. Switch to the newly opened tab displaying the private **GitHub Gist**. | "Here is the mic drop. Flagging vulnerabilities is useless if your backlog just keeps growing. ARGUS doesn't leave you with generic advice. **RemedyBot** analyzes the AST, generates a production-ready unified diff, and commits a private GitHub Gist containing the exact patch. One click, ready to review and merge." |
| **2:45 - 3:00** | **Enterprise Hardening & Outro**<br>Quick transition to presentation slide or code inspection highlighting the `<untrusted_diff>` XML boundary sanitation wrapper. Return to speaker/homepage. | "Best of all, ARGUS is secure by design: untrusted diffs are isolated inside strict `<untrusted_diff>` XML boundaries to neutralize prompt injections before any LLM touches the code. That’s ARGUS: DevSecOps intelligence that thinks like an attacker and fixes like an engineer. Thank you!" |

---

## 💡 Pitch Coaching Tips for the Speaker

* **Confidence & Energy:** Start with a high-energy delivery on the hook. You are pitching a breakthrough that replaces legacy dinosaurs like SonarQube and Checkmarx.
* **Synchronized Clicks:** Don't talk ahead of the screen. Wait for the tab click on *Kill Chain* or *Fix PR Ready* right as you deliver the corresponding punchline.
* **The "Equifax" Number:** Hit the "$575 million penalty" with vocal emphasis; judges remember concrete dollar amounts far better than CWE numbers.
* **No Apologies:** If an LLM call takes 2 extra seconds, lean into it: *"Notice the deep contextual reasoning streaming in..."*
