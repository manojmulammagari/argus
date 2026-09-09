"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import {
  Shield, Scale, Eye, Brain, Wrench, Target,
  Play, ArrowRight, GitPullRequest, Activity,
  CheckCircle2, AlertTriangle, Lock, Terminal
} from "lucide-react"

const AGENTS = [
  { name: "AST Sentinel", icon: Shield, color: "text-purple-400 bg-purple-500/10 border-purple-500/20", desc: "CWE regex heuristics + Groq Llama-3.3 semantic validation" },
  { name: "Policy Guard", icon: Scale, color: "text-blue-400 bg-blue-500/10 border-blue-500/20", desc: "SOC2, HIPAA, PCI-DSS compliance enforcement" },
  { name: "Arch Auditor", icon: Eye, color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20", desc: "Gemini Vision architecture threat modeling" },
  { name: "ThreatMind", icon: Brain, color: "text-amber-400 bg-amber-500/10 border-amber-500/20", desc: "Autonomous STRIDE threat surface generation" },
  { name: "RemedyBot", icon: Wrench, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", desc: "Auto-generates and commits validated fix PRs" },
  { name: "Red Team Ω", icon: Target, color: "text-red-400 bg-red-500/10 border-red-500/20", desc: "Adversarial kill-chain simulation and impact path" },
]

export default function Home() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [repoInput, setRepoInput] = useState("demo/vulnerable-app")
  const [prNumber, setPrNumber] = useState(42)
  const [recentScans, setRecentScans] = useState<any[]>([])

  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

  useEffect(() => {
    fetch(`${apiBase}/api/scans?limit=5`)
      .then(res => res.json())
      .then(data => { if (Array.isArray(data)) setRecentScans(data) })
      .catch(() => {})
  }, [apiBase])

  const triggerScan = async () => {
    setLoading(true)
    try {
      const res = await fetch(`${apiBase}/api/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_full_name: repoInput,
          pr_number: Number(prNumber) || 42,
          frameworks: ["SOC2", "HIPAA", "PCI-DSS"]
        })
      })
      const data = await res.json()
      if (data?.scan_id) {
        router.push(`/scan/${data.scan_id}`)
      }
    } catch (e) {
      console.error(e)
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-[#060b14] text-slate-100 flex flex-col justify-between">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-[#060b14]/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-purple-500/15 border border-purple-500/30">
              <Shield className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <span className="font-black text-lg tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-purple-400 via-blue-400 to-cyan-400">
                ARGUS
              </span>
              <span className="text-[10px] ml-2 px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                v1.0.0
              </span>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <a
              href="http://localhost:8000"
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-white transition flex items-center gap-1.5"
            >
              <Terminal className="w-3.5 h-3.5" /> API Docs & Demo UI
            </a>
            <button
              onClick={triggerScan}
              disabled={loading}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 transition shadow-lg shadow-purple-900/30 flex items-center gap-2"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {loading ? "Launching..." : "Launch Live Demo"}
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <div className="max-w-7xl mx-auto px-6 py-16 flex-1 flex flex-col justify-center items-center text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium mb-6">
          <Activity className="w-3.5 h-3.5" />
          Autonomous Multi-Agent DevSecOps Intelligence
        </div>
        <h1 className="text-4xl sm:text-6xl font-black tracking-tight max-w-4xl leading-[1.1] mb-6">
          Security scanning that <span className="bg-clip-text text-transparent bg-gradient-to-r from-purple-400 via-blue-400 to-emerald-400">thinks like an attacker</span> and fixes like an engineer.
        </h1>
        <p className="text-slate-400 text-base sm:text-lg max-w-2xl mb-10 leading-relaxed">
          ARGUS orchestrates 6 parallel autonomous AI agents across AST analysis, compliance policies, visual architecture auditing, STRIDE threat models, remediation PR generation, and Red Team kill-chain simulations.
        </p>

        {/* Scan Input Card */}
        <div className="w-full max-w-2xl bg-[#0a1120] border border-slate-800 p-3 rounded-2xl shadow-2xl flex flex-col sm:flex-row gap-3">
          <div className="flex-1 flex items-center gap-2 px-3 bg-slate-900/80 rounded-xl border border-slate-800">
            <GitPullRequest className="w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
              placeholder="github-owner/repository"
              className="bg-transparent text-sm w-full py-2.5 outline-none text-slate-200 placeholder:text-slate-600 font-mono"
            />
          </div>
          <div className="w-28 flex items-center gap-1.5 px-3 bg-slate-900/80 rounded-xl border border-slate-800">
            <span className="text-xs text-slate-500 font-mono">PR #</span>
            <input
              type="number"
              value={prNumber}
              onChange={(e) => setPrNumber(Number(e.target.value))}
              className="bg-transparent text-sm w-full py-2.5 outline-none text-slate-200 font-mono"
            />
          </div>
          <button
            onClick={triggerScan}
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-gradient-to-r from-purple-600 via-blue-600 to-cyan-600 hover:opacity-90 transition font-semibold text-sm flex items-center justify-center gap-2 flex-shrink-0"
          >
            {loading ? "Starting..." : "Start ARGUS Scan"}
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        {/* 6 AI Agents Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-20 w-full text-left">
          {AGENTS.map((agent) => {
            const Icon = agent.icon
            return (
              <div
                key={agent.name}
                className="bg-[#0a1120]/80 border border-slate-800/80 p-5 rounded-xl hover:border-slate-700 transition"
              >
                <div className="flex items-center gap-3 mb-2.5">
                  <div className={`p-2 rounded-lg border ${agent.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <h3 className="font-semibold text-sm text-slate-100">{agent.name}</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">{agent.desc}</p>
              </div>
            )
          })}
        </div>

        {/* Recent Scans (if any) */}
        {recentScans.length > 0 && (
          <div className="mt-16 w-full text-left">
            <h2 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Recent Scans</h2>
            <div className="space-y-2">
              {recentScans.map((s) => (
                <div
                  key={s.id}
                  onClick={() => router.push(`/scan/${s.id}`)}
                  className="bg-[#0a1120] border border-slate-800/80 hover:border-slate-700 p-3 rounded-xl flex items-center justify-between cursor-pointer transition"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-purple-400">{s.repo}</span>
                    <span className="text-xs text-slate-600">PR #{s.pr_number}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-xs text-slate-400 font-mono">Risk: {s.risk_score ?? "—"}/100</span>
                    <span className="text-xs text-slate-500">{s.total_findings} findings</span>
                    <span className="text-xs capitalize px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {s.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-6 text-center text-xs text-slate-600">
        ARGUS Enterprise Security Architecture · Multi-Agent Autonomous CI/CD Orchestrator
      </footer>
    </main>
  )
}
