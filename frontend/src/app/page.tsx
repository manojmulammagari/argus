"use client"

import { useState, useEffect, useMemo, useCallback } from "react"
import { useRouter } from "next/navigation"
import {
  Shield, Scale, Eye, Brain, Wrench, Target,
  ArrowRight, GitPullRequest, Activity,
  AlertTriangle, RefreshCw, Clock, Terminal,
} from "lucide-react"

const AGENTS = [
  { name: "AST Sentinel", icon: Shield, color: "text-purple-400 bg-purple-500/10 border-purple-500/20", desc: "AST & CWE analysis on added lines" },
  { name: "Policy Guard", icon: Scale, color: "text-blue-400 bg-blue-500/10 border-blue-500/20", desc: "SOC2 · HIPAA · PCI-DSS enforcement" },
  { name: "Arch Auditor", icon: Eye, color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20", desc: "Architecture & design flaw auditing" },
  { name: "ThreatMind", icon: Brain, color: "text-amber-400 bg-amber-500/10 border-amber-500/20", desc: "STRIDE threat surface modeling" },
  { name: "RemedyBot", icon: Wrench, color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20", desc: "Unified-diff remediation patches" },
  { name: "Red Team Ω", icon: Target, color: "text-red-400 bg-red-500/10 border-red-500/20", desc: "Adversarial kill-chain simulation" },
]

const EXAMPLES = [
  { repo: "traceloop/openllmetry", pr: 4618 },
  { repo: "OWASP/wrongsecrets", pr: 951 },
]

interface RecentScan {
  id: string
  repo_full_name: string
  pr_number: number
  pr_title?: string | null
  status: string
  risk_score?: number
  total_findings: number
  files_scanned?: number
  remediation_pr_url?: string | null
  created_at?: string
}

function riskBadge(score: number | undefined, status: string) {
  if (status !== "complete") {
    return "text-slate-400 bg-slate-500/10 border-slate-500/25"
  }
  const r = score ?? 0
  if (r >= 65) return "text-rose-400 bg-rose-500/10 border-rose-500/25"
  if (r >= 25) return "text-amber-400 bg-amber-500/10 border-amber-500/25"
  return "text-emerald-400 bg-emerald-500/10 border-emerald-500/25"
}

function verdictBadge(score: number | undefined, status: string) {
  if (status !== "complete") {
    return { label: "SCANNING", cls: "text-slate-400 bg-slate-500/10 border-slate-500/25" }
  }
  const r = score ?? 0
  if (r >= 65) return { label: "CRITICAL RISK", cls: "text-rose-400 bg-rose-500/10 border-rose-500/25" }
  if (r >= 25) return { label: "REVIEW NEEDED", cls: "text-amber-400 bg-amber-500/10 border-amber-500/25" }
  return { label: "SECURITY PASS", cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/25" }
}

export default function Home() {
  const router = useRouter()
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [repoInput, setRepoInput] = useState("")
  const [prInput, setPrInput] = useState("")
  const [recentScans, setRecentScans] = useState<RecentScan[]>([])
  const [recentLoading, setRecentLoading] = useState(false)
  const [health, setHealth] = useState<"checking" | "online" | "offline">("checking")

  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

  /* Backend health dot */
  useEffect(() => {
    let active = true
    setHealth("checking")
    fetch(`${apiBase}/`)
      .then((r) => (r.ok ? "online" : "offline"))
      .catch(() => "offline")
      .then((v) => { if (active) setHealth(v as "online" | "offline") })
    return () => { active = false }
  }, [apiBase])

  const loadRecent = useCallback(() => {
    setRecentLoading(true)
    fetch(`${apiBase}/api/scans?limit=12`)
      .then(res => res.json())
      .then(data => { if (Array.isArray(data)) setRecentScans(data as RecentScan[]) })
      .catch(() => {})
      .finally(() => setRecentLoading(false))
  }, [apiBase])

  useEffect(() => { loadRecent() }, [loadRecent])

  // Collapse duplicate runs of the same PR and hide failed/error runs.
  const recentUnique = useMemo(() => {
    const seen = new Set<string>()
    const out: RecentScan[] = []
    for (const s of [...recentScans].reverse()) {
      const key = `${s.repo_full_name}::${s.pr_number}`
      if (seen.has(key)) continue
      seen.add(key)
      if (s.status === "error" || s.status === "failed") continue
      out.push(s)
    }
    return out.slice(0, 6)
  }, [recentScans])

  const applyExample = (repo: string, pr: number) => {
    setRepoInput(repo)
    setPrInput(String(pr))
    setErrorMessage(null)
  }

  const triggerScan = async () => {
    if (loading) return
    const repo = repoInput.trim()
    const pr = Number(prInput)
    if (!/^[\w.\-]+\/[\w.\-]+$/.test(repo)) {
      setErrorMessage("Enter a GitHub repository in owner/repo format.")
      return
    }
    if (!Number.isInteger(pr) || pr < 1) {
      setErrorMessage("Enter a valid pull request number.")
      return
    }
    setLoading(true)
    setErrorMessage(null)
    try {
      const res = await fetch(`${apiBase}/api/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo,
          repo_full_name: repo,
          pr_number: pr,
          frameworks: ["SOC2", "HIPAA", "PCI-DSS"],
        }),
      })
      if (!res.ok) {
        let detail = `Scan request failed (${res.status})`
        try {
          const errData = await res.json()
          if (errData?.detail) detail = errData.detail
        } catch { /* non-JSON error body */ }
        setErrorMessage(detail)
        setLoading(false)
        return
      }
      const data = await res.json()
      if (data?.scan_id) {
        router.push(`/scan/${data.scan_id}`)
      } else {
        setErrorMessage("Server responded without a valid scan ID")
        setLoading(false)
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to connect to backend server"
      setErrorMessage(msg)
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-[#05070d] text-slate-100 flex flex-col justify-between selection:bg-cyan-500/30">
      {/* ── Compact top navigation ───────────────────────────────────────── */}
      <header className="sticky top-0 z-50 border-b border-slate-800/70 bg-[#05070d]/85 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-purple-500/15 border border-purple-500/30">
              <Shield className="w-4 h-4 text-purple-400" />
            </div>
            <span className="font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-purple-400 via-blue-400 to-cyan-400">
              ARGUS
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-[11px] text-slate-400">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  health === "online" ? "bg-emerald-400 shadow-[0_0_6px_#34d399]"
                  : health === "offline" ? "bg-rose-400"
                  : "bg-slate-500 animate-pulse"
                }`}
              />
              {health === "online" ? "Online · FastAPI + Groq/Gemini"
                : health === "offline" ? "Backend offline"
                : "Connecting…"}
            </span>
            <a
              href={`${apiBase}/docs`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition"
            >
              <Terminal className="w-3.5 h-3.5" /> API Docs
            </a>
          </div>
        </div>
      </header>

      <div className="flex-1 relative">
        <div className="absolute inset-0 bg-[radial-gradient(#141c2e_1px,transparent_1px)] [background-size:16px_16px] opacity-40 pointer-events-none" />

        <div className="max-w-6xl mx-auto px-5 py-12 md:py-16">
          {/* ── Hero ────────────────────────────────────────────────────── */}
          <div className="max-w-3xl mb-8">
            <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-white mb-4 leading-tight">
              Security scanning that{" "}
              <span className="bg-clip-text text-transparent bg-gradient-to-r from-purple-400 via-blue-400 to-emerald-400">
                thinks like an attacker
              </span>{" "}
              and fixes like an engineer.
            </h1>
            <p className="text-slate-400 text-sm sm:text-base max-w-2xl leading-relaxed">
              Six parallel autonomous agents audit any live GitHub pull request — AST analysis,
              compliance policy, architecture review, threat modeling, remediation patches, and
              Red Team kill-chain simulation — in seconds.
            </p>
          </div>

          {/* ── Command bar ─────────────────────────────────────────────── */}
          <div className="w-full max-w-4xl">
            <div className="glass-panel rounded-2xl p-4 md:p-5 shadow-2xl ring-1 ring-slate-800/60">
              <div className="grid grid-cols-1 sm:grid-cols-[1fr_140px_auto] gap-2.5">
                <div className="flex items-center gap-2.5 px-4 bg-slate-950/60 rounded-xl border border-slate-800 focus-within:border-cyan-500/50 transition-colors">
                  <GitPullRequest className="w-4 h-4 text-slate-500 shrink-0" />
                  <input
                    type="text"
                    value={repoInput}
                    onChange={(e) => setRepoInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") triggerScan() }}
                    placeholder="owner/repository"
                    aria-label="GitHub repository"
                    className="bg-transparent text-sm w-full py-3 outline-none text-slate-200 placeholder:text-slate-600 font-mono"
                  />
                </div>
                <div className="flex items-center gap-1.5 px-4 bg-slate-950/60 rounded-xl border border-slate-800 focus-within:border-cyan-500/50 transition-colors">
                  <span className="text-xs text-slate-500 font-mono">PR&nbsp;#</span>
                  <input
                    type="number"
                    value={prInput}
                    onChange={(e) => setPrInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") triggerScan() }}
                    placeholder="4618"
                    aria-label="Pull request number"
                    className="bg-transparent text-sm w-full py-3 outline-none text-slate-200 placeholder:text-slate-600 font-mono"
                  />
                </div>
                <button
                  onClick={triggerScan}
                  disabled={loading}
                  className="shrink-0 px-6 py-3 rounded-xl bg-gradient-to-r from-purple-600 via-blue-600 to-cyan-600 hover:from-purple-500 hover:via-blue-500 hover:to-cyan-500 disabled:opacity-60 transition-all shadow-xl shadow-cyan-900/40 ring-1 ring-cyan-400/30 font-semibold text-sm flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" /> Starting…
                    </>
                  ) : (
                    <>
                      Scan Pull Request <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </div>

              {errorMessage && (
                <div className="mt-3 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2.5">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{errorMessage}</span>
                </div>
              )}

              <div className="mt-3 text-[11px] text-slate-600">
                Try an example:{" "}
                {EXAMPLES.map((ex, i) => (
                  <span key={ex.repo}>
                    {i > 0 && <span className="text-slate-700"> · </span>}
                    <button
                      onClick={() => applyExample(ex.repo, ex.pr)}
                      className="font-mono text-slate-500 hover:text-slate-300 underline decoration-dotted underline-offset-2 transition"
                    >
                      {ex.repo} #{ex.pr}
                    </button>
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* ── Compact agent swarm strip ───────────────────────────────── */}
          <div className="mt-10 w-full">
            <div className="flex items-center gap-3 mb-4">
              <div className="h-px bg-slate-800 flex-1" />
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Autonomous Agent Swarm</span>
              <div className="h-px bg-slate-800 flex-1" />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {AGENTS.map((agent) => {
                const Icon = agent.icon
                return (
                  <div key={agent.name} className="glass-panel p-4 rounded-xl hover:border-cyan-500/50 transition-all">
                    <div className="flex items-center gap-2 mb-2">
                      <div className={`p-1.5 rounded-lg border ${agent.color}`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="font-semibold text-xs text-slate-100">{agent.name}</h3>
                    </div>
                    <p className="text-[10px] text-slate-400 leading-relaxed">{agent.desc}</p>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ── Recent scans ────────────────────────────────────────────── */}
          <div className="mt-10 w-full">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2">
                <Activity className="w-3.5 h-3.5" /> Recent Scans
              </h2>
              <button
                onClick={loadRecent}
                disabled={recentLoading}
                className="text-[11px] text-slate-400 hover:text-white transition flex items-center gap-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${recentLoading ? "animate-spin" : ""}`} /> Refresh
              </button>
            </div>

            {recentUnique.length === 0 ? (
              <div className="glass-panel rounded-xl p-6 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
                <Clock className="w-3.5 h-3.5" />
                No scans yet — scan a pull request above to populate history.
              </div>
            ) : (
              <div className="glass-panel rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="text-[10px] uppercase tracking-wider text-slate-500 border-b border-slate-800/80">
                        <th className="px-3.5 py-2.5 font-semibold">Repo</th>
                        <th className="px-3.5 py-2.5 font-semibold">PR #</th>
                        <th className="px-3.5 py-2.5 font-semibold w-full">PR Title</th>
                        <th className="px-3.5 py-2.5 font-semibold text-right">Findings</th>
                        <th className="px-3.5 py-2.5 font-semibold text-center">Risk Score</th>
                        <th className="px-3.5 py-2.5 font-semibold text-right">Verdict</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentUnique.map((s) => {
                        const risk = riskBadge(s.risk_score, s.status)
                        const verdict = verdictBadge(s.risk_score, s.status)
                        return (
                          <tr
                            key={s.id}
                            onClick={() => router.push(`/scan/${s.id}`)}
                            className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/40 transition cursor-pointer"
                          >
                            <td className="px-3.5 py-3 font-mono text-purple-300 whitespace-nowrap">{s.repo_full_name}</td>
                            <td className="px-3.5 py-3 font-mono text-slate-400 whitespace-nowrap">#{s.pr_number}</td>
                            <td className="px-3.5 py-3 text-slate-300 max-w-[320px] truncate" title={s.pr_title ?? ""}>
                              {s.pr_title || <span className="text-slate-600">—</span>}
                            </td>
                            <td className="px-3.5 py-3 text-right font-mono tabular-nums text-slate-400">{s.total_findings}</td>
                            <td className="px-3.5 py-3 text-center">
                              <span className={`inline-block px-2 py-0.5 rounded border font-mono tabular-nums ${risk}`}>
                                {s.status === "complete" ? `${s.risk_score ?? 0}/100` : "…"}
                              </span>
                            </td>
                            <td className="px-3.5 py-3 text-right">
                              <span className={`inline-block px-2 py-0.5 rounded border text-[10px] font-semibold uppercase tracking-wider ${verdict.cls}`}>
                                {verdict.label}
                              </span>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="border-t border-slate-800/70 bg-[#05070d]/85 backdrop-blur py-5 text-center text-xs text-slate-600">
        ARGUS · Multi-Agent Autonomous DevSecOps Orchestrator
      </footer>
    </main>
  )
}
