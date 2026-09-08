"use client"
/**
 * ARGUS — Live Scan Dashboard
 * File: src/app/scan/[scanId]/page.tsx
 *
 * Features:
 *  • 6 live agent cards with SSE-streaming thought traces
 *  • Animated risk gauge (0→score over 2s)
 *  • Breach Oracle  — maps every finding to a real historical breach + fine
 *  • Financial Impact Engine — GDPR / HIPAA / PCI-DSS $ exposure calculator
 *  • Red Team Omega  — attack chain narrative (unique: no other tool does this)
 *  • Attack chain SVG — visual kill-chain graph
 *  • Auto-generated fix PR link
 */

import { useState, useEffect, useRef, useMemo } from "react"
import { useParams } from "next/navigation"
import {
  Shield, Scale, Eye, Brain, Wrench, Target,
  AlertTriangle, CheckCircle2, Clock, Zap,
  ExternalLink, ChevronRight, DollarSign,
  GitPullRequest, Activity, AlertCircle,
  TrendingUp, Lock, Database, Globe,
} from "lucide-react"

// ─── Constants ────────────────────────────────────────────────────────────────

const AGENT_CONFIG = {
  ast_sentinel: { name: "AST Sentinel",   icon: Shield, color: "purple", desc: "CWE vulnerability scan"    },
  policy_guard: { name: "Policy Guard",   icon: Scale,  color: "blue",   desc: "SOC2 · HIPAA · PCI-DSS"   },
  arch_auditor: { name: "Arch Auditor",   icon: Eye,    color: "cyan",   desc: "Vision diagram analysis"   },
  threat_mind:  { name: "ThreatMind",     icon: Brain,  color: "amber",  desc: "STRIDE threat model"       },
  remedy_bot:   { name: "RemedyBot",      icon: Wrench, color: "green",  desc: "Auto-generates fix PRs"    },
  red_team:     { name: "Red Team Ω",     icon: Target, color: "red",    desc: "Attack chain simulation"   },
} as const

type AgentKey = keyof typeof AGENT_CONFIG

const BREACH_ORACLE: Record<string, { breach: string; year: number; records: string; fine: string }> = {
  "CWE-798": { breach: "Twitch source leak",    year: 2021, records: "125 GB source",   fine: "Reputation destroyed"    },
  "CWE-89":  { breach: "Equifax breach",        year: 2017, records: "147 M records",   fine: "$575 M settlement"       },
  "CWE-532": { breach: "Change Healthcare",     year: 2024, records: "100 M+ patients", fine: "$872 M total cost"       },
  "CWE-79":  { breach: "British Airways",       year: 2018, records: "500 K customers", fine: "£20 M GDPR fine"        },
  "CWE-287": { breach: "Uber data breach",      year: 2022, records: "57 M users",      fine: "$148 M settlement"      },
  "CWE-327": { breach: "LinkedIn breach",       year: 2012, records: "117 M passwords", fine: "$1.25 M settlement"     },
  "CWE-22":  { breach: "SolarWinds attack",     year: 2020, records: "18 K orgs",       fine: "$26 M SEC penalty"      },
  "CWE-200": { breach: "Facebook Cambridge",    year: 2018, records: "87 M profiles",   fine: "$5 B FTC fine"          },
  "CWE-269": { breach: "Colonial Pipeline",     year: 2021, records: "Critical infra",  fine: "$5 M ransom paid"       },
  "CWE-400": { breach: "GitHub DDoS",           year: 2018, records: "Service outage",  fine: "$10 M+ revenue loss"    },
  "HIPAA":   { breach: "Advocate Health",       year: 2013, records: "4 M patients",    fine: "$5.55 M HIPAA fine"     },
  "SOC2":    { breach: "Capital One breach",    year: 2019, records: "106 M customers", fine: "$80 M OCC penalty"      },
  "PCI-DSS": { breach: "TJX Companies",         year: 2007, records: "90 M cards",      fine: "$9.75 M card fines"     },
}

const SEVERITY_CFG = {
  critical: { label: "Critical", text: "text-red-400",    bg: "bg-red-950/60 border-red-500/30",    dot: "bg-red-500"    },
  high:     { label: "High",     text: "text-orange-400", bg: "bg-orange-950/60 border-orange-500/30", dot: "bg-orange-500" },
  medium:   { label: "Medium",   text: "text-yellow-400", bg: "bg-yellow-950/60 border-yellow-500/30", dot: "bg-yellow-500" },
  low:      { label: "Low",      text: "text-blue-400",   bg: "bg-blue-950/60 border-blue-500/30",   dot: "bg-blue-500"   },
  info:     { label: "Info",     text: "text-slate-400",  bg: "bg-slate-900 border-slate-700",       dot: "bg-slate-500"  },
} as const

// ─── Types ────────────────────────────────────────────────────────────────────

type AgentStatus = "idle" | "running" | "complete" | "error"
type Severity    = keyof typeof SEVERITY_CFG

interface Finding {
  id: string; agent: string; title: string; description: string
  severity: Severity; cwe_id?: string; location?: string
  line_number?: number; remediation_hint: string; compliance_refs: string[]
}

interface AgentState {
  status: AgentStatus; traces: string[]; findingCount: number
}

interface ScanComplete {
  risk_score: number; remediation_pr_url?: string
  total_findings: number; severity_breakdown: Partial<Record<Severity, number>>
  attack_chain?: string[]
}

// ─── SSE Hook ─────────────────────────────────────────────────────────────────

function useAgentStream(scanId: string) {
  const [agentStates, setAgentStates] = useState<Record<AgentKey, AgentState>>(
    () => Object.fromEntries(
      Object.keys(AGENT_CONFIG).map(k => [k, { status: "idle", traces: [], findingCount: 0 }])
    ) as Record<AgentKey, AgentState>
  )
  const [findings,     setFindings]     = useState<Finding[]>([])
  const [scanComplete, setScanComplete] = useState<ScanComplete | null>(null)
  const [isStarted,    setIsStarted]    = useState(false)

  useEffect(() => {
    if (!scanId) return
    const apiBase = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
    const es = new EventSource(`${apiBase}/api/stream/${scanId}`)
    setIsStarted(true)

    es.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data)
        switch (ev.type) {
          case "agent_trace":
          case "trace":
            const agentKey = ev.agent as AgentKey
            const traceMsg = ev.trace || ev.text || ""
            setAgentStates(prev => ({
              ...prev,
              [agentKey]: {
                ...prev[agentKey],
                status: "running",
                traces: [...(prev[agentKey]?.traces ?? []).slice(-80), traceMsg],
              },
            }))
            break
          case "agent_status":
          case "status":
            setAgentStates(prev => ({
              ...prev,
              [ev.agent]: { ...prev[ev.agent as AgentKey], status: ev.status },
            }))
            break
          case "finding":
            setFindings(prev => [ev.finding, ...prev])
            setAgentStates(prev => ({
              ...prev,
              [ev.finding.agent]: {
                ...prev[ev.finding.agent as AgentKey],
                findingCount: (prev[ev.finding.agent as AgentKey]?.findingCount ?? 0) + 1,
              },
            }))
            break
          case "scan_complete":
            setScanComplete({
              risk_score:        ev.risk_score,
              remediation_pr_url: ev.remediation_pr_url || ev.summary?.remediation_pr_url,
              total_findings:    ev.total_findings ?? ev.summary?.total_findings ?? 0,
              severity_breakdown: ev.severity_breakdown ?? ev.summary?.severity_breakdown ?? {},
              attack_chain:      ev.attack_chain ?? ev.summary?.attack_chain ?? [],
            })
            es.close()
            break
        }
      } catch { /* ignore malformed */ }
    }
    es.onerror = () => es.close()
    return () => es.close()
  }, [scanId])

  return { agentStates, findings, scanComplete, isStarted }
}

// ─── StatusDot ────────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: AgentStatus }) {
  if (status === "running")
    return (
      <span className="relative flex h-2 w-2">
        <span className="animate-ping absolute h-full w-full rounded-full bg-blue-400 opacity-75" />
        <span className="relative h-2 w-2 rounded-full bg-blue-500" />
      </span>
    )
  const c = { idle: "bg-slate-700", complete: "bg-emerald-500", error: "bg-red-500" }
  return <span className={`h-2 w-2 rounded-full ${c[status]}`} />
}

// ─── AgentCard ────────────────────────────────────────────────────────────────

const AGENT_BORDER: Record<AgentStatus, string> = {
  idle:     "border-slate-800",
  running:  "border-blue-500/50 shadow-[0_0_20px_rgba(59,130,246,0.15)]",
  complete: "border-emerald-500/40",
  error:    "border-red-500/40",
}

const AGENT_COLORS: Record<string, string> = {
  purple: "text-purple-400 bg-purple-500/10",
  blue:   "text-blue-400 bg-blue-500/10",
  cyan:   "text-cyan-400 bg-cyan-500/10",
  amber:  "text-amber-400 bg-amber-500/10",
  green:  "text-emerald-400 bg-emerald-500/10",
  red:    "text-red-400 bg-red-500/10",
}

function AgentCard({ agentKey, state }: { agentKey: AgentKey; state: AgentState }) {
  const cfg    = AGENT_CONFIG[agentKey]
  const Icon   = cfg.icon
  const colors = AGENT_COLORS[cfg.color]
  const traceRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (traceRef.current) traceRef.current.scrollTop = traceRef.current.scrollHeight
  }, [state.traces])

  const isRedTeam = agentKey === "red_team"

  return (
    <div className={`relative rounded-xl border bg-[#0a1120]/90 backdrop-blur-sm p-4 transition-all duration-500 ${AGENT_BORDER[state.status]} ${isRedTeam ? "col-span-2 md:col-span-2" : ""}`}>
      {isRedTeam && state.status === "running" && (
        <div className="absolute inset-0 rounded-xl bg-red-900/10 animate-pulse pointer-events-none" />
      )}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2.5">
          <div className={`p-1.5 rounded-lg ${colors}`}>
            <Icon size={13} />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-100 leading-none">{cfg.name}</p>
            <p className="text-[11px] text-slate-500 mt-0.5">{cfg.desc}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {state.findingCount > 0 && (
            <span className="text-xs px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400 font-mono font-bold">
              {state.findingCount}
            </span>
          )}
          <StatusDot status={state.status} />
        </div>
      </div>

      <div
        ref={traceRef}
        className={`overflow-y-auto font-mono text-[11px] space-y-[2px] scroll-smooth ${isRedTeam ? "h-28" : "h-20"}`}
        style={{ scrollbarWidth: "thin", scrollbarColor: "#334155 transparent" }}
      >
        {state.traces.length === 0 ? (
          <span className="text-slate-700 italic">Awaiting dispatch...</span>
        ) : (
          state.traces.map((t, i) => (
            <div key={i} className={`leading-relaxed break-all ${
              t.startsWith("🚨") || t.startsWith("❌") || t.startsWith("⚠️") || t.startsWith("🚫") ? "text-red-400"
              : t.startsWith("✅") ? "text-emerald-400"
              : t.startsWith("🎯") || t.startsWith("⚔️") ? "text-orange-400"
              : t.startsWith("🔧") || t.startsWith("✍️") || t.startsWith("📋") ? "text-blue-400"
              : "text-slate-400"
            }`}>{t}</div>
          ))
        )}
      </div>
    </div>
  )
}

// ─── Risk Gauge ───────────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number | null }) {
  const [displayScore, setDisplayScore] = useState(0)

  useEffect(() => {
    if (score === null) return
    let start = 0
    const step = score / 60
    const timer = setInterval(() => {
      start += step
      if (start >= score) { setDisplayScore(score); clearInterval(timer) }
      else setDisplayScore(Math.round(start))
    }, 16)
    return () => clearInterval(timer)
  }, [score])

  const R = 54, C = 2 * Math.PI * R
  const s = displayScore
  const arc  = C * 0.75
  const fill = arc * (s / 100)
  const color = s >= 80 ? "#ef4444" : s >= 60 ? "#f97316" : s >= 40 ? "#eab308" : "#22c55e"
  const label = s >= 80 ? "CRITICAL" : s >= 60 ? "HIGH RISK" : s >= 40 ? "MEDIUM" : "LOW RISK"

  return (
    <div className="flex flex-col items-center py-2">
      <svg width="150" height="110" viewBox="0 0 150 110">
        {/* Track */}
        <circle cx="75" cy="90" r={R} fill="none" stroke="#1e293b" strokeWidth="11"
          strokeDasharray={`${arc} ${C - arc}`} strokeLinecap="round"
          transform="rotate(135 75 90)" />
        {/* Fill */}
        <circle cx="75" cy="90" r={R} fill="none" stroke={color} strokeWidth="11"
          strokeDasharray={`${fill} ${C - fill}`} strokeLinecap="round"
          transform="rotate(135 75 90)"
          style={{ transition: "stroke-dasharray 0.1s linear, stroke 1s" }} />
        <text x="75" y="84" textAnchor="middle" fill="white" fontSize="26" fontWeight="800" fontFamily="monospace">
          {score !== null ? s : "—"}
        </text>
        <text x="75" y="100" textAnchor="middle" fill={color} fontSize="8" fontWeight="700" letterSpacing="1">
          {score !== null ? label : "SCANNING"}
        </text>
      </svg>
      <p className="text-[11px] text-slate-500">Risk Score / 100</p>
    </div>
  )
}

// ─── Financial Impact ─────────────────────────────────────────────────────────

function FinancialImpact({ findings }: { findings: Finding[] }) {
  const impact = useMemo(() => {
    const hipaa = findings.filter(f => f.compliance_refs.some(r => r.startsWith("HIPAA"))).length
    const pci   = findings.filter(f => f.compliance_refs.some(r => r.startsWith("PCI"))).length
    const crit  = findings.filter(f => f.severity === "critical").length
    const high  = findings.filter(f => f.severity === "high").length
    return {
      gdpr:  crit > 0 ? 20_000_000 : high > 0 ? 5_000_000 : 0,
      hipaa: hipaa * 50_000 * Math.max(crit, 1),
      pci:   pci * 100_000,
    }
  }, [findings])

  const total = impact.gdpr + impact.hipaa + impact.pci
  const fmt   = (n: number) => n >= 1_000_000 ? `$${(n / 1_000_000).toFixed(1)}M` : n >= 1000 ? `$${(n / 1000).toFixed(0)}K` : `$${n}`

  if (total === 0) return null

  return (
    <div className="rounded-xl border border-red-900/50 bg-red-950/20 p-4">
      <div className="flex items-center gap-2 mb-3">
        <DollarSign size={13} className="text-red-400" />
        <h3 className="text-xs font-bold text-red-400 uppercase tracking-wider">Regulatory Exposure</h3>
      </div>
      <p className="text-3xl font-black text-red-300 font-mono mb-3">{fmt(total)}</p>
      <div className="space-y-1.5">
        {impact.gdpr > 0 && (
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">GDPR (Art. 83)</span>
            <span className="text-red-400 font-mono font-semibold">{fmt(impact.gdpr)}</span>
          </div>
        )}
        {impact.hipaa > 0 && (
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">HIPAA HHS fine</span>
            <span className="text-red-400 font-mono font-semibold">{fmt(impact.hipaa)}</span>
          </div>
        )}
        {impact.pci > 0 && (
          <div className="flex justify-between text-xs">
            <span className="text-slate-400">PCI-DSS penalty</span>
            <span className="text-red-400 font-mono font-semibold">{fmt(impact.pci)}</span>
          </div>
        )}
      </div>
      <p className="text-[10px] text-slate-600 mt-2">*Estimated max exposure per regulation</p>
    </div>
  )
}

// ─── Breach Oracle ────────────────────────────────────────────────────

function BreachOracle({ findings }: { findings: Finding[] }) {
  const matches = useMemo(() => {
    const seen = new Set<string>()
    const out: Array<{ finding: Finding; breach: typeof BREACH_ORACLE[string] }> = []
    for (const f of findings) {
      const key = f.cwe_id ?? f.compliance_refs[0]?.split("-")[0]
      if (!key || seen.has(key)) continue
      const entry = BREACH_ORACLE[key] ?? BREACH_ORACLE[f.compliance_refs[0]?.split("-")[0] ?? ""]
      if (entry) { seen.add(key); out.push({ finding: f, breach: entry }) }
    }
    return out.slice(0, 4)
  }, [findings])

  if (matches.length === 0) return null

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0a1120] p-4">
      <div className="flex items-center gap-2 mb-3">
        <Globe size={13} className="text-amber-400" />
        <h3 className="text-xs font-bold text-amber-400 uppercase tracking-wider">Breach Oracle</h3>
        <span className="text-[10px] text-slate-600 ml-auto">Real-world correlations</span>
      </div>
      <div className="space-y-3">
        {matches.map(({ finding, breach }, i) => (
          <div key={i} className="rounded-lg bg-slate-900/60 border border-slate-800 p-2.5">
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${SEVERITY_CFG[finding.severity].bg} ${SEVERITY_CFG[finding.severity].text}`}>
                {finding.cwe_id ?? finding.compliance_refs[0]?.split("-")[0]}
              </span>
              <span className="text-[10px] text-slate-500">{breach.year}</span>
            </div>
            <p className="text-xs font-semibold text-amber-300">{breach.breach}</p>
            <p className="text-[11px] text-slate-400 mt-0.5">{breach.records} · <span className="text-orange-400">{breach.fine}</span></p>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Finding Card ─────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const cfg = SEVERITY_CFG[finding.severity] ?? SEVERITY_CFG.info

  return (
    <button
      onClick={() => setOpen(!open)}
      className={`w-full text-left rounded-lg border p-3 transition-all duration-200 ${cfg.bg} hover:brightness-110`}
    >
      <div className="flex items-start gap-2">
        <span className={`mt-[5px] flex-shrink-0 h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[11px] font-bold ${cfg.text}`}>{cfg.label.toUpperCase()}</span>
            {finding.cwe_id && <span className="text-[11px] text-slate-500 font-mono">{finding.cwe_id}</span>}
            <span className="text-[10px] text-slate-600 font-mono">{finding.agent}</span>
          </div>
          <p className="text-sm text-slate-200 mt-0.5 leading-snug font-medium">{finding.title}</p>
          {finding.location && (
            <p className="text-[11px] text-slate-500 mt-0.5 font-mono truncate">
              {finding.location}{finding.line_number ? `:${finding.line_number}` : ""}
            </p>
          )}
          {open && (
            <div className="mt-2.5 space-y-2 text-left">
              <p className="text-xs text-slate-400 leading-relaxed">{finding.description}</p>
              <div className="rounded-md bg-emerald-950/50 border border-emerald-900/50 p-2">
                <p className="text-[11px] text-emerald-400 font-semibold mb-1">Remediation →</p>
                <p className="text-xs text-slate-300">{finding.remediation_hint}</p>
              </div>
              {finding.compliance_refs.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {finding.compliance_refs.map(r => (
                    <span key={r} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">{r}</span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
        <ChevronRight size={11} className={`flex-shrink-0 text-slate-600 transition-transform mt-1 ${open ? "rotate-90" : ""}`} />
      </div>
    </button>
  )
}

// ─── Attack Chain SVG ─────────────────────────────────────────────────

function AttackChain({ steps }: { steps: string[] }) {
  if (!steps || steps.length === 0) return null

  return (
    <div className="rounded-xl border border-red-900/40 bg-red-950/10 p-4">
      <div className="flex items-center gap-2 mb-4">
        <Target size={14} className="text-red-400" />
        <h3 className="text-xs font-bold text-red-400 uppercase tracking-wider">Red Team Ω — Kill Chain</h3>
        <span className="ml-auto text-[10px] text-red-700 bg-red-900/30 px-2 py-0.5 rounded-full">SIMULATION</span>
      </div>
      <div className="space-y-2">
        {steps.map((step, i) => (
          <div key={i} className="flex items-start gap-3">
            <div className="flex flex-col items-center flex-shrink-0">
              <div className="h-5 w-5 rounded-full bg-red-900/60 border border-red-700/50 flex items-center justify-center">
                <span className="text-[9px] font-bold text-red-400">{i + 1}</span>
              </div>
              {i < steps.length - 1 && <div className="w-px h-4 bg-red-900/40 mt-0.5" />}
            </div>
            <p className="text-xs text-slate-300 leading-relaxed pt-0.5">{step}</p>
          </div>
        ))}
      </div>
      <div className="mt-3 rounded-lg bg-red-900/30 border border-red-800/50 p-2.5 flex items-center gap-2">
        <AlertTriangle size={12} className="text-red-400 flex-shrink-0" />
        <p className="text-xs text-red-300 font-semibold">Attack path: {steps.length} steps to full compromise</p>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────

export default function ScanPage() {
  const params    = useParams()
  const scanId    = (params?.scanId as string) ?? "demo"
  const { agentStates, findings, scanComplete, isStarted } = useAgentStream(scanId)

  const criticalCount = findings.filter(f => f.severity === "critical").length
  const highCount     = findings.filter(f => f.severity === "high").length
  const agentKeys     = Object.keys(AGENT_CONFIG) as AgentKey[]
  const doneCount     = agentKeys.filter(k => agentStates[k]?.status === "complete").length

  return (
    <div className="min-h-screen bg-[#060b14] text-white antialiased">

      {/* ── Header ── */}
      <div className="sticky top-0 z-20 border-b border-slate-800/80 bg-[#060b14]/95 backdrop-blur">
        <div className="max-w-[1400px] mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-purple-500/15">
                <Shield size={15} className="text-purple-400" />
              </div>
              <span className="font-black text-base tracking-tight text-white">ARGUS</span>
            </div>
            <span className="text-slate-700">/</span>
            <code className="text-xs text-slate-500 font-mono">{scanId.slice(0, 16)}...</code>
          </div>
          <div className="flex items-center gap-4">
            {!scanComplete && isStarted && (
              <div className="flex items-center gap-2 text-xs text-blue-400">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="animate-ping absolute h-full w-full rounded-full bg-blue-400 opacity-75"/>
                  <span className="relative h-1.5 w-1.5 rounded-full bg-blue-500"/>
                </span>
                {doneCount}/{agentKeys.length} agents active
              </div>
            )}
            {scanComplete && (
              <div className="flex items-center gap-2 text-xs text-emerald-400">
                <CheckCircle2 size={12} />
                Scan complete · {scanComplete.total_findings} findings
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div className="max-w-[1400px] mx-auto px-6 py-6 flex gap-6">

        {/* LEFT: Agents + Findings + Attack Chain */}
        <div className="flex-1 min-w-0 space-y-6">

          {/* Agent Cards */}
          <section>
            <div className="flex items-center gap-2 mb-3">
              <Zap size={13} className="text-purple-400" />
              <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Agent Execution</h2>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {agentKeys.map(k => (
                <AgentCard key={k} agentKey={k} state={agentStates[k] ?? { status: "idle", traces: [], findingCount: 0 }} />
              ))}
            </div>
          </section>

          {/* Findings Feed */}
          <section>
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={13} className="text-orange-400" />
              <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Live Findings</h2>
              {findings.length > 0 && (
                <span className="ml-1 text-xs px-1.5 py-0.5 rounded-full bg-orange-500/20 text-orange-400 font-semibold">
                  {findings.length}
                </span>
              )}
            </div>
            {findings.length === 0 ? (
              <div className="rounded-xl border border-slate-800 bg-[#0a1120]/60 p-10 text-center">
                <Clock size={22} className="text-slate-800 mx-auto mb-2" />
                <p className="text-sm text-slate-700">Findings stream here in real time...</p>
              </div>
            ) : (
              <div className="space-y-2">
                {findings.map(f => <FindingCard key={f.id} finding={f} />)}
              </div>
            )}
          </section>

          {/* Attack Chain */}
          {scanComplete?.attack_chain && <AttackChain steps={scanComplete.attack_chain} />}
        </div>

        {/* RIGHT Sidebar */}
        <div className="w-72 flex-shrink-0 space-y-4">

          {/* Risk Score */}
          <div className="rounded-xl border border-slate-800 bg-[#0a1120] p-4">
            <h3 className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-1 text-center">Risk Score</h3>
            <RiskGauge score={scanComplete?.risk_score ?? null} />
            <div className="grid grid-cols-2 gap-2 mt-1">
              <div className="rounded-lg bg-red-950/50 border border-red-900/50 p-2 text-center">
                <p className="text-xl font-black text-red-400">{criticalCount}</p>
                <p className="text-[11px] text-slate-600">Critical</p>
              </div>
              <div className="rounded-lg bg-orange-950/50 border border-orange-900/50 p-2 text-center">
                <p className="text-xl font-black text-orange-400">{highCount}</p>
                <p className="text-[11px] text-slate-600">High</p>
              </div>
            </div>
          </div>

          {/* Financial Impact */}
          <FinancialImpact findings={findings} />

          {/* Fix PR */}
          {scanComplete?.remediation_pr_url && (
            <div className="rounded-xl border border-emerald-900/40 bg-emerald-950/20 p-4">
              <div className="flex items-center gap-2 mb-2">
                <GitPullRequest size={13} className="text-emerald-400" />
                <h3 className="text-xs font-bold text-emerald-400">Fix PR Ready</h3>
              </div>
              <p className="text-xs text-slate-500 mb-3 leading-relaxed">
                ARGUS auto-generated a remediation PR with patches for all critical findings.
              </p>
              <a
                href={scanComplete.remediation_pr_url}
                target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-2 text-xs bg-emerald-500/15 hover:bg-emerald-500/25 transition-colors text-emerald-300 rounded-lg p-2.5 font-semibold"
              >
                <ExternalLink size={11} /> View Remediation PR
              </a>
            </div>
          )}

          {/* Breach Oracle */}
          <BreachOracle findings={findings} />

          {/* Compliance Summary */}
          <div className="rounded-xl border border-slate-800 bg-[#0a1120] p-4">
            <div className="flex items-center gap-2 mb-3">
              <Lock size={13} className="text-blue-400" />
              <h3 className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Compliance</h3>
            </div>
            {["SOC2", "HIPAA", "PCI-DSS"].map(fw => {
              const n = findings.filter(f => f.compliance_refs.some(r => r.startsWith(fw))).length
              return (
                <div key={fw} className="flex items-center justify-between py-2 border-b border-slate-800/60 last:border-0">
                  <span className="text-xs text-slate-400 font-mono">{fw}</span>
                  <span className={`text-xs font-bold ${n > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {n > 0 ? `${n} violation${n > 1 ? "s" : ""}` : "✓ Clean"}
                  </span>
                </div>
              )
            })}
          </div>

          {/* Agent Status Summary */}
          <div className="rounded-xl border border-slate-800 bg-[#0a1120] p-4">
            <div className="flex items-center gap-2 mb-3">
              <Activity size={13} className="text-slate-400" />
              <h3 className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Agent Status</h3>
            </div>
            {agentKeys.map(k => {
              const cfg   = AGENT_CONFIG[k]
              const state = agentStates[k]
              return (
                <div key={k} className="flex items-center gap-2 py-1.5 border-b border-slate-800/60 last:border-0">
                  <StatusDot status={state?.status ?? "idle"} />
                  <span className="text-xs text-slate-400 flex-1">{cfg.name}</span>
                  <span className="text-xs text-slate-600 capitalize">{state?.status ?? "idle"}</span>
                  {(state?.findingCount ?? 0) > 0 && (
                    <span className="text-[11px] text-red-400 font-mono font-bold">{state.findingCount}</span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
