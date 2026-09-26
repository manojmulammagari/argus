"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { useParams, useRouter } from "next/navigation"
import {
  Shield, Scale, Eye, Brain, Wrench, Target,
  AlertTriangle, CheckCircle2, Clock, ArrowLeft,
  ExternalLink, ChevronRight, Activity, Skull,
  FileWarning
} from "lucide-react"

interface Finding {
  id: string
  agent: string
  title: string
  description: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  cwe_id?: string
  location?: string
  line_number?: number
  remediation_hint?: string
  compliance_refs?: string[]
  breach_citation?: { breach: string; year: number; records: string; fine: string }
}

interface ScanMeta {
  id: string
  repo_full_name: string
  pr_number: number
  status: string
  risk_score?: number
  total_findings: number
}

const AGENTS = {
  ast_sentinel: { name: "AST Sentinel", Icon: Shield, color: { ring: "#a855f7", bg: "rgba(168,85,247,0.08)", text: "#c084fc", border: "rgba(168,85,247,0.25)" } },
  policy_guard: { name: "Policy Guard", Icon: Scale, color: { ring: "#3b82f6", bg: "rgba(59,130,246,0.08)", text: "#60a5fa", border: "rgba(59,130,246,0.25)" } },
  arch_auditor: { name: "Arch Auditor", Icon: Eye, color: { ring: "#06b6d4", bg: "rgba(6,182,212,0.08)", text: "#22d3ee", border: "rgba(6,182,212,0.25)" } },
  threat_mind: { name: "ThreatMind", Icon: Brain, color: { ring: "#f59e0b", bg: "rgba(245,158,11,0.08)", text: "#fbbf24", border: "rgba(245,158,11,0.25)" } },
  remedy_bot: { name: "RemedyBot", Icon: Wrench, color: { ring: "#22c55e", bg: "rgba(34,197,94,0.08)", text: "#4ade80", border: "rgba(34,197,94,0.25)" } },
  red_team: { name: "Red Team Ω", Icon: Target, color: { ring: "#ef4444", bg: "rgba(239,68,68,0.08)", text: "#f87171", border: "rgba(239,68,68,0.25)" } },
} as const

const SEVERITY_STYLE: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border border-red-500/25",
  high: "text-orange-400 bg-orange-500/10 border border-orange-500/25",
  medium: "text-amber-400 bg-amber-500/10 border border-amber-500/25",
  low: "text-blue-400 bg-blue-500/10 border border-blue-500/25",
  info: "text-slate-400 bg-slate-500/10 border border-slate-500/25",
}

function RiskGauge({ score }: { score: number | null }) {
  const [displayed, setDisplayed] = useState(0)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (score === null) return
    const start = performance.now()
    const duration = 1800
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplayed(Math.round(eased * score))
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
  }, [score])

  const R = 52
  const C = 2 * Math.PI * R
  const offset = C - (displayed / 100) * C
  const gaugeColor = displayed >= 75 ? "#ef4444" : displayed >= 50 ? "#f97316" : displayed >= 25 ? "#eab308" : "#22c55e"
  const label = displayed >= 75 ? "CRITICAL" : displayed >= 50 ? "HIGH" : displayed >= 25 ? "MEDIUM" : "LOW"

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-32 h-32">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r={R} fill="none" stroke="#1e293b" strokeWidth="10" />
          <circle
            cx="60" cy="60" r={R} fill="none"
            stroke={gaugeColor} strokeWidth="10"
            strokeDasharray={C} strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 0.04s linear, stroke 0.4s" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-black tabular-nums" style={{ color: gaugeColor }}>{displayed}</span>
          <span className="text-[10px] text-slate-500 -mt-0.5">/100</span>
        </div>
      </div>
      {score !== null && (
        <span className="text-[10px] font-bold tracking-widest px-2 py-0.5 rounded-full"
          style={{ color: gaugeColor, backgroundColor: `${gaugeColor}18`, border: `1px solid ${gaugeColor}40` }}>
          {label}
        </span>
      )}
    </div>
  )
}

function AgentCard({ agentKey, traces, status, findingCount }: {
  agentKey: keyof typeof AGENTS; traces: string[]; status: string; findingCount: number
}) {
  const cfg = AGENTS[agentKey]
  const { Icon } = cfg
  const col = cfg.color
  const logRef = useRef<HTMLDivElement>(null)
  const isRunning = status === "running"
  const isDone = status === "complete"
  const isError = status === "error"

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [traces])

  return (
    <div className="rounded-xl overflow-hidden transition-all duration-500"
      style={{
        backgroundColor: "#080f1c",
        border: `1px solid ${isRunning ? col.border : isDone ? "rgba(100,116,139,0.2)" : "rgba(51,65,85,0.3)"}`,
        boxShadow: isRunning ? `0 0 20px ${col.ring}22` : "none",
        opacity: !status && !traces.length ? 0.45 : 1,
      }}>
      {isRunning ? (
        <div className="h-[2px] w-full animate-pulse" style={{ background: `linear-gradient(90deg, transparent, ${col.ring}, transparent)` }} />
      ) : <div className="h-[2px]" />}

      <div className="flex items-center justify-between px-3.5 py-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg" style={{ backgroundColor: col.bg, border: `1px solid ${col.border}` }}>
            <Icon className="w-3.5 h-3.5" style={{ color: col.text }} />
          </div>
          <span className="text-sm font-semibold" style={{ color: col.text }}>{cfg.name}</span>
        </div>
        <div className="flex items-center gap-2">
          {findingCount > 0 && (
            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/20 tabular-nums">
              {findingCount}
            </span>
          )}
          {isRunning && (
            <span className="flex gap-[3px] items-end h-4">
              {[0, 1, 2].map(i => (
                <span key={i} className="w-[3px] rounded-full animate-bounce"
                  style={{ height: `${8 + i * 3}px`, backgroundColor: col.ring, animationDelay: `${i * 120}ms` }} />
              ))}
            </span>
          )}
          {isDone && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />}
          {isError && <AlertTriangle className="w-3.5 h-3.5 text-red-500" />}
          {!status && <Clock className="w-3.5 h-3.5 text-slate-700" />}
        </div>
      </div>

      <div ref={logRef} className="h-28 overflow-y-auto px-3.5 pb-3 space-y-0.5 font-mono text-[10.5px] leading-relaxed scrollbar-none">
        {traces.length === 0 ? (
          <span className="text-slate-700">Waiting to dispatch...</span>
        ) : (
          traces.slice(-30).map((t, i) => <div key={i} className="text-slate-400 break-all">{t}</div>)
        )}
        {isRunning && <span className="inline-block w-1.5 h-3 ml-0.5 rounded-sm animate-pulse" style={{ backgroundColor: col.ring }} />}
      </div>
    </div>
  )
}

function KillChainTimeline({ steps }: { steps: string[] }) {
  const [visibleCount, setVisibleCount] = useState(0)

  useEffect(() => {
    if (!steps.length) return
    setVisibleCount(0)
    let i = 0
    const interval = setInterval(() => {
      i++
      setVisibleCount(i)
      if (i >= steps.length) clearInterval(interval)
    }, 500)
    return () => clearInterval(interval)
  }, [steps])

  const icons = ["🔓", "☁️", "💉", "🎭", "📤", "🦀", "💀"]

  return (
    <div className="space-y-1.5">
      {steps.map((step, i) => (
        <div key={i} className="flex gap-3 transition-all duration-500"
          style={{ opacity: i < visibleCount ? 1 : 0, transform: i < visibleCount ? "translateX(0)" : "translateX(-16px)" }}>
          <div className="flex flex-col items-center flex-shrink-0">
            <div className="w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 border"
              style={{ backgroundColor: "rgba(239,68,68,0.12)", borderColor: "rgba(239,68,68,0.35)" }}>
              <span className="text-[11px]">{icons[i] ?? "⚔️"}</span>
            </div>
            {i < steps.length - 1 && (
              <div className="w-px flex-1 mt-1" style={{ background: "linear-gradient(180deg, rgba(239,68,68,0.3), rgba(239,68,68,0.05))", minHeight: "12px" }} />
            )}
          </div>
          <div className="pb-3 pt-0.5 flex-1">
            <span className="text-[10px] text-red-500/60 font-mono uppercase tracking-wider">Step {i + 1}</span>
            <p className="text-sm text-slate-300 leading-snug mt-0.5">{step}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function ScanPage() {
  const params = useParams()
  const router = useRouter()
  const scanId = params?.id as string | undefined
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

  const [scanMeta, setScanMeta] = useState<ScanMeta | null>(null)
  const [agentTraces, setAgentTraces] = useState<Record<string, string[]>>({})
  const [agentStatuses, setAgentStatuses] = useState<Record<string, string>>({})
  const [findings, setFindings] = useState<Finding[]>([])
  const [killChain, setKillChain] = useState<string[]>([])
  const [riskScore, setRiskScore] = useState<number | null>(null)
  const [scanComplete, setScanComplete] = useState(false)
  const [remediationUrl, setRemediationUrl] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<"agents" | "findings" | "killchain">("agents")
  const [sseError, setSseError] = useState(false)
  const [retryCount, setRetryCount] = useState(0)

  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!scanId) return
    fetch(`${apiBase}/api/scans/${scanId}`).then(r => r.json()).then(setScanMeta).catch(() => {})
  }, [scanId, apiBase])

  const connect = useCallback(() => {
    if (!scanId || scanComplete) return
    setSseError(false)
    const es = new EventSource(`${apiBase}/api/stream/${scanId}`)
    esRef.current = es

    es.onmessage = (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data as string)

        if (data.type === "trace" || data.type === "agent_trace") {
          const agent = (data.agent as string) || "orchestrator"
          const text = (data.text || data.trace || "") as string
          setAgentTraces(prev => ({ ...prev, [agent]: [...(prev[agent] ?? []), text] }))
        }
        if (data.type === "status" || data.type === "agent_status") {
          setAgentStatuses(prev => ({ ...prev, [data.agent]: data.status }))
        }
        if (data.type === "finding") {
          setFindings(prev => [...prev, data.finding as Finding])
        }
        if (data.type === "scan_complete" || data.type === "done") {
          if (data.risk_score !== undefined) setRiskScore(data.risk_score as number)
          if (Array.isArray(data.attack_chain)) setKillChain(data.attack_chain as string[])
          if (data.remediation_pr_url) setRemediationUrl(data.remediation_pr_url as string)
          setScanComplete(true)
          es.close()
        }
        if (data.type === "timeout") {
          setScanComplete(true)
          es.close()
        }
      } catch { /* ignore parse errors */ }
    }

    es.onerror = () => {
      es.close()
      if (!scanComplete) {
        setSseError(true)
        if (retryCount < 3) {
          const delay = Math.pow(2, retryCount) * 1000
          setTimeout(() => { setRetryCount(c => c + 1); connect() }, delay)
        }
      }
    }
    return () => es.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, apiBase, scanComplete, retryCount])

  useEffect(() => {
    const cleanup = connect()
    return () => { esRef.current?.close(); cleanup?.() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  const findingsByAgent = findings.reduce<Record<string, number>>((acc, f) => { acc[f.agent] = (acc[f.agent] ?? 0) + 1; return acc }, {})
  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc }, {})
  const completedAgents = Object.values(agentStatuses).filter(s => s === "complete").length

  return (
    <div className="min-h-screen bg-[#060b14] text-slate-100">
      <header className="sticky top-0 z-50 backdrop-blur" style={{ borderBottom: "1px solid rgba(51,65,85,0.4)", backgroundColor: "rgba(6,11,20,0.92)" }}>
        <div className="max-w-7xl mx-auto px-5 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 min-w-0">
            <button onClick={() => router.push("/")} className="p-1.5 rounded-lg hover:bg-slate-800/60 transition flex-shrink-0">
              <ArrowLeft className="w-4 h-4 text-slate-400" />
            </button>
            <Shield className="w-4 h-4 text-purple-400 flex-shrink-0" />
            <span className="font-black text-sm bg-clip-text text-transparent" style={{ backgroundImage: "linear-gradient(90deg, #a855f7, #22d3ee)" }}>ARGUS</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-700 flex-shrink-0" />
            <span className="text-sm text-slate-400 font-mono truncate">{scanMeta?.repo_full_name ?? "..."}</span>
            <span className="text-xs text-slate-600 flex-shrink-0">PR #{scanMeta?.pr_number}</span>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            {sseError && !scanComplete && <span className="text-xs text-amber-400 flex items-center gap-1.5"><AlertTriangle className="w-3 h-3" /> Reconnecting...</span>}
            {!scanComplete ? (
              <span className="text-xs text-amber-400 flex items-center gap-1.5"><Activity className="w-3 h-3 animate-pulse" /> Scanning...</span>
            ) : (
              <span className="text-xs text-emerald-400 flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5" /> Complete</span>
            )}
            {remediationUrl && (
              <a href={remediationUrl} target="_blank" rel="noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition"
                style={{ backgroundColor: "rgba(34,197,94,0.1)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.25)" }}>
                <ExternalLink className="w-3 h-3" /> Fix PR Ready
              </a>
            )}
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-5 py-6">
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
          <div className="col-span-2 sm:col-span-1 lg:col-span-2 rounded-xl p-4 flex items-center gap-4" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(51,65,85,0.4)" }}>
            <RiskGauge score={riskScore} />
            <div>
              <div className="text-xs text-slate-500 mb-0.5">Risk Score</div>
              <div className="text-[11px] text-slate-400 leading-relaxed">
                {riskScore === null ? "Calculating..." : riskScore >= 75 ? "Immediate action required" : riskScore >= 50 ? "High exposure — fix before merge" : riskScore >= 25 ? "Review recommended" : "Low risk detected"}
              </div>
            </div>
          </div>
          <div className="rounded-xl p-4" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(51,65,85,0.4)" }}>
            <div className="text-xs text-slate-500 mb-1">Findings</div>
            <div className="text-2xl font-black text-slate-200 tabular-nums">{findings.length}</div>
          </div>
          <div className="rounded-xl p-4" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(239,68,68,0.15)" }}>
            <div className="text-xs text-slate-500 mb-1">Critical</div>
            <div className="text-2xl font-black text-red-400 tabular-nums">{severityCounts.critical ?? 0}</div>
          </div>
          <div className="rounded-xl p-4" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(51,65,85,0.4)" }}>
            <div className="text-xs text-slate-500 mb-1">Agents</div>
            <div className="flex items-baseline gap-1"><span className="text-2xl font-black text-purple-400 tabular-nums">{completedAgents}</span><span className="text-slate-600 text-sm">/6</span></div>
          </div>
          <div className="rounded-xl p-4" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(51,65,85,0.4)" }}>
            <div className="text-xs text-slate-500 mb-1">Kill Chain</div>
            <div className="flex items-baseline gap-1"><span className="text-2xl font-black text-red-400 tabular-nums">{killChain.length}</span><span className="text-slate-600 text-sm">steps</span></div>
          </div>
        </div>

        <div className="flex gap-0.5 mb-5 p-1 rounded-xl w-fit" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(51,65,85,0.4)" }}>
          {(["agents", "findings", "killchain"] as const).map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} className="px-4 py-2 text-xs font-semibold rounded-lg transition-all capitalize"
              style={activeTab === tab ? { backgroundColor: "#1e293b", color: "#f1f5f9" } : { color: "#64748b" }}>
              {tab === "killchain" ? "Kill Chain" : tab}
              {tab === "findings" && findings.length > 0 && <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400">{findings.length}</span>}
              {tab === "killchain" && killChain.length > 0 && <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full bg-red-500/20 text-red-400">{killChain.length}</span>}
            </button>
          ))}
        </div>

        {activeTab === "agents" && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(Object.keys(AGENTS) as Array<keyof typeof AGENTS>).map(key => (
              <AgentCard key={key} agentKey={key} traces={agentTraces[key] ?? []} status={agentStatuses[key] ?? ""} findingCount={findingsByAgent[key] ?? 0} />
            ))}
          </div>
        )}

        {activeTab === "findings" && (
          <div className="space-y-3">
            {findings.length === 0 ? (
              <div className="text-center py-20 text-slate-700">
                <FileWarning className="w-8 h-8 mx-auto mb-3 opacity-40" />
                {scanComplete ? "No findings detected." : "Agents are scanning..."}
              </div>
            ) : (
              findings.map(f => (
                <div key={f.id} className="rounded-xl p-4 transition-all hover:border-slate-700/60" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(51,65,85,0.35)" }}>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap mb-2">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${SEVERITY_STYLE[f.severity]}`}>{f.severity}</span>
                        {f.cwe_id && <span className="text-[10px] font-mono text-slate-500 bg-slate-800/80 border border-slate-700/50 px-2 py-0.5 rounded">{f.cwe_id}</span>}
                        <span className="text-[10px] text-slate-600">{f.agent?.replace(/_/g, " ")}</span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200 mb-1">{f.title}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed">{f.description}</p>
                      {f.remediation_hint && (
                        <div className="mt-2.5 p-2.5 rounded-lg" style={{ backgroundColor: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.15)" }}>
                          <p className="text-xs text-emerald-400 font-mono leading-relaxed">🔧 {f.remediation_hint}</p>
                        </div>
                      )}
                      {f.breach_citation && (
                        <div className="mt-2 p-2.5 rounded-lg" style={{ backgroundColor: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.15)" }}>
                          <p className="text-[10px] text-red-400 font-semibold">⚠️ Historical breach: {f.breach_citation.breach} ({f.breach_citation.year})</p>
                          <p className="text-[10px] text-slate-500 mt-0.5">{f.breach_citation.records} · Fine: {f.breach_citation.fine}</p>
                        </div>
                      )}
                      {f.compliance_refs && f.compliance_refs.length > 0 && (
                        <div className="mt-2 flex gap-1 flex-wrap">
                          {f.compliance_refs.map(ref => (
                            <span key={ref} className="text-[10px] px-2 py-0.5 rounded" style={{ color: "#60a5fa", backgroundColor: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.2)" }}>{ref}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    {f.location && (
                      <div className="text-right flex-shrink-0">
                        <div className="text-[11px] font-mono text-slate-500">{f.location}</div>
                        {f.line_number && <div className="text-[10px] text-slate-700">:{f.line_number}</div>}
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === "killchain" && (
          <div className="max-w-2xl">
            {killChain.length === 0 ? (
              <div className="text-center py-20 text-slate-700">
                <Skull className="w-8 h-8 mx-auto mb-3 opacity-40" />
                {scanComplete ? "No kill chain generated." : "Red Team Ω constructing adversarial path..."}
              </div>
            ) : (
              <div className="rounded-xl p-6" style={{ backgroundColor: "#080f1c", border: "1px solid rgba(239,68,68,0.2)" }}>
                <div className="flex items-center gap-2 mb-6">
                  <Target className="w-4 h-4 text-red-400" />
                  <span className="text-sm font-bold text-red-400">Adversarial Kill Chain</span>
                  <span className="ml-auto text-xs text-slate-600">{killChain.length} steps · full compromise</span>
                </div>
                <KillChainTimeline steps={killChain} />
              </div>
            )}
          </div>
        )}
      </div>

      <style>{`.scrollbar-none::-webkit-scrollbar{display:none}`}</style>
    </div>
  )
}
