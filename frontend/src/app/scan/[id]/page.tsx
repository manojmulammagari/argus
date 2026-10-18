"use client"

import { useState, useEffect, useRef, useCallback, useMemo } from "react"
import type { ReactNode } from "react"
import { useParams, useRouter } from "next/navigation"
import {
  Shield, Scale, Eye, Brain, Wrench, Target,
  AlertTriangle, CheckCircle2, Clock, ArrowLeft,
  ExternalLink, ChevronRight, Activity, Skull,
  Zap, Copy, FileCode2, ShieldCheck, X, GitPullRequest,
} from "lucide-react"

/* ────────────────────────────────────────────────────────────────────────────
 * Contracts
 * ────────────────────────────────────────────────────────────────────────── */
interface Finding {
  id: string
  agent: string
  title: string
  description: string
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string
  cwe_id?: string | null
  file_path?: string | null
  line_number?: number | null
  remediation?: string | null
  compliance_refs?: string[]
  breach_citation?: { breach: string; year: number; records: string; fine: string } | null
  advisory?: boolean
}

interface BreachCard {
  cwe_id: string
  breach: string
  year: number
  records: string
  fine: string
}

interface ConsensusData {
  agents_total?: number
  agents_completed?: number
  agents_failed?: number
  agents_flagged?: number
  consensus_ratio?: string
  completed_agents?: string[]
  failed_agents?: string[]
  is_degraded?: boolean
  corroborated?: boolean
  advisory_only?: boolean
}

interface ScanMeta {
  id: string
  repo_full_name: string
  pr_number: number
  pr_title?: string | null
  pr_state?: string | null
  pr_author?: string | null
  pr_url?: string | null
  status: string
  verdict?: string | null
  scan_status?: string | null
  risk_score?: number
  total_findings: number
  files_scanned?: number
  files?: string[]
  findings?: Finding[]
  breach_oracle?: BreachCard[]
  remediation_pr_url?: string | null
  patch_preview?: string | null
  attack_chain?: string[]
  severity_breakdown?: Record<string, number>
  failed_agents?: string[]
  completed_agents?: string[]
  agent_errors?: Record<string, string>
  consensus?: ConsensusData
  error?: string | null
  created_at?: string
}

interface PrContext {
  title?: string | null
  state?: string | null
  author?: string | null
  url?: string | null
  repo?: string | null
  pr_number?: number | null
}

const AGENTS = {
  ast_sentinel: { name: "AST Sentinel", Icon: Shield, role: "AST & CWE analysis", text: "#c084fc", bg: "rgba(168,85,247,0.08)", border: "rgba(168,85,247,0.25)" },
  policy_guard: { name: "Policy Guard", Icon: Scale, role: "SOC2 · HIPAA · PCI-DSS", text: "#60a5fa", bg: "rgba(59,130,246,0.08)", border: "rgba(59,130,246,0.25)" },
  arch_auditor: { name: "Arch Auditor", Icon: Eye, role: "Architecture & design", text: "#22d3ee", bg: "rgba(6,182,212,0.08)", border: "rgba(6,182,212,0.25)" },
  threat_mind: { name: "ThreatMind", Icon: Brain, role: "STRIDE threat modeling", text: "#fbbf24", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.25)" },
  remedy_bot: { name: "RemedyBot", Icon: Wrench, role: "Remediation patches", text: "#4ade80", bg: "rgba(34,197,94,0.08)", border: "rgba(34,197,94,0.25)" },
  red_team: { name: "Red Team Ω", Icon: Target, role: "Adversarial kill chain", text: "#f87171", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.25)" },
} as const

type AgentKey = keyof typeof AGENTS

const AGENT_KEY_BY_LABEL: Record<string, AgentKey> = {
  "AST Sentinel": "ast_sentinel",
  "Policy Guard": "policy_guard",
  "Arch Auditor": "arch_auditor",
  "ThreatMind": "threat_mind",
  "RemedyBot": "remedy_bot",
  "Red Team Ω": "red_team",
}

const SEVERITY_STYLE: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border border-red-500/25",
  HIGH: "text-orange-400 bg-orange-500/10 border border-orange-500/25",
  MEDIUM: "text-amber-400 bg-amber-500/10 border border-amber-500/25",
  LOW: "text-blue-400 bg-blue-500/10 border border-blue-500/25",
}

const TONE = {
  emerald: { text: "#4ade80", bg: "rgba(34,197,94,0.12)", border: "rgba(34,197,94,0.35)" },
  amber: { text: "#fbbf24", bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.35)" },
  rose: { text: "#f87171", bg: "rgba(248,113,113,0.12)", border: "rgba(248,113,113,0.35)" },
}

/* ────────────────────────────────────────────────────────────────────────────
 * Helpers
 * ────────────────────────────────────────────────────────────────────────── */
function formatElapsed(ms: number) {
  const total = Math.max(0, ms)
  const m = Math.floor(total / 60000)
  const s = Math.floor((total % 60000) / 1000)
  const t = Math.floor((total % 1000) / 100)
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}.${t}s`
}

/** Defensive clean-up: never render raw JSON fragments in the thought stream. */
function isNoisyTrace(text: string) {
  const t = text.trim()
  if (!t) return true
  if (t.startsWith("{") || t.startsWith("[") || t.startsWith('"')) return true
  return /^["']?[\w-]+["']?\s*:/.test(t) && /["{},[\]]/.test(t)
}

function verdictFor(
  risk: number | null,
  complete: boolean,
  serverVerdict?: string | null,
  scanStatus?: string | null,
  failedCount = 0
) {
  if (!complete) return { label: "SCANNING", tone: "amber" as const }

  if (serverVerdict) {
    if (serverVerdict === "SCAN INCOMPLETE / ANALYSIS FAILED" || serverVerdict === "SCAN ERROR") {
      return { label: serverVerdict, tone: "rose" as const }
    }
    if (serverVerdict === "SCAN DEGRADED") {
      return { label: "SCAN DEGRADED", tone: "amber" as const }
    }
    if (serverVerdict === "CRITICAL VULNERABILITIES FOUND") {
      return { label: serverVerdict, tone: "rose" as const }
    }
    if (serverVerdict === "SECURITY REVIEW ADVISED") {
      return { label: serverVerdict, tone: "amber" as const }
    }
    if (serverVerdict === "SECURITY CHECK PASSED") {
      if (failedCount > 0 || scanStatus === "degraded" || scanStatus === "error") {
        return { label: "SCAN DEGRADED", tone: "amber" as const }
      }
      return { label: "SECURITY CHECK PASSED", tone: "emerald" as const }
    }
  }

  if (failedCount > 0 || scanStatus === "degraded" || scanStatus === "error") {
    return { label: "SCAN DEGRADED", tone: "amber" as const }
  }
  const r = risk ?? 0
  if (r >= 65) return { label: "CRITICAL VULNERABILITIES FOUND", tone: "rose" as const }
  if (r >= 25) return { label: "SECURITY REVIEW ADVISED", tone: "amber" as const }
  return { label: "SECURITY CHECK PASSED", tone: "emerald" as const }
}

function githubStateBadge(state?: string | null) {
  const s = (state || "").trim().toUpperCase()
  if (s === "MERGED") return { label: "MERGED PR", cls: "text-purple-300 bg-purple-500/10 border-purple-500/30" }
  if (s === "CLOSED") return { label: "CLOSED PR", cls: "text-rose-300 bg-rose-500/10 border-rose-500/30" }
  if (s === "OPEN") return { label: "OPEN PR", cls: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30" }
  return null
}

/* ────────────────────────────────────────────────────────────────────────────
 * Compact risk gauge (64×64 for the KPI strip)
 * ────────────────────────────────────────────────────────────────────────── */
function MiniGauge({ score }: { score: number | null }) {
  const [displayed, setDisplayed] = useState(0)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (score === null) return
    const start = performance.now()
    const duration = 900
    const from = displayed
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplayed(Math.round(from + eased * (score - from)))
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [score])

  const R = 26
  const C = 2 * Math.PI * R
  const offset = C - (displayed / 100) * C
  const color = displayed >= 65 ? "#ef4444" : displayed >= 25 ? "#f59e0b" : "#22c55e"

  return (
    <div className="relative w-16 h-16 shrink-0">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 64 64">
        <circle cx="32" cy="32" r={R} fill="none" stroke="#16213a" strokeWidth="7" />
        <circle
          cx="32" cy="32" r={R} fill="none"
          stroke={color} strokeWidth="7"
          strokeDasharray={C} strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-lg font-black tabular-nums" style={{ color }}>{displayed}</span>
      </div>
    </div>
  )
}

/* ────────────────────────────────────────────────────────────────────────────
 * KPI card
 * ────────────────────────────────────────────────────────────────────────── */
function Kpi({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="glass-panel rounded-xl p-4 flex flex-col justify-between gap-2 min-h-[96px]">
      <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">{label}</span>
      <div>{children}</div>
      {hint && <div className="text-[10px] text-slate-500 leading-tight">{hint}</div>}
    </div>
  )
}

/* ────────────────────────────────────────────────────────────────────────────
 * Agent live-status card (3-line scrollable mono box)
 * ────────────────────────────────────────────────────────────────────────── */
function AgentCard({ agentKey, traces, status, findingCount, errorMessage }: {
  agentKey: AgentKey; traces: string[]; status: string; findingCount: number; errorMessage?: string
}) {
  const cfg = AGENTS[agentKey]
  const { Icon } = cfg
  const logRef = useRef<HTMLDivElement>(null)

  const clean = useMemo(() => traces.filter(t => !isNoisyTrace(t)), [traces])

  useEffect(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [clean, errorMessage])

  const isError = status === "error" || status === "failed"

  const state =
    isError ? { label: "FAILED", cls: "text-red-400 bg-red-500/15 border-red-500/40", pulse: false }
    : status === "running" ? { label: "SCANNING", cls: "text-cyan-300 bg-cyan-500/10 border-cyan-500/30", pulse: true }
    : status === "complete" && findingCount > 0 ? { label: "FLAGGED", cls: "text-rose-300 bg-rose-500/10 border-rose-500/30", pulse: false }
    : status === "complete" ? { label: "CLEAN", cls: "text-emerald-300 bg-emerald-500/10 border-emerald-500/30", pulse: false }
    : { label: "IDLE", cls: "text-slate-500 bg-slate-500/10 border-slate-500/25", pulse: false }

  return (
    <div
      className={`glass-panel rounded-xl p-3.5 transition-all ${
        isError ? "border-red-500/40 bg-red-950/20 shadow-lg shadow-red-950/30" : ""
      }`}
      style={{
        borderColor: isError ? "rgba(239,68,68,0.45)" : status === "running" ? cfg.border : undefined,
        backgroundColor: isError ? "rgba(239,68,68,0.06)" : undefined,
      }}
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <div
            className="p-1.5 rounded-lg shrink-0"
            style={{
              backgroundColor: isError ? "rgba(239,68,68,0.15)" : cfg.bg,
              border: `1px solid ${isError ? "rgba(239,68,68,0.35)" : cfg.border}`,
            }}
          >
            <Icon className="w-3.5 h-3.5" style={{ color: isError ? "#f87171" : cfg.text }} />
          </div>
          <div className="min-w-0">
            <div className="text-xs font-semibold leading-tight truncate" style={{ color: isError ? "#f87171" : cfg.text }}>
              {cfg.name}
            </div>
            <div className="text-[9px] text-slate-500 truncate">{cfg.role}</div>
          </div>
        </div>
        <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full border flex items-center gap-1 shrink-0 ${state.cls}`}>
          {state.pulse && <span className="w-1 h-1 rounded-full bg-current animate-ping" />}
          {state.label}
        </span>
      </div>
      <div
        ref={logRef}
        role="log"
        aria-live="polite"
        aria-label={`${cfg.name} live status`}
        className={`h-[54px] overflow-y-auto rounded-lg px-2.5 py-1.5 space-y-0.5 text-xs font-mono leading-[18px] ${
          isError
            ? "bg-red-950/40 border border-red-500/30 text-red-300"
            : "bg-slate-950/60 border border-slate-800/60 text-slate-300"
        }`}
      >
        {isError && errorMessage ? (
          <div className="text-red-400 font-medium truncate" title={errorMessage}>
            ⚠ {errorMessage}
          </div>
        ) : clean.length === 0 ? (
          <div className={isError ? "text-red-400" : "text-slate-600"}>
            {isError ? "Execution halted — engine failure" : "Waiting to dispatch…"}
          </div>
        ) : null}
        {clean.slice(-10).map((t, i) => (
          <div key={i} className={`truncate ${isError && i === clean.length - 1 ? "text-red-400 font-medium" : ""}`}>
            {t}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ────────────────────────────────────────────────────────────────────────────
 * Red Team Ω — connected vertical numbered steps
 * ────────────────────────────────────────────────────────────────────────── */
function KillChain({ steps }: { steps: string[] }) {
  return (
    <div>
      {steps.map((step, i) => (
        <div key={i} className="flex gap-2.5">
          <div className="flex flex-col items-center shrink-0">
            <div className="w-5 h-5 rounded-full bg-red-500/15 border border-red-500/40 text-red-300 text-[10px] font-bold flex items-center justify-center">
              {i + 1}
            </div>
            {i < steps.length - 1 && <div className="w-px flex-1 bg-red-500/25 my-1" />}
          </div>
          <p className="text-xs text-slate-300 leading-snug pb-3">{step}</p>
        </div>
      ))}
    </div>
  )
}

/* ────────────────────────────────────────────────────────────────────────────
 * Page
 * ────────────────────────────────────────────────────────────────────────── */
export default function ScanPage() {
  const params = useParams()
  const router = useRouter()
  const scanId = params?.id as string | undefined
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

  const [scanMeta, setScanMeta] = useState<ScanMeta | null>(null)
  const [prContext, setPrContext] = useState<PrContext>({})
  const [agentTraces, setAgentTraces] = useState<Record<string, string[]>>({})
  const [agentStatuses, setAgentStatuses] = useState<Record<string, string>>({})
  const [findings, setFindings] = useState<Finding[]>([])
  const [killChain, setKillChain] = useState<string[]>([])
  const [riskScore, setRiskScore] = useState<number | null>(null)
  const [scanComplete, setScanComplete] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)
  const [remediationUrl, setRemediationUrl] = useState<string | null>(null)
  const [patchPreview, setPatchPreview] = useState<string | null>(null)
  const [filesScanned, setFilesScanned] = useState<number | null>(null)
  const [scannedFiles, setScannedFiles] = useState<string[]>([])
  const [breachOracle, setBreachOracle] = useState<BreachCard[]>([])
  const [showPatchModal, setShowPatchModal] = useState(false)
  const [scanNotFound, setScanNotFound] = useState(false)
  const [startTime] = useState(() => Date.now())
  const [now, setNow] = useState(() => Date.now())
  const [frozenMs, setFrozenMs] = useState<number | null>(null)

  // Fail-closed resilience and swarm tracking state
  const [verdict, setVerdict] = useState<string | null>(null)
  const [scanStatus, setScanStatus] = useState<string | null>(null)
  const [failedAgents, setFailedAgents] = useState<string[]>([])
  const [completedAgents, setCompletedAgents] = useState<string[]>([])
  const [agentErrors, setAgentErrors] = useState<Record<string, string>>({})
  const [consensusData, setConsensusData] = useState<ConsensusData | null>(null)

  const esRef = useRef<EventSource | null>(null)
  const scanCompleteRef = useRef(false)

  useEffect(() => { scanCompleteRef.current = scanComplete }, [scanComplete])

  /* Live elapsed timer */
  useEffect(() => {
    if (scanComplete) return
    const id = setInterval(() => setNow(Date.now()), 100)
    return () => clearInterval(id)
  }, [scanComplete])

  useEffect(() => {
    if (scanComplete && frozenMs === null) setFrozenMs(Date.now() - startTime)
  }, [scanComplete, frozenMs, startTime])

  const elapsedMs = frozenMs ?? (now - startTime)

  /* Apply an authoritative scan_complete payload */
  const applySummary = useCallback((data: Record<string, unknown>) => {
    if (typeof data.error === "string" && data.error) setScanError(data.error)
    if (typeof data.risk_score === "number") setRiskScore(data.risk_score)
    if (typeof data.verdict === "string") setVerdict(data.verdict)
    if (typeof data.scan_status === "string") setScanStatus(data.scan_status)
    if (Array.isArray(data.failed_agents)) setFailedAgents(data.failed_agents as string[])
    if (Array.isArray(data.completed_agents)) setCompletedAgents(data.completed_agents as string[])
    if (data.agent_errors && typeof data.agent_errors === "object") {
      setAgentErrors(data.agent_errors as Record<string, string>)
    }
    if (data.consensus && typeof data.consensus === "object") {
      setConsensusData(data.consensus as ConsensusData)
    }
    if (Array.isArray(data.attack_chain)) setKillChain(data.attack_chain as string[])
    if (typeof data.remediation_pr_url === "string") setRemediationUrl(data.remediation_pr_url)
    if (typeof data.patch_preview === "string") setPatchPreview(data.patch_preview)
    if (typeof data.files_scanned === "number") setFilesScanned(data.files_scanned)
    if (Array.isArray(data.files)) setScannedFiles(data.files as string[])
    if (Array.isArray(data.breach_oracle)) setBreachOracle(data.breach_oracle as BreachCard[])
    if (Array.isArray(data.findings)) setFindings(data.findings as Finding[])
    if (typeof data.pr_title === "string" || typeof data.pr_state === "string") {
      setPrContext(prev => ({
        ...prev,
        title: (data.pr_title as string) ?? prev.title,
        state: (data.pr_state as string) ?? prev.state,
        author: (data.pr_author as string) ?? prev.author,
        url: (data.pr_url as string) ?? prev.url,
      }))
    }
    setScanComplete(true)
  }, [])

  /* Hydrate from the REST endpoint (fast path for already-finished scans) */
  useEffect(() => {
    if (!scanId) return
    let active = true
    fetch(`${apiBase}/api/scans/${scanId}`)
      .then(r => {
        if (!active) return null
        if (r.status === 404) { setScanNotFound(true); return null }
        return r.json()
      })
      .then((data: ScanMeta | null) => {
        if (!active || !data) return
        setScanMeta(data)
        setPrContext(prev => ({
          ...prev,
          title: data.pr_title ?? prev.title,
          state: data.pr_state ?? prev.state,
          author: data.pr_author ?? prev.author,
          url: data.pr_url ?? prev.url,
          repo: data.repo_full_name ?? prev.repo,
          pr_number: data.pr_number ?? prev.pr_number,
        }))
        if (data.error) setScanError(data.error)
        if (data.verdict) setVerdict(data.verdict)
        if (data.scan_status) setScanStatus(data.scan_status)
        if (Array.isArray(data.failed_agents)) setFailedAgents(data.failed_agents)
        if (Array.isArray(data.completed_agents)) setCompletedAgents(data.completed_agents)
        if (data.agent_errors) setAgentErrors(data.agent_errors)
        if (data.consensus) setConsensusData(data.consensus)
        if (typeof data.files_scanned === "number") setFilesScanned(data.files_scanned)
        if (Array.isArray(data.files) && data.files.length) setScannedFiles(data.files)
        if (Array.isArray(data.breach_oracle) && data.breach_oracle.length) setBreachOracle(data.breach_oracle)
        if (typeof data.patch_preview === "string") setPatchPreview(data.patch_preview)
        if (typeof data.remediation_pr_url === "string") setRemediationUrl(data.remediation_pr_url)
        if (data.status === "complete" || data.status === "failed" || data.status === "degraded" || data.status === "error") {
          if (typeof data.risk_score === "number") setRiskScore(data.risk_score)
          if (Array.isArray(data.findings)) setFindings(data.findings)
          if (Array.isArray(data.attack_chain)) setKillChain(data.attack_chain)
          setScanComplete(true)
        }
      })
      .catch(() => {})
    return () => { active = false }
  }, [scanId, apiBase])

  /* SSE subscription */
  const connect = useCallback(() => {
    if (!scanId || scanCompleteRef.current || scanNotFound) return
    const es = new EventSource(`${apiBase}/api/stream/${scanId}`)
    esRef.current = es

    es.onmessage = (ev: MessageEvent) => {
      let data: Record<string, unknown>
      try {
        data = JSON.parse(ev.data as string)
      } catch {
        return
      }
      const type = data.type as string

      if (type === "trace" || type === "agent_trace") {
        const agent = (data.agent as string) || "orchestrator"
        const text = (data.text || data.trace || "") as string
        if (isNoisyTrace(text)) return
        setAgentTraces(prev => ({ ...prev, [agent]: [...(prev[agent] ?? []), text] }))
      } else if (type === "status" || type === "agent_status") {
        const agent = data.agent as string
        const st = data.status as string
        setAgentStatuses(prev => ({ ...prev, [agent]: st }))
        if (st === "error" || st === "failed") {
          setFailedAgents(prev => (prev.includes(agent) ? prev : [...prev, agent]))
          if (typeof data.error === "string" && data.error) {
            setAgentErrors(prev => ({ ...prev, [agent]: data.error as string }))
          }
        } else if (st === "complete") {
          setCompletedAgents(prev => (prev.includes(agent) ? prev : [...prev, agent]))
        }
      } else if (type === "pr_meta") {
        setPrContext(prev => ({
          ...prev,
          title: (data.pr_title as string) ?? prev.title,
          state: (data.pr_state as string) ?? prev.state,
          author: (data.pr_author as string) ?? prev.author,
          url: (data.pr_url as string) ?? prev.url,
          repo: (data.repo as string) ?? prev.repo,
          pr_number: (data.pr_number as number) ?? prev.pr_number,
        }))
      } else if (type === "finding") {
        setFindings(prev => [...prev, data.finding as Finding])
      } else if (type === "scan_complete") {
        applySummary(data)
        es.close()
      } else if (type === "done" || type === "timeout") {
        setScanComplete(true)
        es.close()
      }
    }

    es.onerror = () => {
      es.close()
      // EventSource errors are expected once the stream closes normally.
      if (scanCompleteRef.current) return
      // Fall back to a REST refresh so the UI is never left hanging.
      fetch(`${apiBase}/api/scans/${scanId}`)
        .then(r => (r.ok ? r.json() : null))
        .then((data: ScanMeta | null) => {
          if (data && (data.status === "complete" || data.status === "failed" || data.status === "degraded" || data.status === "error")) {
            if (typeof data.risk_score === "number") setRiskScore(data.risk_score)
            if (data.verdict) setVerdict(data.verdict)
            if (data.scan_status) setScanStatus(data.scan_status)
            if (Array.isArray(data.failed_agents)) setFailedAgents(data.failed_agents)
            if (Array.isArray(data.completed_agents)) setCompletedAgents(data.completed_agents)
            if (data.agent_errors) setAgentErrors(data.agent_errors)
            if (data.consensus) setConsensusData(data.consensus)
            if (Array.isArray(data.findings)) setFindings(data.findings)
            if (Array.isArray(data.attack_chain)) setKillChain(data.attack_chain)
            if (data.remediation_pr_url) setRemediationUrl(data.remediation_pr_url)
            if (typeof data.patch_preview === "string") setPatchPreview(data.patch_preview)
            if (typeof data.files_scanned === "number") setFilesScanned(data.files_scanned)
            if (Array.isArray(data.files)) setScannedFiles(data.files)
            if (Array.isArray(data.breach_oracle)) setBreachOracle(data.breach_oracle)
            if (data.error) setScanError(data.error)
            setScanComplete(true)
          }
        })
        .catch(() => {})
    }
    return () => es.close()
  }, [scanId, apiBase, scanNotFound, applySummary])

  useEffect(() => {
    if (scanNotFound || scanComplete) return
    const cleanup = connect()
    return () => { esRef.current?.close(); cleanup?.() }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, scanNotFound, scanComplete])

  /* ── Derived state ─────────────────────────────────────────────────── */
  const findingsByAgent = useMemo(() => {
    const acc: Record<string, number> = {}
    for (const f of findings) {
      for (const label of (f.agent || "").split(" + ")) {
        const key = AGENT_KEY_BY_LABEL[label.trim()]
        if (key) acc[key] = (acc[key] ?? 0) + 1
      }
    }
    return acc
  }, [findings])

  const severityCounts = useMemo(() => {
    const acc: Record<string, number> = {}
    for (const f of findings) {
      const sev = String(f.severity || "").toUpperCase()
      acc[sev] = (acc[sev] ?? 0) + 1
    }
    return acc
  }, [findings])

  const allAgentKeys = Object.keys(AGENTS) as AgentKey[]

  const actualFailedAgents = useMemo(() => {
    const set = new Set<string>(failedAgents)
    for (const k of allAgentKeys) {
      if (agentStatuses[k] === "error" || agentStatuses[k] === "failed") {
        set.add(k)
      }
    }
    return Array.from(set)
  }, [failedAgents, agentStatuses, allAgentKeys])

  const failedCount = actualFailedAgents.length

  const healthyCount = useMemo(() => {
    if (consensusData?.agents_completed !== undefined) {
      return consensusData.agents_completed
    }
    return allAgentKeys.filter(k => agentStatuses[k] === "complete").length
  }, [consensusData, agentStatuses, allAgentKeys])

  const isSwarmDegraded =
    scanStatus === "degraded" ||
    scanStatus === "error" ||
    failedCount > 0 ||
    Boolean(consensusData?.is_degraded)

  const settledAgents = allAgentKeys
    .filter(k => ["complete", "error", "failed"].includes(agentStatuses[k] ?? "") || actualFailedAgents.includes(k)).length

  const progress = scanComplete ? 100 : Math.round((settledAgents / 6) * 100)

  const effectiveVerdict = verdict || scanMeta?.verdict
  const effectiveScanStatus = scanStatus || scanMeta?.scan_status

  const pill = verdictFor(riskScore, scanComplete, effectiveVerdict, effectiveScanStatus, failedCount)
  const pillTone = TONE[pill.tone]

  /* Deduplicate breach oracle cards by (cwe_id, breach name) — defensive; backend already dedupes */
  const breachCards = useMemo(() => {
    const source: BreachCard[] = breachOracle.length
      ? breachOracle
      : findings
          .filter(f => f.breach_citation)
          .map(f => ({
            cwe_id: f.cwe_id || "CWE-200",
            breach: f.breach_citation!.breach,
            year: f.breach_citation!.year,
            records: f.breach_citation!.records,
            fine: f.breach_citation!.fine,
          }))
    const seen = new Set<string>()
    const out: BreachCard[] = []
    for (const c of source) {
      const key = `${(c.cwe_id || "").toUpperCase()}::${(c.breach || "").trim().toLowerCase()}`
      if (!c.breach || seen.has(key)) continue
      seen.add(key)
      out.push(c)
    }
    return out
  }, [breachOracle, findings])

  const repoName = scanMeta?.repo_full_name ?? prContext.repo ?? ""
  const prNumber = scanMeta?.pr_number ?? prContext.pr_number ?? null
  const prLink = prContext.url || (repoName && prNumber ? `https://github.com/${repoName}/pull/${prNumber}` : "#")
  const stateBadge = githubStateBadge(prContext.state)
  const hasGist = Boolean(remediationUrl)
  const hasPatch = hasGist || Boolean(patchPreview)

  if (scanNotFound) {
    return (
      <div className="min-h-screen bg-[#05070d] text-slate-100 flex flex-col items-center justify-center p-6 text-center">
        <div className="p-5 rounded-full bg-red-500/10 border border-red-500/20 mb-5 shadow-lg shadow-red-900/30">
          <AlertTriangle className="w-10 h-10 text-red-400" />
        </div>
        <h1 className="text-xl font-bold mb-2">Scan Not Found</h1>
        <p className="text-sm text-slate-400 max-w-md mb-6">
          The requested scan ID{" "}
          <code className="text-purple-400 font-mono bg-purple-500/10 px-1.5 py-0.5 rounded">{scanId}</code>{" "}
          does not exist or has expired from memory.
        </p>
        <button
          onClick={() => router.push("/")}
          className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 transition font-semibold text-sm flex items-center gap-2"
        >
          <ArrowLeft className="w-4 h-4" /> Return to Dashboard
        </button>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#05070d] text-slate-100 selection:bg-cyan-500/30">
      {/* ── Sticky header: PR title + GitHub state + verdict ─────────────── */}
      <header className="sticky top-0 z-40 border-b border-slate-800/70 bg-[#05070d]/90 backdrop-blur-xl">
        <div className="max-w-[1400px] mx-auto px-4 h-16 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <button onClick={() => router.push("/")} aria-label="Back to dashboard" className="p-1.5 rounded-lg hover:bg-slate-800/60 transition shrink-0">
              <ArrowLeft className="w-4 h-4 text-slate-400" />
            </button>
            <Shield className="w-4 h-4 text-purple-400 shrink-0" />
            <span className="font-extrabold text-sm bg-clip-text text-transparent bg-gradient-to-r from-purple-400 to-cyan-400 shrink-0">ARGUS</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-700 shrink-0" />
            <div className="min-w-0">
              <div className="flex items-center gap-2 min-w-0">
                <a
                  href={prLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 font-mono text-xs text-slate-400 hover:text-white transition min-w-0"
                >
                  <GitPullRequest className="w-3 h-3 shrink-0" />
                  <span className="truncate">{repoName || "…"}{prNumber ? ` #${prNumber}` : ""}</span>
                  <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                </a>
                {stateBadge && (
                  <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border shrink-0 ${stateBadge.cls}`}>
                    {stateBadge.label}
                  </span>
                )}
              </div>
              <h1 className="text-sm font-semibold text-slate-100 truncate" title={prContext.title ?? ""}>
                {prContext.title || "Loading pull request context…"}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <span
              className="hidden sm:flex items-center gap-2 text-[11px] font-bold tracking-wider px-3 py-1.5 rounded-lg"
              style={{ color: pillTone.text, backgroundColor: pillTone.bg, border: `1px solid ${pillTone.border}` }}
            >
              <span className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: pillTone.text, boxShadow: `0 0 8px ${pillTone.text}` }} />
              {pill.label}
            </span>
            {hasPatch && (
              <a
                href={remediationUrl ?? "#"}
                target={remediationUrl ? "_blank" : undefined}
                rel="noopener noreferrer"
                onClick={remediationUrl ? undefined : () => setShowPatchModal(true)}
                className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all hover:brightness-110"
                style={{ background: "rgba(34,197,94,0.14)", color: "#4ade80", border: "1px solid rgba(34,197,94,0.4)", boxShadow: "0 0 18px rgba(34,197,94,0.2)" }}
              >
                <ExternalLink className="w-3 h-3" /> View Remediation {hasGist ? "Gist" : "Patch"} ↗
              </a>
            )}
          </div>
        </div>
        {/* Thin swarm progress bar */}
        {!scanComplete && (
          <div className="h-0.5 w-full bg-slate-800/60">
            <div className="h-full bg-gradient-to-r from-purple-500 via-blue-500 to-cyan-400 transition-all duration-700" style={{ width: `${progress}%` }} />
          </div>
        )}
      </header>

      <div className="max-w-[1400px] mx-auto px-4 py-5">
        {scanError && (
          <div className={`mb-4 p-3.5 rounded-xl border text-sm flex items-start gap-3 ${
            scanComplete ? "bg-rose-500/10 border-rose-500/30 text-rose-300" : "bg-amber-500/10 border-amber-500/30 text-amber-300"
          }`}>
            <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold">{scanComplete ? "Scan Failed" : "Scan Notice"}</div>
              <div className="text-xs opacity-90 mt-1 leading-relaxed">{scanError}</div>
            </div>
          </div>
        )}

        {/* ── Degraded Scan Warning Banner ─────────────────────────────── */}
        {isSwarmDegraded && (
          <div className="mb-4 p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-200 text-xs flex items-start gap-3 shadow-lg shadow-amber-950/20">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="font-bold text-amber-300 text-sm">
                Scan Degraded: {failedCount > 0 ? failedCount : 1} agent(s) failed (Groq/Gemini capacity reached)
              </div>
              <p className="mt-1 text-slate-300 leading-relaxed text-xs">
                Findings represent partial diff coverage. One or more security analysis engines were unable to complete their inspection due to upstream capacity or rate limits.
              </p>
              {actualFailedAgents.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-2.5">
                  {actualFailedAgents.map(ak => {
                    const agentCfg = AGENTS[ak as AgentKey]
                    const name = agentCfg?.name || ak
                    const err = agentErrors[ak]
                    return (
                      <span
                        key={ak}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-300"
                        title={err}
                      >
                        {name}{err ? `: ${err}` : ""}
                      </span>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Compact 5-column KPI strip ────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-4">
          {/* 1 · Risk Score */}
          <div className="glass-panel rounded-xl p-4 flex items-center gap-3">
            <MiniGauge score={scanComplete ? (riskScore ?? 0) : riskScore} />
            <div className="min-w-0">
              <div className="text-2xl font-black tabular-nums text-slate-100 leading-none">{riskScore ?? 0}</div>
              <div className="text-[9px] text-slate-500 uppercase tracking-wider mt-0.5">Score / 100</div>
              <div className={`text-[10px] font-bold uppercase tracking-wider mt-1 ${
                (riskScore ?? 0) >= 65 ? "text-rose-400" : (riskScore ?? 0) >= 25 ? "text-amber-400" : "text-emerald-400"
              }`}>
                {(riskScore ?? 0) >= 65 ? "Critical" : (riskScore ?? 0) >= 25 ? "Elevated" : "Low"}
              </div>
            </div>
          </div>

          {/* 2 · Files Audited */}
          <Kpi
            label="Files Audited"
            hint={
              scannedFiles.length > 0 ? (
                <div className="space-y-0.5">
                  {scannedFiles.slice(0, 3).map(f => (
                    <div key={f} className="font-mono text-[9px] text-slate-500 truncate" title={f}>{f}</div>
                  ))}
                  {scannedFiles.length > 3 && (
                    <div className="text-[9px] text-slate-600">+{scannedFiles.length - 3} more</div>
                  )}
                </div>
              ) : undefined
            }
          >
            <div className="flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-cyan-400" />
              <span className="text-2xl font-black tabular-nums text-slate-100">{filesScanned ?? "—"}</span>
            </div>
          </Kpi>

          {/* 3 · Verified Findings */}
          <Kpi
            label="Verified Findings"
            hint={
              <span className="flex flex-wrap gap-1">
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(sev => (
                  <span key={sev} className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${SEVERITY_STYLE[sev]}`}>
                    {severityCounts[sev] ?? 0} {sev[0]}
                  </span>
                ))}
              </span>
            }
          >
            <div className="flex items-center gap-2">
              <ShieldCheck className={`w-4 h-4 ${findings.length > 0 ? "text-rose-400" : "text-emerald-400"}`} />
              <span className="text-2xl font-black tabular-nums text-slate-100">{findings.length}</span>
            </div>
          </Kpi>

          {/* 4 · PR Status */}
          <Kpi
            label="PR Status"
            hint={prContext.author ? <span className="font-mono">@{prContext.author}</span> : "awaiting metadata"}
          >
            <div className="flex items-center gap-2">
              <GitPullRequest className="w-4 h-4 text-slate-500" />
              <span className={`text-sm font-black uppercase tracking-wide ${
                (prContext.state || "").toUpperCase() === "MERGED" ? "text-purple-300"
                : (prContext.state || "").toUpperCase() === "CLOSED" ? "text-rose-300"
                : "text-emerald-300"
              }`}>
                {prContext.state || "—"}
              </span>
            </div>
          </Kpi>

          {/* 5 · Swarm Consensus */}
          <Kpi
            label="Swarm Consensus"
            hint={
              <div className="flex items-center justify-between gap-1">
                <span className="flex items-center gap-1.5 font-mono tabular-nums">
                  <Clock className="w-3 h-3 text-slate-500" /> {formatElapsed(elapsedMs)}
                </span>
                {failedCount > 0 && (
                  <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    {failedCount} Failed
                  </span>
                )}
              </div>
            }
          >
            <div className="flex items-center gap-2">
              <Activity className={`w-4 h-4 ${failedCount > 0 ? "text-amber-400" : "text-emerald-400"}`} />
              <span className={`text-sm font-black tabular-nums ${failedCount > 0 ? "text-amber-300" : "text-emerald-300"}`}>
                {healthyCount}/6 <span className="text-slate-400 font-semibold">{scanComplete ? "Healthy Agents" : "Agents"}</span>
              </span>
            </div>
          </Kpi>
        </div>

        {/* ── Compact 3×2 agent grid ────────────────────────────────────── */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-6">
          {(Object.keys(AGENTS) as AgentKey[]).map(key => (
            <AgentCard
              key={key}
              agentKey={key}
              traces={agentTraces[key] ?? []}
              status={actualFailedAgents.includes(key) ? "error" : (agentStatuses[key] ?? "")}
              findingCount={findingsByAgent[key] ?? 0}
              errorMessage={agentErrors[key]}
            />
          ))}
        </div>

        {/* ── Findings + intelligence split (2 : 1) ─────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left — verified findings */}
          <div className="lg:col-span-2 glass-panel rounded-2xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <h2 className="font-bold text-sm">Verified Findings</h2>
              </div>
              <span className="text-[10px] font-mono text-slate-500">{findings.length} total · cross-agent deduped</span>
            </div>

            {scanComplete && findings.length === 0 ? (
              isSwarmDegraded ? (
                <div className="flex flex-col items-center justify-center py-8 text-center rounded-xl border border-dashed border-amber-500/40 bg-amber-500/10 px-4">
                  <AlertTriangle className="w-8 h-8 text-amber-400 mb-2" />
                  <h3 className="text-sm font-bold text-amber-300">Analysis Incomplete — Engines Unavailable</h3>
                  <p className="text-xs text-slate-300 mt-1 max-w-lg leading-relaxed">
                    One or more security agents failed to inspect this diff. Automated merge verification cannot be guaranteed. Review engine fallback logs or re-trigger the scan.
                  </p>
                  {actualFailedAgents.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-1.5 justify-center">
                      {actualFailedAgents.map(ak => (
                        <span key={ak} className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30">
                          {AGENTS[ak as AgentKey]?.name || ak} failed
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-center rounded-xl border border-dashed border-emerald-500/30 bg-emerald-500/5 px-4">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mb-2" />
                  <h3 className="text-sm font-bold text-emerald-400">Zero Exploitable Vulnerabilities Introduced in This Diff</h3>
                  <p className="text-[11px] text-slate-500 mt-1 max-w-lg leading-relaxed">
                    All six agents verified the added lines and returned no confirmed findings. Safe to merge.
                  </p>
                </div>
              )
            ) : (
              <div className="space-y-2.5">
                {findings.map(f => (
                  <div key={f.id} className="rounded-xl p-3.5 border border-slate-800/70" style={{ backgroundColor: "#080f1c" }}>
                    <div className="flex flex-wrap items-center gap-1.5 mb-2">
                      <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${SEVERITY_STYLE[String(f.severity || "").toUpperCase()] ?? SEVERITY_STYLE.LOW}`}>
                        {f.severity}
                      </span>
                      <span className="text-[9px] font-mono text-slate-300 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                        {f.cwe_id || "CWE-200"}
                      </span>
                      <span className="text-[9px] font-semibold text-purple-300 bg-purple-500/10 border border-purple-500/25 px-2 py-0.5 rounded">
                        {f.agent}
                      </span>
                      <span className="text-[9px] font-mono text-cyan-300/90 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded max-w-[280px] truncate" title={`${f.file_path || "unknown"}:${f.line_number ?? 1}`}>
                        {f.file_path || "unknown"}:{f.line_number ?? 1}
                      </span>
                      {f.advisory && (
                        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase text-amber-300 bg-amber-500/10 border border-amber-500/25">
                          advisory
                        </span>
                      )}
                      {(f.compliance_refs ?? []).map(ref => (
                        <span key={ref} className="text-[9px] px-2 py-0.5 rounded"
                          style={{ color: "#60a5fa", backgroundColor: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.25)" }}>
                          {ref}
                        </span>
                      ))}
                    </div>
                    <h4 className="text-sm font-semibold text-slate-200 mb-1">{f.title}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed">{f.description}</p>
                    {f.remediation && (
                      <div className="mt-2.5 rounded-lg bg-slate-950/80 border border-emerald-500/20 px-3 py-2">
                        <div className="flex items-center gap-1.5 mb-1">
                          <Wrench className="w-3 h-3 text-emerald-400" />
                          <span className="text-[9px] font-bold text-emerald-400 uppercase tracking-wider">Remediation</span>
                        </div>
                        <p className="text-[11px] font-mono text-emerald-200/90 leading-relaxed whitespace-pre-wrap">{f.remediation}</p>
                      </div>
                    )}
                    {f.breach_citation && (
                      <div className="mt-2 p-2 rounded-lg" style={{ backgroundColor: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)" }}>
                        <p className="text-[10px] text-red-400 font-bold">
                          ⚠ Historical breach: {f.breach_citation.breach} ({f.breach_citation.year})
                        </p>
                        <p className="text-[10px] text-slate-400 mt-0.5">
                          {f.breach_citation.records} · Penalty: {f.breach_citation.fine}
                        </p>
                      </div>
                    )}
                  </div>
                ))}
                {!scanComplete && (
                  <div className="text-xs text-slate-500 text-center py-4">Agents are analyzing the diff…</div>
                )}
              </div>
            )}
          </div>

          {/* Right — Breach Oracle + Red Team Ω */}
          <div className="space-y-4">
            <div className="glass-panel rounded-2xl p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-amber-400" />
                  <h2 className="font-bold text-sm">Breach Oracle</h2>
                </div>
                {breachCards.length > 0 && (
                  <span className="text-[10px] font-mono text-slate-500">{breachCards.length} mapped</span>
                )}
              </div>
              {breachCards.length > 0 ? (
                <div className="space-y-2.5">
                  {breachCards.map((c, i) => (
                    <div key={i} className="rounded-xl p-2.5 border" style={{ backgroundColor: "rgba(245,158,11,0.05)", borderColor: "rgba(249,115,22,0.25)" }}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-mono font-bold text-amber-300 bg-amber-500/10 border border-amber-500/25 px-1.5 py-0.5 rounded">
                          {c.cwe_id}
                        </span>
                        <span className="text-[9px] font-mono text-red-400">{c.year}</span>
                      </div>
                      <div className="text-xs font-bold text-amber-200 mb-0.5">{c.breach}</div>
                      <p className="text-[10px] text-slate-400 leading-relaxed">
                        <span className="text-slate-300 font-semibold">{c.records}</span> exposed
                      </p>
                      <p className="text-[10px] text-red-300/90 leading-relaxed mt-0.5 font-semibold">{c.fine}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6 text-slate-500 text-xs">
                  <Skull className="w-5 h-5 mx-auto mb-1.5 opacity-30" />
                  No historical breach correlation.
                </div>
              )}
            </div>

            <div className="glass-panel rounded-2xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <Target className="w-4 h-4 text-red-400" />
                <h2 className="font-bold text-sm">Red Team Ω — Kill Chain</h2>
              </div>
              {killChain.length > 0 ? (
                <KillChain steps={killChain} />
              ) : (
                <div className="text-center py-6 text-slate-500 text-xs">
                  {scanComplete ? "No kill chain generated — attack surface neutralized." : "Red Team Ω constructing adversarial path…"}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── Patch modal ──────────────────────────────────────────────────── */}
      {showPatchModal && patchPreview && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
          onClick={() => setShowPatchModal(false)}
        >
          <div
            className="max-w-3xl w-full max-h-[75vh] overflow-y-auto rounded-xl p-5"
            style={{ backgroundColor: "#080f1c", border: "1px solid rgba(34,197,94,0.25)" }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <Copy className="w-3 h-3" /> Generated Remediation Patch
              </span>
              <button onClick={() => setShowPatchModal(false)} aria-label="Close patch preview" className="text-slate-500 hover:text-slate-300">
                <X className="w-4 h-4" />
              </button>
            </div>
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{patchPreview}</pre>
          </div>
        </div>
      )}
    </div>
  )
}
