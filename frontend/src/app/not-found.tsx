import Link from "next/link"
import { Shield, ArrowLeft } from "lucide-react"

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[#060b14] text-slate-100 flex flex-col items-center justify-center p-6 text-center">
      <div className="w-14 h-14 rounded-2xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center mb-6">
        <Shield className="w-7 h-7 text-purple-400" />
      </div>
      <span className="text-xs font-mono uppercase tracking-widest text-purple-400 mb-2 font-semibold">404 · Page Not Found</span>
      <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100 mb-3 tracking-tight">Resource Not Found</h1>
      <p className="text-sm text-slate-400 max-w-md mb-8 leading-relaxed">
        The security analysis dashboard or scan you requested does not exist or may have been evicted from memory.
      </p>
      <Link
        href="/"
        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white text-sm font-semibold shadow-lg shadow-purple-500/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
      >
        <ArrowLeft className="w-4 h-4" />
        Return to Dashboard
      </Link>
    </div>
  )
}
