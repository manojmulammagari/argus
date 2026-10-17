export default function Loading() {
  return (
    <div className="min-h-screen bg-[#060b14] text-slate-100 p-6 animate-pulse">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="h-14 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <div className="col-span-2 sm:col-span-1 lg:col-span-2 h-32 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
          <div className="h-32 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
          <div className="h-32 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
          <div className="h-32 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
          <div className="h-32 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-44 bg-slate-900/60 border border-slate-800/80 rounded-xl" />
          ))}
        </div>
      </div>
    </div>
  )
}
