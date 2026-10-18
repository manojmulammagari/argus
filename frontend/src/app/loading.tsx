export default function Loading() {
  return (
    <div className="min-h-screen bg-[#05070d] text-slate-100 p-4 animate-pulse">
      <div className="max-w-[1400px] mx-auto space-y-4">
        {/* Sticky header skeleton */}
        <div className="h-16 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center px-4 gap-3">
          <div className="w-4 h-4 rounded bg-slate-800" />
          <div className="h-3 w-40 rounded bg-slate-800" />
          <div className="ml-auto h-7 w-52 rounded-lg bg-slate-800/80" />
        </div>

        {/* 5-column KPI strip skeleton */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-[96px] rounded-xl bg-slate-900/50 border border-slate-800/80 p-4 space-y-3">
              <div className="h-3 w-24 rounded bg-slate-800/70" />
              <div className="h-7 w-16 rounded bg-slate-800" />
              <div className="h-2 w-full rounded bg-slate-800/60" />
            </div>
          ))}
        </div>

        {/* 3×2 agent grid skeleton */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-28 rounded-xl bg-slate-900/50 border border-slate-800/80 p-4 space-y-3">
              <div className="flex items-center gap-3">
                <div className="w-7 h-7 rounded-lg bg-slate-800" />
                <div className="h-3 w-28 rounded bg-slate-800/70" />
                <div className="ml-auto h-4 w-16 rounded-full bg-slate-800/60" />
              </div>
              <div className="h-2 w-3/4 rounded bg-slate-800/50" />
              <div className="h-2 w-1/2 rounded bg-slate-800/40" />
            </div>
          ))}
        </div>

        {/* Findings + intelligence split skeleton */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 h-64 rounded-2xl bg-slate-900/50 border border-slate-800/80 p-4 space-y-3">
            <div className="h-3 w-36 rounded bg-slate-800/70" />
            <div className="h-20 rounded-xl bg-slate-800/40" />
            <div className="h-20 rounded-xl bg-slate-800/40" />
          </div>
          <div className="space-y-4">
            <div className="h-32 rounded-2xl bg-slate-900/50 border border-slate-800/80" />
            <div className="h-32 rounded-2xl bg-slate-900/50 border border-slate-800/80" />
          </div>
        </div>
      </div>
    </div>
  );
}
