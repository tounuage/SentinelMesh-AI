import { Activity, HeartPulse, Play, Shield, Square, Unplug } from 'lucide-react'
import { useSoc } from '../hooks/useDashboard'

function LiveDot({ on }: { on: boolean }) {
  return (
    <span className="relative inline-flex h-2.5 w-2.5">
      {on ? <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" /> : null}
      <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${on ? 'bg-emerald-400' : 'bg-rose-500'}`} />
    </span>
  )
}

export function TopBar() {
  const {
    snapshot,
    simHealthy,
    engineHealthy,
    controllerActive,
    autoRespond,
    setAutoRespond,
    lastError,
    demoRunning,
    runDemo,
    stopDemo,
  } = useSoc()

  return (
    <header className="sticky top-0 z-20 border-b border-cyan-500/15 bg-[#05070c]/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1680px] flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10">
            <Shield className="h-5 w-5 text-cyan-300" />
          </div>
          <div>
            <p className="font-mono text-[10px] tracking-[0.28em] text-cyan-400/80 uppercase">SentinelMesh AI</p>
            <h1 className="text-lg font-semibold tracking-tight text-white">Cyber-physical immune system</h1>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-slate-300">
            <LiveDot on={simHealthy} />
            Home mesh {simHealthy ? 'live' : 'down'}
          </span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-slate-300">
            <LiveDot on={engineHealthy} />
            AI {engineHealthy ? 'online' : 'heuristic'}
          </span>
          <span
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono ${
              controllerActive
                ? 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
                : 'border-white/10 bg-white/5 text-slate-400'
            }`}
            title={
              controllerActive
                ? 'Backend worker is ingesting, executing policy, and enforcing without the dashboard'
                : 'Controller heartbeat is stale; the dashboard may fall back to driving ingest'
            }
          >
            <LiveDot on={controllerActive} />
            <HeartPulse className="h-3.5 w-3.5" />
            Controller {controllerActive ? 'active' : 'idle'}
          </span>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1.5 font-mono text-slate-300">
            <Activity className="h-3.5 w-3.5 text-cyan-300" />
            Tick {snapshot?.tick ?? '—'}
          </span>
          <button
            type="button"
            onClick={() => setAutoRespond(!autoRespond)}
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono text-[11px] tracking-wide uppercase ${
              autoRespond
                ? 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
                : 'border-amber-400/40 bg-amber-400/10 text-amber-200'
            }`}
          >
            {autoRespond ? <Shield className="h-3.5 w-3.5" /> : <Unplug className="h-3.5 w-3.5" />}
            {autoRespond ? 'Immune armed' : 'Immune paused'}
          </button>
          <button
            type="button"
            onClick={() => (demoRunning ? stopDemo() : void runDemo())}
            className="inline-flex items-center gap-2 rounded-full border border-cyan-400/40 bg-cyan-400/15 px-3 py-1.5 font-mono text-[11px] tracking-wide text-cyan-100 uppercase"
          >
            {demoRunning ? <Square className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            {demoRunning ? 'Stop demo' : 'Run demo'}
          </button>
        </div>
      </div>
      {lastError ? (
        <div className="border-t border-rose-500/20 bg-rose-500/10 px-4 py-1.5 text-center font-mono text-[11px] text-rose-200">
          {lastError}
        </div>
      ) : null}
    </header>
  )
}
