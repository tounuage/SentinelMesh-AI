import { READINESS_ITEMS, readinessLine, type ReadinessFlags } from '../lib/readiness'

export function ReadinessStrip(flags: ReadinessFlags) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 px-4 py-2 font-mono text-xs" aria-live="polite">
      <span className="sr-only">{readinessLine(flags)}</span>
      {READINESS_ITEMS.map((item) => {
        const ok = flags[item.key]
        return (
          <span key={item.key} className={ok ? 'text-emerald-300' : 'text-slate-500'}>
            {item.label} {ok ? '✓' : '—'}
          </span>
        )
      })}
    </div>
  )
}
