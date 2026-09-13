import type { ReactNode } from 'react'

type PanelProps = {
  title: string
  eyebrow?: string
  icon?: ReactNode
  action?: ReactNode
  actions?: ReactNode
  className?: string
  children: ReactNode
}

export function Panel({ title, eyebrow, icon, action, actions, className = '', children }: PanelProps) {
  const trailing = actions ?? action
  return (
    <section
      className={`panel flex min-h-0 flex-col overflow-hidden rounded-2xl border border-cyan-500/15 bg-[#09111c]/90 shadow-[0_0_0_1px_rgba(46,230,214,0.04)] ${className}`}
    >
      <header className="flex items-center justify-between gap-3 border-b border-cyan-500/10 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2.5">
          {icon ? <span className="text-cyan-300">{icon}</span> : null}
          <div className="min-w-0">
            {eyebrow ? (
              <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-cyan-400/70">{eyebrow}</p>
            ) : null}
            <h2 className="truncate text-sm font-semibold tracking-wide text-slate-100">{title}</h2>
          </div>
        </div>
        {trailing ? <div className="flex shrink-0 items-center gap-2">{trailing}</div> : null}
      </header>
      <div className="min-h-0 flex-1 p-4">{children}</div>
    </section>
  )
}

export function Pill({
  children,
  tone = 'neutral',
}: {
  children: ReactNode
  tone?: 'neutral' | 'ok' | 'watch' | 'high' | 'critical'
}) {
  const tones = {
    neutral: 'border-slate-600/50 bg-slate-800/70 text-slate-300',
    ok: 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
    watch: 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200',
    high: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
    critical: 'border-rose-400/40 bg-rose-500/15 text-rose-200',
  }
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${tones[tone]}`}>
      {children}
    </span>
  )
}

export function Chip({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${className}`}>
      {children}
    </span>
  )
}
