import { History } from 'lucide-react'
import { formatClock } from '../lib/labels'
import { useSoc } from '../hooks/useDashboard'
import { Panel, Pill } from './Panel'

export function StatusTimeline() {
  const model = useSoc()
  return (
    <Panel eyebrow="Audit" title="Device status changes" icon={<History className="h-4 w-4" />}>
      {model.events.length === 0 ? (
        <p className="text-sm text-slate-500">Status transitions will stream here as the mesh changes state.</p>
      ) : (
        <ol className="grid max-h-[220px] gap-2 overflow-y-auto">
          {model.events.slice(0, 8).map((event) => (
            <li
              key={event.id}
              className="cursor-pointer rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2"
              onClick={() => model.setSelectedId(event.deviceId)}
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm text-slate-100">{event.deviceName}</p>
                <Pill tone={toneFor(event.kind)}>{event.kind}</Pill>
              </div>
              <p className="mt-1 line-clamp-2 text-xs text-slate-400">{event.detail}</p>
              <p className="mt-1 font-mono text-[10px] text-slate-500">
                {event.from ? `${event.from} → ${event.to}` : event.to} · {formatClock(event.at)}
              </p>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  )
}

function toneFor(kind: string): 'ok' | 'watch' | 'high' | 'critical' | 'neutral' {
  if (kind === 'recovery') return 'ok'
  if (kind === 'attack') return 'critical'
  if (kind === 'response' || kind === 'containment') return 'high'
  if (kind === 'status') return 'watch'
  return 'neutral'
}
