import { ArrowRight, Link2 } from 'lucide-react'
import { useSoc } from '../hooks/useDashboard'
import { relativeTime } from '../lib/labels'
import { Panel, Pill } from './Panel'

export function MeshIncidentCard() {
  const { meshIncident, samples, setSelectedId } = useSoc()
  const names = new Map(samples.map((sample) => [sample.device_id, sample.name]))

  return (
    <Panel
      eyebrow="Mesh correlation"
      title="Cross-device incident"
      icon={<Link2 className="h-4 w-4" />}
      action={
        <Pill tone={meshIncident ? 'critical' : 'ok'}>
          {meshIncident ? 'rule match' : 'quiet'}
        </Pill>
      }
    >
      {meshIncident ? (
        <div className="space-y-3">
          <div>
            <p className="text-sm font-semibold text-white">{meshIncident.title}</p>
            <p className="mt-1 text-sm text-slate-300">{meshIncident.detail}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {meshIncident.device_ids.map((deviceId, index) => (
              <div key={deviceId} className="contents">
                {index > 0 ? <ArrowRight className="h-3.5 w-3.5 text-rose-300" /> : null}
                <button
                  type="button"
                  onClick={() => setSelectedId(deviceId)}
                  className="rounded-full border border-rose-400/40 bg-rose-500/10 px-2.5 py-1 font-mono text-[10px] tracking-wide text-rose-100 uppercase hover:border-rose-300"
                >
                  {names.get(deviceId) ?? deviceId}
                </button>
              </div>
            ))}
          </div>
          <ol className="space-y-2">
            {meshIncident.sequence.map((event, index) => (
              <li
                key={`${event.device_id}-${event.timestamp}`}
                className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2"
              >
                <p className="font-mono text-[10px] tracking-[0.16em] text-rose-200/80 uppercase">
                  {index === 0 ? '01 camera' : '02 lock'} · {relativeTime(event.timestamp)}
                </p>
                <p className="mt-1 text-sm text-slate-100">
                  {event.command} from {event.source_ip}
                </p>
                <p className="mt-0.5 font-mono text-[10px] text-slate-500 uppercase">
                  {event.device_name} · {event.result.replaceAll('_', ' ')}
                </p>
              </li>
            ))}
          </ol>
          <p className="text-xs leading-relaxed text-slate-500">{meshIncident.explanation}</p>
        </div>
      ) : (
        <div className="rounded-xl border border-dashed border-white/10 px-3 py-6 text-center">
          <p className="text-sm text-slate-400">No cross-device incident.</p>
          <p className="mt-2 text-xs leading-relaxed text-slate-500">
            Correlation is a 10-second shared-source rule over observed camera and lock commands, not a
            learned graph model.
          </p>
        </div>
      )}
    </Panel>
  )
}
