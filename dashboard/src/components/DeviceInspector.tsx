import { ShieldCheck } from 'lucide-react'
import { Chip, Panel } from './Panel'
import { useSoc } from '../hooks/useDashboard'
import { containmentOf, pretty, responseChip, statusChip } from '../lib/format'

export function DeviceInspector() {
  const { selectedSample, selectedFinding, selectedResponse, recoverDevice, busy } = useSoc()
  if (!selectedSample) {
    return (
      <Panel eyebrow="Device" title="Inspector">
        <p className="text-sm text-slate-400">Waiting for the home mesh…</p>
      </Panel>
    )
  }

  const state = containmentOf(selectedSample, selectedResponse?.response_state)
  const sensors = Object.entries(selectedSample.sensors).slice(0, 8)
  const commands = selectedSample.command_history.slice(-3).reverse()

  return (
    <Panel
      eyebrow={selectedSample.room.replaceAll('_', ' ')}
      title={selectedSample.name}
      action={<Chip className={responseChip(state)}>{state}</Chip>}
    >
      <div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <Chip className={statusChip(selectedSample.status)}>{selectedSample.status}</Chip>
          {selectedSample.containment?.safe_mode ? (
            <Chip className="border-amber-400/40 text-amber-200">safe mode</Chip>
          ) : null}
          <Chip className="border-white/10 text-slate-300">{selectedSample.network.local_ip}</Chip>
        </div>
        <dl className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
          {sensors.map(([key, value]) => (
            <div key={key} className="rounded-lg border border-white/8 bg-black/20 px-2 py-1.5">
              <dt className="font-mono text-[10px] tracking-wide uppercase">{pretty(key)}</dt>
              <dd className="mt-0.5 text-slate-100">{formatSensor(value)}</dd>
            </div>
          ))}
        </dl>
        {commands.length ? (
          <div>
            <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">Recent commands</p>
            <ul className="mt-1 space-y-1">
              {commands.map((command) => (
                <li key={`${command.timestamp}-${command.command}`} className="font-mono text-[11px] text-slate-400">
                  <span className={command.authorized ? 'text-emerald-300' : 'text-rose-300'}>
                    {command.authorized ? 'ok' : 'deny'}
                  </span>{' '}
                  {command.command} · {command.actor}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <button
          type="button"
          disabled={busy || state === 'normal'}
          onClick={() => void recoverDevice(selectedSample.device_id, true)}
          className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-emerald-400/30 bg-emerald-400/10 py-2 text-sm text-emerald-100 hover:bg-emerald-400/15 disabled:opacity-40"
        >
          <ShieldCheck className="h-4 w-4" />
          Recover to normal
        </button>
        {selectedFinding?.defensive_action ? (
          <p className="text-xs leading-relaxed text-slate-400">{selectedFinding.defensive_action}</p>
        ) : null}
      </div>
    </Panel>
  )
}

function formatSensor(value: unknown) {
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(1)
  if (value == null) return '—'
  return String(value)
}
