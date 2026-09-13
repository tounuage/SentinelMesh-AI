import { Camera, DoorOpen, Lock, Plug, Shield, Thermometer } from 'lucide-react'
import type { DeviceType, TelemetrySample } from '../types'
import { useSoc } from '../hooks/useDashboard'
import { buildVerifiedContainment } from '../lib/containment'
import { containmentOf, findingFor, pretty, riskColor } from '../lib/format'
import {
  buildPhysicalConsequence,
  consequenceDevice,
  type ConsequenceTone,
  type PhysicalConsequenceView,
} from '../lib/physicalConsequence'

const ROOMS: {
  id: string
  label: string
  className: string
  devices: string[]
}[] = [
  { id: 'entryway', label: 'Entryway', className: '', devices: ['cam-front-door', 'lock-front-door'] },
  { id: 'hallway', label: 'Hallway', className: '', devices: ['thermo-hallway'] },
  { id: 'living_room', label: 'Living room', className: 'col-span-2', devices: ['plug-living-lamp'] },
]

function Glyph({ type }: { type: DeviceType }) {
  const cls = 'h-4 w-4'
  if (type === 'smart_camera') return <Camera className={cls} />
  if (type === 'smart_lock') return <Lock className={cls} />
  if (type === 'smart_plug') return <Plug className={cls} />
  return <Thermometer className={cls} />
}

function nodeTone(sample: TelemetrySample, risk: number, state: string) {
  if (state === 'quarantine' || sample.status === 'quarantined') return 'border-rose-400 bg-rose-500/20 text-rose-100'
  if (state === 'restricted' || sample.containment?.safe_mode) return 'border-orange-400 bg-orange-500/15 text-orange-100'
  if (risk >= 45 || sample.status === 'compromised') return 'border-rose-400/80 bg-rose-500/10 text-rose-100'
  if (risk >= 20) return 'border-amber-400/70 bg-amber-500/10 text-amber-100'
  return 'border-emerald-400/50 bg-emerald-500/10 text-emerald-100'
}

function toneClass(tone: ConsequenceTone) {
  if (tone === 'hostile') return 'text-rose-200'
  if (tone === 'contained') return 'text-emerald-200'
  if (tone === 'attention') return 'text-amber-200'
  if (tone === 'pending') return 'text-slate-400'
  return 'text-slate-300'
}

export function HomeFloor() {
  const { samples, findings, responses, selectedId, setSelectedId, demoStage, attacks, meshIncident } = useSoc()
  const byId = new Map(samples.map((sample) => [sample.device_id, sample]))
  const lock = consequenceDevice(samples)
  const lockResponse = responses.find((item) => item.device_id === lock?.device_id)
  const lockAttack = attacks.find((item) => item.device_id === lock?.device_id) ?? attacks[0] ?? null
  const evidence = lock ? buildVerifiedContainment(lock, lockAttack, lockResponse?.last_action) : null
  const view = buildPhysicalConsequence(lock, evidence)

  return (
    <section className="panel overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between border-b border-cyan-500/10 px-4 py-3">
        <div>
          <p className="font-mono text-[10px] tracking-[0.22em] text-cyan-400/70 uppercase">Residence 14 · 192.168.1.0/24</p>
          <h2 className="text-sm font-semibold text-white">Smart home</h2>
        </div>
        <span className="font-mono text-[11px] text-slate-400">
          {view.phase === 'after'
            ? 'Verified physical consequences'
            : view.phase === 'before'
              ? 'Before / after defense'
              : demoStage === 'normal' || demoStage === 'idle'
                ? 'Quiet occupancy'
                : 'Immune system engaged'}
        </span>
      </div>
      <div className="relative bg-[#070d16] p-4">
        <div className="pointer-events-none absolute inset-0 opacity-40 mesh-grid" />
        <div className="relative space-y-3">
          <CommunicationOverlay view={view} />
          <div className="grid min-h-[340px] grid-cols-2 grid-rows-[1.15fr_0.85fr] gap-3">
          {ROOMS.map((room) => (
            <div
              key={room.id}
              className={`${room.className} relative rounded-2xl border bg-white/[0.03] p-4 ${
                view.focused && room.id === 'entryway' ? 'border-cyan-400/40 consequence-room' : 'border-white/10'
              } ${meshIncident && room.id === 'entryway' ? 'ring-1 ring-rose-400/30' : ''}`}
            >
              <p className="font-mono text-[10px] tracking-[0.2em] text-slate-500 uppercase">{room.label}</p>
              <div className="mt-4 flex flex-wrap gap-3">
                {room.devices.map((id) => {
                  const sample = byId.get(id)
                  if (!sample) {
                    return (
                      <div key={id} className="rounded-xl border border-dashed border-white/10 px-3 py-2 text-xs text-slate-500">
                        Waiting for {id}
                      </div>
                    )
                  }
                  const finding = findingFor(findings, id)
                  const risk = finding?.risk_score ?? 0
                  const selected = selectedId === id
                  const response = responses.find((item) => item.device_id === id)
                  const state = containmentOf(
                    sample,
                    response?.response_state ?? finding?.response_state,
                  )
                  const affected = view.animateDevice && sample.device_id === view.deviceId
                  const linked = Boolean(meshIncident?.device_ids.includes(id))
                  return (
                    <button
                      key={id}
                      type="button"
                      onClick={() => setSelectedId(id)}
                      className={`min-w-[150px] rounded-xl border px-3 py-3 text-left transition ${nodeTone(sample, risk, state)} ${
                        selected ? 'ring-2 ring-white/70' : ''
                      } ${affected ? (view.phase === 'after' ? 'consequence-device-after' : 'consequence-device-before') : ''} ${
                        linked ? 'ring-1 ring-rose-300/50' : ''
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <Glyph type={sample.device_type} />
                        {sample.containment?.safe_mode || state === 'restricted' || state === 'quarantine' ? (
                          <Shield className="h-3.5 w-3.5" />
                        ) : null}
                      </div>
                      <p className="mt-2 text-sm font-semibold">{sample.name}</p>
                      {linked ? (
                        <p className="mt-1 font-mono text-[10px] tracking-wide text-rose-100 uppercase">Linked incident</p>
                      ) : null}
                      <p className="mt-1 font-mono text-[10px] opacity-80">
                        {pretty(state)} · risk {risk.toFixed(0)}
                      </p>
                      {sample.device_id === view.deviceId ? (
                        <p className="mt-1 font-mono text-[10px] text-slate-300">
                          Latch {view.latchLocked === false ? 'unlocked' : 'locked'}
                          {view.doorNeedsAttention ? ' · door ajar' : ''}
                        </p>
                      ) : null}
                      {sample.device_id === view.deviceId && view.doorNeedsAttention ? (
                        <span className="mt-2 inline-flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-0.5 font-mono text-[10px] tracking-wide text-amber-100 uppercase">
                          <DoorOpen className="h-3 w-3" />
                          Door ajar · needs attention
                        </span>
                      ) : null}
                      <div className="mt-2 h-1 overflow-hidden rounded-full bg-black/30">
                        <div className="h-full" style={{ width: `${Math.min(100, risk)}%`, background: riskColor(risk) }} />
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
          </div>
        </div>
      </div>
      <ConsequenceTable view={view} />
    </section>
  )
}

function CommunicationOverlay({ view }: { view: PhysicalConsequenceView }) {
  if (!view.animatePath) return null
  const blocked = view.communication.state === 'blocked'
  return (
    <div
      className={`flex items-center gap-3 rounded-xl border px-3 py-2 ${
        blocked ? 'border-emerald-400/30 bg-emerald-400/5' : 'border-rose-400/30 bg-rose-400/5'
      }`}
    >
      <div className="min-w-0">
        <p className={`font-mono text-[10px] tracking-[0.16em] uppercase ${blocked ? 'text-emerald-200/80' : 'text-rose-200/80'}`}>
          {blocked ? 'Path blocked' : 'Untrusted path'}
        </p>
        <p className="truncate font-mono text-[11px] text-slate-300">{view.communication.from}</p>
      </div>
      <svg viewBox="0 0 220 28" className="h-7 min-w-[120px] flex-1" aria-hidden="true">
        <line
          x1="8"
          y1="14"
          x2="212"
          y2="14"
          stroke={blocked ? '#34d399' : '#fb7185'}
          strokeWidth="2"
          strokeDasharray={blocked ? '5 7' : '6 10'}
          className={blocked ? 'path-blocked' : 'path-hostile'}
        />
        {blocked ? (
          <g>
            <circle cx="110" cy="14" r="8" fill="#08202b" stroke="#34d399" />
            <path d="M106 14 L114 14 M110 10 L110 18" stroke="#34d399" strokeWidth="1.6" />
          </g>
        ) : (
          <circle cx="110" cy="14" r="3.5" fill="#fb7185" className="path-hostile" />
        )}
      </svg>
      <p className="shrink-0 font-mono text-[11px] text-slate-200">{view.deviceName}</p>
    </div>
  )
}

function ConsequenceTable({ view }: { view: PhysicalConsequenceView }) {
  return (
    <div className="space-y-3 border-t border-cyan-500/10 px-4 py-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">Physical consequences</p>
          <p className="text-sm font-medium text-white">
            {view.verified ? 'After verified defense' : view.focused ? 'Before defense vs current sensors' : 'Baseline posture'}
          </p>
        </div>
        {view.doorNeedsAttention ? (
          <span className="inline-flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-1 font-mono text-[10px] tracking-wide text-amber-100 uppercase">
            <DoorOpen className="h-3 w-3" />
            Door ajar · independent sensor
          </span>
        ) : null}
      </div>
      <div className="overflow-hidden rounded-xl border border-white/10">
        <table className="w-full text-left text-sm">
          <thead className="bg-white/[0.03] font-mono text-[10px] tracking-[0.16em] text-slate-500 uppercase">
            <tr>
              <th className="px-3 py-2 font-medium">Observation</th>
              <th className="px-3 py-2 font-medium">Before defense</th>
              <th className="px-3 py-2 font-medium">After verified defense</th>
            </tr>
          </thead>
          <tbody>
            {view.rows.map((item) => (
              <tr key={item.id} className="border-t border-white/10">
                <td className="px-3 py-2 text-slate-200">{item.observation}</td>
                <td className={`px-3 py-2 font-medium ${toneClass(item.beforeTone)}`}>{item.before}</td>
                <td className={`px-3 py-2 font-medium ${toneClass(item.afterTone)}`}>
                  {view.phase === 'quiet' ? '—' : item.after}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs leading-relaxed text-slate-400">{view.scenarioAssessment}</p>
      {view.residualAttention ? (
        <p className="rounded-xl border border-amber-400/20 bg-amber-400/5 px-3 py-2 text-xs leading-relaxed text-amber-100">
          {view.residualAttention}
        </p>
      ) : null}
    </div>
  )
}
