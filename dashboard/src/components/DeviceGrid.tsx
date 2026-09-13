import { Camera, Lock, Plug, Thermometer } from 'lucide-react'
import type { DeviceType } from '../types'
import { formatBytes, prettyRoom, responseTone, riskColor, riskTone, STATUS_LABEL, statusTone } from '../lib/labels'
import { containmentOf } from '../lib/format'
import { useSoc } from '../hooks/useDashboard'
import { Panel, Pill } from './Panel'

const ICONS: Record<DeviceType, typeof Camera> = {
  smart_camera: Camera,
  smart_lock: Lock,
  smart_plug: Plug,
  smart_thermostat: Thermometer,
}

export function DeviceGrid() {
  const model = useSoc()
  const devices = model.snapshot?.devices ?? []
  return (
    <Panel eyebrow="Inventory" title="IoT device overview">
      <div className="grid gap-3 md:grid-cols-2">
        {devices.map((device) => {
          const finding = model.findings.find((item) => item.device === device.device_id)
          const score = finding?.risk_score ?? 0
          const selected = model.selectedId === device.device_id
          const Icon = ICONS[device.device_type]
          const containment = containmentOf(device)
          return (
            <button
              key={device.device_id}
              type="button"
              onClick={() => model.setSelectedId(device.device_id)}
              className={`rounded-xl border p-3 text-left transition ${
                selected ? 'border-cyan-400/60 bg-cyan-400/5' : 'border-white/10 bg-white/[0.03] hover:border-cyan-400/30'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="grid h-8 w-8 place-items-center rounded-md border border-white/10 bg-[#09111c] text-cyan-300">
                    <Icon className="h-4 w-4" />
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-white">{device.name}</p>
                    <p className="font-mono text-[10px] text-slate-500">{device.device_id}</p>
                  </div>
                </div>
                <Pill tone={riskTone(score)}>{score.toFixed(0)}</Pill>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                <div>
                  Status <span className={statusTone(device.status)}>{STATUS_LABEL[device.status]}</span>
                </div>
                <div>
                  Response <span className={responseTone(containment)}>{containment}</span>
                </div>
                <div>{prettyRoom(device.room)}</div>
                <div>{device.network.local_ip}</div>
                <div>{device.power.watts.toFixed(1)} W</div>
                <div>
                  fw {device.firmware_version}
                  {device.firmware_signed ? '' : ' !'}
                </div>
                <div>{formatBytes(device.network.bytes_sent)} ↑</div>
                <div>{device.network.active_connections.length} peers</div>
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${Math.min(100, score)}%`, background: riskColor(score) }}
                />
              </div>
            </button>
          )
        })}
      </div>
    </Panel>
  )
}
