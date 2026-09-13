import { Bell } from 'lucide-react'
import { ATTACK_LABEL, relativeTime, threatLabel } from '../lib/labels'
import { useSoc } from '../hooks/useDashboard'
import { Panel, Pill } from './Panel'

export function AlertFeed() {
  const model = useSoc()
  const alerts = buildAlerts(model)

  return (
    <Panel eyebrow="Detections" title="Threat alerts" icon={<Bell className="h-4 w-4" />} className="min-h-[280px]">
      <div className="max-h-[280px] space-y-2 overflow-y-auto pr-1">
        {alerts.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/10 px-3 py-8 text-center text-sm text-slate-500">
            No active threat alerts. The home is quiet.
          </div>
        ) : (
          alerts.map((alert) => (
            <button
              key={alert.id}
              type="button"
              onClick={() => model.setSelectedId(alert.deviceId)}
              className={`w-full rounded-xl border px-3 py-2.5 text-left ${
                alert.mesh
                  ? 'border-rose-400/40 bg-rose-500/10 hover:border-rose-300/60'
                  : 'border-white/10 bg-white/[0.03] hover:border-rose-400/40'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium text-slate-100">{alert.title}</p>
                <Pill tone={alert.tone}>{alert.severity}</Pill>
              </div>
              <p className="mt-1 line-clamp-2 text-xs text-slate-400">{alert.detail}</p>
              <p className="mt-1 font-mono text-[10px] tracking-wider text-slate-500 uppercase">
                {alert.deviceName} · {relativeTime(alert.at)}
              </p>
            </button>
          ))
        )}
      </div>
    </Panel>
  )
}

function buildAlerts(model: ReturnType<typeof useSoc>) {
  const names = new Map((model.snapshot?.devices ?? []).map((device) => [device.device_id, device.name]))
  const items: {
    id: string
    deviceId: string
    deviceName: string
    title: string
    detail: string
    at: string
    severity: string
    tone: 'watch' | 'high' | 'critical'
    mesh?: boolean
  }[] = []

  if (model.meshIncident) {
    const linked = model.meshIncident.device_ids
      .map((deviceId) => names.get(deviceId) ?? deviceId)
      .join(' + ')
    items.push({
      id: model.meshIncident.id,
      deviceId: model.meshIncident.device_ids[1] ?? model.meshIncident.device_ids[0],
      deviceName: linked,
      title: model.meshIncident.title,
      detail: model.meshIncident.detail,
      at: model.meshIncident.observed_at,
      severity: 'mesh',
      tone: 'critical',
      mesh: true,
    })
  }

  for (const attack of model.attacks) {
    items.push({
      id: `atk-${attack.attack_id}`,
      deviceId: attack.device_id,
      deviceName: names.get(attack.device_id) ?? attack.device_id,
      title: ATTACK_LABEL[attack.attack_type],
      detail: `Injected ${attack.intensity} intensity attack is still live on the mesh.`,
      at: attack.started_at,
      severity: attack.intensity,
      tone: attack.intensity === 'high' ? 'critical' : 'high',
    })
  }

  for (const finding of model.findings) {
    if (finding.threat_type === 'benign' && finding.risk_score < 20) continue
    items.push({
      id: `find-${finding.device}`,
      deviceId: finding.device,
      deviceName: names.get(finding.device) ?? finding.device,
      title: threatLabel(finding.threat_type),
      detail: finding.explanation,
      at: model.snapshot?.generated_at ?? new Date().toISOString(),
      severity: `risk ${finding.risk_score.toFixed(0)}`,
      tone: finding.risk_score >= 75 ? 'critical' : finding.risk_score >= 45 ? 'high' : 'watch',
    })
  }

  return items.slice(0, 10)
}
