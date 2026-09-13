import { Gauge } from 'lucide-react'
import { riskColor, riskTone, threatLabel } from '../lib/labels'
import { useSoc } from '../hooks/useDashboard'
import { Panel, Pill } from './Panel'

export function RiskPanel() {
  const model = useSoc()
  return (
    <Panel eyebrow="Scoring" title="Risk scores" icon={<Gauge className="h-4 w-4" />}>
      <div className="space-y-3">
        {model.findings.map((finding) => {
          const sample = model.snapshot?.devices.find((device) => device.device_id === finding.device)
          const history = model.riskHistory[finding.device] ?? [finding.risk_score]
          const selected = model.selectedId === finding.device
          return (
            <button
              key={finding.device}
              type="button"
              onClick={() => model.setSelectedId(finding.device)}
              className={`flex w-full items-center gap-3 rounded-xl border px-3 py-2 text-left ${
                selected ? 'border-cyan-400/50 bg-cyan-400/5' : 'border-white/10 bg-white/[0.03]'
              }`}
            >
              <RiskDial score={finding.risk_score} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <p className="truncate text-sm text-white">{sample?.name ?? finding.device}</p>
                  <Pill tone={riskTone(finding.risk_score)}>{threatLabel(finding.threat_type)}</Pill>
                </div>
                <Sparkline values={history} color={riskColor(finding.risk_score)} />
              </div>
            </button>
          )
        })}
        {model.findings.length === 0 && (
          <p className="text-sm text-slate-500">Risk scores appear after the first analyzed tick.</p>
        )}
      </div>
    </Panel>
  )
}

function RiskDial({ score }: { score: number }) {
  const radius = 18
  const circ = 2 * Math.PI * radius
  const offset = circ - (Math.min(100, score) / 100) * circ
  const color = riskColor(score)
  return (
    <svg width="52" height="52" viewBox="0 0 52 52" className="shrink-0">
      <circle cx="26" cy="26" r={radius} fill="none" stroke="#1b334c" strokeWidth="5" />
      <circle
        cx="26"
        cy="26"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="5"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 26 26)"
      />
      <text x="26" y="30" textAnchor="middle" fill={color} fontSize="11" fontFamily="IBM Plex Mono">
        {score.toFixed(0)}
      </text>
    </svg>
  )
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  if (values.length < 2) return <div className="mt-2 h-8" />
  const max = Math.max(100, ...values)
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 160
      const y = 28 - (value / max) * 24
      return `${x},${y}`
    })
    .join(' ')
  return (
    <svg viewBox="0 0 160 32" className="mt-2 h-8 w-full">
      <polyline fill="none" stroke={color} strokeWidth="1.6" points={points} />
    </svg>
  )
}
