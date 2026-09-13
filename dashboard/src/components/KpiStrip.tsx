import { Radio, ShieldAlert, ShieldCheck, Sparkles } from 'lucide-react'
import { useSoc } from '../hooks/useDashboard'
import { containmentOf, riskTone } from '../lib/format'

export function KpiStrip() {
  const { samples, findings, attacks } = useSoc()
  const online = samples.filter((sample) => sample.status === 'online').length
  const threats = findings.filter((finding) => finding.threat_type !== 'benign' && finding.risk_score >= 20).length
  const avg =
    findings.length === 0 ? 0 : findings.reduce((sum, item) => sum + item.risk_score, 0) / findings.length
  const contained = samples.filter((sample) => containmentOf(sample) !== 'normal').length
  const verified = samples.some((sample) => sample.verified_containment?.verified)

  const cards = [
    { label: 'IoT devices', value: String(samples.length), hint: `${online} healthy`, icon: Radio },
    { label: 'Active threats', value: String(threats), hint: `${attacks.length} injected campaigns`, icon: ShieldAlert },
    {
      label: 'Fleet risk',
      value: avg.toFixed(1),
      hint: riskTone(avg) === 'ok' ? 'within baseline' : 'elevated',
      icon: Sparkles,
    },
    {
      label: 'Contained',
      value: String(contained),
      hint: verified ? 'next unlock denied' : 'monitor / restrict / quarantine',
      icon: ShieldCheck,
    },
  ]

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <div key={card.label} className="panel rounded-2xl px-4 py-3">
          <div className="flex items-start justify-between">
            <div>
              <p className="font-mono text-[10px] tracking-[0.2em] text-cyan-400/70 uppercase">{card.label}</p>
              <p className="mt-1 text-2xl font-semibold text-white">{card.value}</p>
              <p className="mt-1 text-xs text-slate-400">{card.hint}</p>
            </div>
            <card.icon className="h-4 w-4 text-cyan-300/80" />
          </div>
        </div>
      ))}
    </div>
  )
}
