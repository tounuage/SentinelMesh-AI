import { ArrowDown, ShieldCheck } from 'lucide-react'
import { Chip, Panel, Pill } from './Panel'
import { useSoc } from '../hooks/useDashboard'
import { buildVerifiedContainment, emptyContainment, formatLatency } from '../lib/containment'
import { formatClock } from '../lib/labels'

export function VerifiedContainmentPanel() {
  const { selectedSample, selectedResponse, attacks } = useSoc()
  const attack = attacks.find((item) => item.device_id === selectedSample?.device_id) ?? attacks[0] ?? null
  const evidence = selectedSample
    ? buildVerifiedContainment(selectedSample, attack, selectedResponse?.last_action)
    : emptyContainment()
  const completeCount = evidence.sequence.filter((step) => step.complete).length

  return (
    <Panel
      eyebrow="Proof of defense"
      title="Verified containment"
      icon={<ShieldCheck className="h-4 w-4 text-emerald-300" />}
      action={
        <Chip
          className={
            evidence.verified
              ? 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
              : 'border-amber-400/30 bg-amber-400/10 text-amber-100'
          }
        >
          {evidence.verified ? 'behavior changed' : 'score is not proof'}
        </Chip>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-2">
          <LatencyCard label="Detection latency" value={formatLatency(evidence.detection_latency_ms)} />
          <LatencyCard label="Containment latency" value={formatLatency(evidence.containment_latency_ms)} />
        </div>
        <ol className="space-y-0">
          {evidence.sequence.map((step, index) => (
            <li key={step.id}>
              <div
                className={`rounded-xl border px-3 py-2.5 ${
                  step.complete ? 'border-cyan-400/30 bg-cyan-400/5' : 'border-white/10 bg-white/[0.03]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <p className={`text-sm font-medium ${step.complete ? 'text-white' : 'text-slate-400'}`}>
                    {step.label}
                  </p>
                  <Pill tone={step.kind === 'intended' ? 'watch' : step.complete ? 'ok' : 'neutral'}>
                    {step.kind}
                  </Pill>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">{step.detail}</p>
                <p className="mt-1 font-mono text-[10px] text-slate-500">
                  {step.at ? formatClock(step.at) : 'pending'}
                </p>
              </div>
              {index < evidence.sequence.length - 1 ? (
                <div className="flex justify-center py-1 text-cyan-500/70">
                  <ArrowDown className={`h-4 w-4 ${step.complete ? 'opacity-100' : 'opacity-30'}`} />
                </div>
              ) : null}
            </li>
          ))}
        </ol>
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="rounded-xl border border-cyan-500/15 bg-black/20 p-3">
            <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">Intended actions</p>
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {evidence.intended.length ? (
                evidence.intended.map((item) => (
                  <li key={item} className="flex gap-2">
                    <span className="text-cyan-400">›</span>
                    {item}
                  </li>
                ))
              ) : (
                <li className="text-slate-500">Policy has not requested a blocking action yet.</li>
              )}
            </ul>
          </div>
          <div className="rounded-xl border border-emerald-500/15 bg-black/20 p-3">
            <p className="font-mono text-[10px] tracking-[0.18em] text-emerald-300/80 uppercase">Observed outcomes</p>
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {evidence.outcomes.length ? (
                evidence.outcomes.map((item) => (
                  <li key={item.label} className="flex items-start justify-between gap-3">
                    <span>
                      <span className="text-emerald-300">›</span> {item.label}: {item.observed}
                    </span>
                    <span className={`font-mono text-[10px] ${item.matched ? 'text-emerald-300' : 'text-amber-300'}`}>
                      {item.matched ? 'match' : 'gap'}
                    </span>
                  </li>
                ))
              ) : (
                <li className="text-slate-500">No enforcement outcome yet. A red score is not containment.</li>
              )}
            </ul>
          </div>
        </div>
        <p className="text-xs leading-relaxed text-slate-500">
          {evidence.verified
            ? `Verified ${completeCount}/4 steps. The lock changed behavior: the next hostile unlock was denied.`
            : 'Containment is verified only after the simulator acknowledges policy and a follow-up unlock is denied.'}
        </p>
      </div>
    </Panel>
  )
}

function LatencyCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2">
      <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">{label}</p>
      <p className="mt-1 font-mono text-lg text-white">{value}</p>
    </div>
  )
}
