import { Flame } from 'lucide-react'
import { Chip, Panel } from './Panel'
import { useSoc } from '../hooks/useDashboard'
import { pretty, riskColor } from '../lib/format'

export function PhysicalRiskPanel() {
  const { selectedSample, selectedFinding } = useSoc()
  const physical = selectedFinding?.physical
  const score = physical?.score ?? 0

  return (
    <Panel
      eyebrow="Cyber-physical"
      title="Scenario assessment"
      icon={<Flame className="h-4 w-4 text-orange-300" />}
      action={
        <Chip className={score >= 55 ? 'border-rose-400/40 text-rose-200' : 'border-emerald-400/30 text-emerald-200'}>
          {physical?.severity ?? 'none'}
        </Chip>
      }
    >
      {!selectedSample || !physical ? (
        <p className="text-sm text-slate-400">Select a device to forecast what a compromise would do in the house.</p>
      ) : (
        <div className="space-y-3">
          <div className="flex items-end justify-between">
            <div>
              <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">Hazard</p>
              <p className="mt-1 text-sm font-semibold text-white">{pretty(physical.hazard)}</p>
            </div>
            <p className="font-mono text-2xl" style={{ color: riskColor(score) }}>
              {score.toFixed(0)}
            </p>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-500">
            Possible harm is a scenario assessment from cyber evidence and sensors, not a proven outcome such as
            “intrusion prevented.”
          </p>
          <ul className="space-y-1.5 text-sm leading-relaxed text-slate-300">
            {physical.consequences.map((item) => (
              <li key={item} className="flex gap-2">
                <span className="text-orange-300">›</span>
                {item}
              </li>
            ))}
          </ul>
          <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3">
            <p className="font-mono text-[10px] tracking-[0.18em] text-amber-200/80 uppercase">Safe operating mode</p>
            <p className="mt-1 text-sm text-amber-50">{physical.safe_mode}</p>
          </div>
        </div>
      )}
    </Panel>
  )
}
