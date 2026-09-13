import type { DemoStage } from '../types'
import { useSoc } from '../hooks/useDashboard'
import { ReadinessStrip } from './ReadinessStrip'

const STAGES: { id: DemoStage; n: string; label: string }[] = [
  { id: 'normal', n: '01', label: 'Normal home' },
  { id: 'attack', n: '02', label: 'Attack' },
  { id: 'detect', n: '03', label: 'AI detection' },
  { id: 'explain', n: '04', label: 'Explainable risk' },
  { id: 'respond', n: '05', label: 'Safe mode' },
  { id: 'recover', n: '06', label: 'Recovery' },
]

const ORDER: DemoStage[] = STAGES.map((stage) => stage.id)

function rank(stage: DemoStage) {
  if (stage === 'idle') return -1
  if (stage === 'complete') return ORDER.length
  return ORDER.indexOf(stage)
}

export function DemoRail() {
  const {
    demoStage,
    demoNote,
    demoRunning,
    modelsReady,
    simHealthy,
    controllerActive,
    scenarioClean,
  } = useSoc()
  const current = rank(demoStage)

  return (
    <section className="panel overflow-hidden rounded-2xl">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-cyan-500/10 px-4 py-3">
        <div>
          <p className="font-mono text-[10px] tracking-[0.22em] text-cyan-400/70 uppercase">Immune cycle</p>
          <h2 className="text-sm font-semibold text-white">
            {demoStage === 'complete' ? 'Home restored' : demoRunning ? 'Live demonstration' : 'Six-step product demo'}
          </h2>
        </div>
        <p className="max-w-xl text-right text-xs leading-relaxed text-slate-400">{demoNote}</p>
      </div>
      <ReadinessStrip
        simulator={simHealthy}
        modelsReady={modelsReady}
        controllerActive={controllerActive}
        scenarioClean={scenarioClean}
      />
      <ol className="grid grid-cols-2 gap-0 sm:grid-cols-3 xl:grid-cols-6">
        {STAGES.map((stage, index) => {
          const active = demoStage === stage.id || (demoStage === 'complete' && index === STAGES.length - 1)
          const done = current > index
          return (
            <li
              key={stage.id}
              className={`border-cyan-500/10 px-4 py-3 ${index < STAGES.length - 1 ? 'border-r' : ''} ${
                active ? 'bg-cyan-400/10' : done ? 'bg-emerald-400/5' : ''
              }`}
            >
              <p className={`font-mono text-[10px] tracking-[0.18em] uppercase ${active ? 'text-cyan-200' : 'text-slate-500'}`}>
                {stage.n}
              </p>
              <p className={`mt-1 text-sm font-medium ${active ? 'text-white' : done ? 'text-emerald-200' : 'text-slate-400'}`}>
                {stage.label}
              </p>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
