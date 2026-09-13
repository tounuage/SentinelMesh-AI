import type { ActiveAttack, TelemetrySample } from '../types'

export type ReadinessFlags = {
  simulator: boolean
  modelsReady: boolean
  controllerActive: boolean
  scenarioClean: boolean
}

export const READINESS_ITEMS = [
  { key: 'simulator', label: 'Simulator' },
  { key: 'modelsReady', label: 'Models ready' },
  { key: 'controllerActive', label: 'Controller active' },
  { key: 'scenarioClean', label: 'Scenario clean' },
] as const satisfies readonly { key: keyof ReadinessFlags; label: string }[]

export function isScenarioClean(samples: TelemetrySample[], attacks: ActiveAttack[]): boolean {
  return (
    attacks.length === 0 &&
    samples.length > 0 &&
    samples.every(
      (sample) =>
        sample.command_history.every((command) => command.authorized) &&
        sample.firmware_signed &&
        sample.attack_signals.length === 0 &&
        (sample.containment?.response_state ?? 'normal') === 'normal',
    )
  )
}

export function readinessMark(ok: boolean): '✓' | '—' {
  return ok ? '✓' : '—'
}

export function readinessLine(flags: ReadinessFlags): string {
  return READINESS_ITEMS.map((item) => `${item.label} ${readinessMark(flags[item.key])}`).join('   ')
}
