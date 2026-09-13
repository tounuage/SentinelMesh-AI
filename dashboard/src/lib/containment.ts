import type {
  ActionOutcome,
  ActiveAttack,
  CommandRecord,
  DefensiveAction,
  IncidentStep,
  TelemetrySample,
  VerifiedContainment,
} from '../types'

const UNLOCK_COMMANDS = new Set(['unlock', 'remote_unlock'])

export function latencyMs(start?: string | null, end?: string | null): number | null {
  if (!start || !end) return null
  const from = Date.parse(start)
  const to = Date.parse(end)
  if (!Number.isFinite(from) || !Number.isFinite(to)) return null
  return Math.max(0, Math.round((to - from) * 10) / 10)
}

export function formatLatency(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

function isContained(state?: string | null): boolean {
  return state === 'restricted' || state === 'quarantine'
}

function hostileAccepted(commands: CommandRecord[]): CommandRecord | undefined {
  return commands.find((command) => !command.authorized && command.result !== 'denied_by_containment')
}

function deniedUnlock(commands: CommandRecord[]): CommandRecord | undefined {
  return commands.find(
    (command) =>
      command.result === 'denied_by_containment' &&
      (UNLOCK_COMMANDS.has(command.command) || !command.authorized),
  )
}

export function followUpDenied(sample: TelemetrySample | null | undefined): boolean {
  if (!sample) return false
  return Boolean(deniedUnlock(sample.command_history))
}

export function buildVerifiedContainment(
  sample: TelemetrySample,
  attack?: ActiveAttack | null,
  action?: DefensiveAction | null,
): VerifiedContainment {
  if (sample.verified_containment) return sample.verified_containment

  const commands = sample.command_history
  const detectedCmd = hostileAccepted(commands)
  const deniedCmd = deniedUnlock(commands)
  const report = sample.containment
  const detectedAt = report?.detected_at ?? detectedCmd?.timestamp ?? null
  const requestedAt = report?.requested_at ?? (action && isContained(action.response_state) ? action.timestamp : null)
  const acknowledgedAt = report?.applied_at ?? null
  const deniedAt = report?.first_denied_at ?? deniedCmd?.timestamp ?? null
  const state = report?.response_state ?? 'normal'
  const contained = isContained(state) || Boolean(report?.safe_mode)
  const lockKind = sample.device_type === 'smart_lock' || sample.device_id.includes('lock')
  const hostileName =
    lockKind || (detectedCmd && UNLOCK_COMMANDS.has(detectedCmd.command)) ? 'unlock' : 'command'
  const deniedName = lockKind || (deniedCmd && UNLOCK_COMMANDS.has(deniedCmd.command)) ? 'unlock' : 'command'
  const outcomes = outcomesFor(sample, action, contained, deniedCmd)
  const sequence: IncidentStep[] = [
    {
      id: 'detected',
      label: `Unauthorized ${hostileName} detected`,
      kind: 'observed',
      complete: Boolean(detectedAt),
      at: detectedAt,
      detail: detectedCmd
        ? `${detectedCmd.command} from ${detectedCmd.source_ip} was accepted without authorization.`
        : detectedAt
          ? 'Hostile remote unlock was observed on this device.'
          : 'Waiting for a hostile command on this device.',
    },
    {
      id: 'requested',
      label: 'Containment requested',
      kind: 'intended',
      complete: Boolean(requestedAt && (action || contained)),
      at: requestedAt,
      detail: action?.action ?? (contained ? `Policy requested ${state}.` : 'No defensive action has been issued yet.'),
    },
    {
      id: 'acknowledged',
      label: 'Simulator acknowledged',
      kind: 'observed',
      complete: Boolean(acknowledgedAt && contained),
      at: contained ? acknowledgedAt : null,
      detail: contained
        ? `Enforcement plane entered ${state}; safe mode=${report?.safe_mode ? 'on' : 'off'}.`
        : 'Simulator has not applied a blocking policy yet.',
    },
    {
      id: 'denied',
      label: `Next ${deniedName} attempt: DENIED`,
      kind: 'observed',
      complete: Boolean(deniedAt && deniedCmd),
      at: deniedAt,
      detail: deniedCmd
        ? `${deniedCmd.command} from ${deniedCmd.source_ip} returned ${deniedCmd.result}.`
        : 'Keep the attack running to prove the next attempt is blocked.',
    },
  ]

  return {
    device_id: sample.device_id,
    verified: sequence.every((step) => step.complete),
    detection_latency_ms: latencyMs(attack?.started_at, detectedAt),
    containment_latency_ms: latencyMs(detectedAt, deniedAt ?? acknowledgedAt),
    intended: outcomes.map((item) => `${item.label}: ${item.intended}`),
    observed: outcomes.map((item) => `${item.label}: ${item.observed}`),
    outcomes,
    sequence,
  }
}

function outcomesFor(
  sample: TelemetrySample,
  action: DefensiveAction | null | undefined,
  contained: boolean,
  deniedCmd: CommandRecord | undefined,
): ActionOutcome[] {
  const report = sample.containment
  const intendedState =
    action && isContained(action.response_state)
      ? action.response_state
      : contained
        ? (report?.response_state ?? 'restricted')
        : 'restricted'
  const locked = sample.sensors.locked
  const remoteUnlock = sample.sensors.remote_unlock_enabled
  const outcomes: ActionOutcome[] = [
    {
      label: 'Containment state',
      intended: intendedState,
      observed: report?.response_state ?? 'normal',
      matched: contained && (!action || report?.response_state === intendedState),
    },
    {
      label: 'Door lock',
      intended: 'forced shut',
      observed: locked === true ? 'locked' : 'unlocked',
      matched: locked === true,
    },
    {
      label: 'Remote unlock',
      intended: 'revoked',
      observed: remoteUnlock === false || contained ? 'disabled' : 'enabled',
      matched: contained && remoteUnlock !== true,
    },
    {
      label: 'Follow-up command',
      intended: 'DENIED',
      observed: deniedCmd ? deniedCmd.result.replaceAll('_', ' ').toUpperCase() : 'still allowed / not attempted',
      matched: Boolean(deniedCmd),
    },
  ]
  if (sample.device_type !== 'smart_lock' && !sample.device_id.includes('lock') && locked == null) {
    return outcomes.filter((item) => item.label !== 'Door lock' && item.label !== 'Remote unlock')
  }
  return outcomes
}

export function emptyContainment(deviceId = 'lock-front-door'): VerifiedContainment {
  return {
    device_id: deviceId,
    verified: false,
    detection_latency_ms: null,
    containment_latency_ms: null,
    intended: [],
    observed: [],
    outcomes: [],
    sequence: [
      { id: 'detected', label: 'Unauthorized unlock detected', kind: 'observed', complete: false },
      { id: 'requested', label: 'Containment requested', kind: 'intended', complete: false },
      { id: 'acknowledged', label: 'Simulator acknowledged', kind: 'observed', complete: false },
      { id: 'denied', label: 'Next unlock attempt: DENIED', kind: 'observed', complete: false },
    ],
  }
}
