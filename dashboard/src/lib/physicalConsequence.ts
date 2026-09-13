import type { CommandRecord, NetworkConnection, TelemetrySample, VerifiedContainment } from '../types'

const UNLOCK_COMMANDS = new Set(['unlock', 'remote_unlock'])
const WAN_HINT = /^(203\.0\.113\.|198\.51\.100\.)/

export type ConsequenceTone = 'hostile' | 'contained' | 'attention' | 'quiet' | 'pending'

export type ConsequenceRowId = 'remote_unlock' | 'latch' | 'untrusted_communication'

export type ConsequenceRow = {
  id: ConsequenceRowId
  observation: string
  before: string
  after: string
  beforeTone: ConsequenceTone
  afterTone: ConsequenceTone
}

export type CommunicationPath = {
  from: string
  to: string
  state: 'idle' | 'hostile' | 'blocked'
}

export type PhysicalConsequenceView = {
  deviceId: string
  deviceName: string
  focused: boolean
  phase: 'quiet' | 'before' | 'after'
  verified: boolean
  rows: ConsequenceRow[]
  latchLocked: boolean | null
  doorAjar: boolean
  doorNeedsAttention: boolean
  communication: CommunicationPath
  animateDevice: boolean
  animatePath: boolean
  scenarioAssessment: string
  residualAttention: string | null
}

function isUnlock(command: CommandRecord): boolean {
  return UNLOCK_COMMANDS.has(command.command)
}

function isWan(ip: string): boolean {
  return WAN_HINT.test(ip) || (!ip.startsWith('192.168.') && !ip.startsWith('10.') && ip !== '127.0.0.1')
}

function hostileAccepted(commands: CommandRecord[]): CommandRecord | undefined {
  return commands.find(
    (command) => !command.authorized && command.result !== 'denied_by_containment' && isUnlock(command),
  )
}

function deniedUnlock(commands: CommandRecord[]): CommandRecord | undefined {
  return commands.find(
    (command) =>
      command.result === 'denied_by_containment' && (isUnlock(command) || !command.authorized),
  )
}

function suspiciousLinks(sample: TelemetrySample): NetworkConnection[] {
  return sample.network.active_connections.filter(
    (connection) =>
      connection.reputation === 'suspicious' || (connection.reputation !== 'trusted' && isWan(connection.remote_ip)),
  )
}

function untrustedPeer(sample: TelemetrySample): string {
  const live = suspiciousLinks(sample)[0]?.remote_ip
  if (live) return live
  const command = [...sample.command_history]
    .reverse()
    .find((item) => !item.authorized && isWan(item.source_ip))
  return command?.source_ip ?? 'untrusted WAN'
}

function isContained(sample: TelemetrySample): boolean {
  const state = sample.containment?.response_state
  return state === 'restricted' || state === 'quarantine' || Boolean(sample.containment?.safe_mode)
}

function untrustedBlocked(sample: TelemetrySample): boolean {
  const report = sample.containment
  if (!report || !isContained(sample) || suspiciousLinks(sample).length > 0) return false
  const mode = report.network_mode
  return report.isolated || mode === 'trusted_only' || mode === 'full_isolation' || report.blocked_ips.length > 0
}

function latchState(sample: TelemetrySample): boolean | null {
  const locked = sample.sensors.locked
  if (typeof locked === 'boolean') return locked
  return null
}

function doorAjar(sample: TelemetrySample): boolean {
  return sample.sensors.door_ajar === true
}

export function isUnsupportedHarmClaim(text: string): boolean {
  return /intrusion prevented|break-?in stopped|attacker kept out|entry prevented/i.test(text)
}

function assessment(input: {
  phase: 'quiet' | 'before' | 'after'
  verified: boolean
  doorAjar: boolean
  latchLocked: boolean | null
}): { scenarioAssessment: string; residualAttention: string | null } {
  if (input.phase === 'quiet') {
    return {
      scenarioAssessment:
        'Possible harm is a scenario assessment. No hostile actuation is in evidence on this tick.',
      residualAttention: input.doorAjar
        ? 'The door sensor reports ajar and still needs attention, independent of cyber state.'
        : null,
    }
  }
  if (input.phase === 'before') {
    return {
      scenarioAssessment:
        'Scenario assessment: a hostile remote unlock can admit a person if the latch is open. This is a forecast from observed commands and sensors, not a confirmed intrusion.',
      residualAttention: input.doorAjar
        ? 'The door sensor reports ajar. Physical attention is required even before defense is verified.'
        : null,
    }
  }
  if (input.doorAjar) {
    return {
      scenarioAssessment:
        'Verified defense changed cyber behavior: remote unlock denied, latch commanded locked, untrusted communication blocked. The door sensor still reports ajar, so physical attention is still required.',
      residualAttention:
        'Latch control is not a door closer. The leaf remaining ajar is independent sensor truth, not proof that an intrusion was prevented.',
    }
  }
  return {
    scenarioAssessment:
      input.latchLocked === true
        ? 'Verified defense changed device behavior: remote unlock denied, latch locked, untrusted communication blocked. Physical entry remains a scenario assessment; sensors do not prove an intrusion occurred or was prevented.'
        : 'Verified defense blocked the cyber channel. Latch state is still unlocked, so possible physical harm remains an open scenario assessment.',
    residualAttention: input.latchLocked === false ? 'The latch sensor still reports unlocked.' : null,
  }
}

export function emptyPhysicalConsequence(deviceId = 'lock-front-door'): PhysicalConsequenceView {
  return {
    deviceId,
    deviceName: 'Front Door Lock',
    focused: false,
    phase: 'quiet',
    verified: false,
    rows: [
      {
        id: 'remote_unlock',
        observation: 'Remote unlock',
        before: 'Idle',
        after: '—',
        beforeTone: 'quiet',
        afterTone: 'pending',
      },
      {
        id: 'latch',
        observation: 'Latch',
        before: 'Locked',
        after: '—',
        beforeTone: 'quiet',
        afterTone: 'pending',
      },
      {
        id: 'untrusted_communication',
        observation: 'Untrusted communication',
        before: 'None observed',
        after: '—',
        beforeTone: 'quiet',
        afterTone: 'pending',
      },
    ],
    latchLocked: true,
    doorAjar: false,
    doorNeedsAttention: false,
    communication: { from: 'untrusted WAN', to: deviceId, state: 'idle' },
    animateDevice: false,
    animatePath: false,
    scenarioAssessment:
      'Possible harm is a scenario assessment. No hostile actuation is in evidence on this tick.',
    residualAttention: null,
  }
}

export function buildPhysicalConsequence(
  sample?: TelemetrySample | null,
  evidence?: VerifiedContainment | null,
): PhysicalConsequenceView {
  if (!sample) return emptyPhysicalConsequence()

  const verifiedEvidence = evidence ?? sample.verified_containment ?? null
  const accepted = hostileAccepted(sample.command_history)
  const denied = deniedUnlock(sample.command_history)
  const contained = isContained(sample)
  const verified = contained && (Boolean(verifiedEvidence?.verified) || Boolean(denied))
  const detected = Boolean(verifiedEvidence?.sequence.find((step) => step.id === 'detected' && step.complete))
  const locked = latchState(sample)
  const ajar = doorAjar(sample)
  const peer = untrustedPeer(sample)
  const hostile =
    Boolean(accepted) ||
    Boolean(denied) ||
    detected ||
    sample.attack_signals.includes('unauthorized_commands')
  const blocked = untrustedBlocked(sample)
  const phase: PhysicalConsequenceView['phase'] = verified ? 'after' : hostile || contained ? 'before' : 'quiet'
  const priorUnlock = Boolean(accepted) || verified || Boolean(denied) || detected
  const afterUnlock = verified && denied ? 'Denied' : denied ? 'Denied (unverified)' : contained ? 'Pending retry' : '—'
  const afterLatch =
    verified && locked === true ? 'Locked' : locked === true ? 'Locked (sensor)' : locked === false ? 'Unlocked' : '—'
  const afterComms =
    verified && blocked ? 'Blocked' : blocked ? 'Blocked (sensor)' : suspiciousLinks(sample).length || accepted ? 'Allowed' : '—'

  const rows: ConsequenceRow[] = [
    {
      id: 'remote_unlock',
      observation: 'Remote unlock',
      before: priorUnlock ? 'Accepted' : hostile ? 'Attempted' : 'Idle',
      after: phase === 'quiet' ? 'Idle' : afterUnlock,
      beforeTone: priorUnlock ? 'hostile' : 'quiet',
      afterTone: verified && denied ? 'contained' : phase === 'quiet' ? 'quiet' : 'pending',
    },
    {
      id: 'latch',
      observation: 'Latch',
      before: priorUnlock || locked === false ? 'Unlocked' : 'Locked',
      after: phase === 'quiet' ? (locked === false ? 'Unlocked' : 'Locked') : afterLatch,
      beforeTone: priorUnlock || locked === false ? 'hostile' : 'quiet',
      afterTone:
        locked === false
          ? 'attention'
          : verified && locked === true
            ? 'contained'
            : phase === 'quiet'
              ? 'quiet'
              : 'pending',
    },
    {
      id: 'untrusted_communication',
      observation: 'Untrusted communication',
      before: priorUnlock || suspiciousLinks(sample).length > 0 || hostile ? 'Allowed' : 'None observed',
      after: phase === 'quiet' ? 'None observed' : afterComms,
      beforeTone: priorUnlock || suspiciousLinks(sample).length > 0 || hostile ? 'hostile' : 'quiet',
      afterTone: verified && blocked ? 'contained' : phase === 'quiet' ? 'quiet' : 'pending',
    },
  ]

  const copy = assessment({ phase, verified, doorAjar: ajar, latchLocked: locked })
  const view: PhysicalConsequenceView = {
    deviceId: sample.device_id,
    deviceName: sample.name,
    focused: phase !== 'quiet',
    phase,
    verified,
    rows,
    latchLocked: locked,
    doorAjar: ajar,
    doorNeedsAttention: ajar,
    communication: {
      from: peer,
      to: sample.device_id,
      state: phase === 'quiet' ? 'idle' : blocked ? 'blocked' : 'hostile',
    },
    animateDevice: phase !== 'quiet',
    animatePath: phase !== 'quiet',
    scenarioAssessment: copy.scenarioAssessment,
    residualAttention: copy.residualAttention,
  }

  if (isUnsupportedHarmClaim(view.scenarioAssessment) || (view.residualAttention && isUnsupportedHarmClaim(view.residualAttention))) {
    view.scenarioAssessment =
      'Scenario assessment only. Observed cyber changes are listed separately from independent physical sensors.'
  }
  return view
}

export function consequenceDevice(samples: TelemetrySample[]): TelemetrySample | undefined {
  return samples.find((sample) => sample.device_id === 'lock-front-door') ?? samples.find((sample) => sample.device_type === 'smart_lock')
}
