import assert from 'node:assert/strict'
import test from 'node:test'
import { buildVerifiedContainment } from './containment.ts'
import {
  buildPhysicalConsequence,
  emptyPhysicalConsequence,
  isUnsupportedHarmClaim,
} from './physicalConsequence.ts'
import type { ActiveAttack, CommandRecord, DefensiveAction, TelemetrySample } from '../types'

function command(overrides: Partial<CommandRecord> = {}): CommandRecord {
  return {
    timestamp: '2026-09-14T12:00:02.000Z',
    command: 'unlock',
    actor: 'unknown_session',
    source_ip: '203.0.113.66',
    authorized: false,
    result: 'accepted_without_authz',
    ...overrides,
  }
}

function sample(overrides: Partial<TelemetrySample> = {}): TelemetrySample {
  return {
    timestamp: '2026-09-14T12:00:04.000Z',
    device_id: 'lock-front-door',
    device_type: 'smart_lock',
    name: 'Front Door Lock',
    room: 'entryway',
    status: 'restricted',
    firmware_version: '3.2.8',
    firmware_signed: true,
    firmware_checksum: 'abc',
    network: {
      interface: 'wlan0',
      local_ip: '192.168.1.55',
      mac_address: '3c:22:fb:10:a1:04',
      bytes_sent: 1,
      bytes_recv: 1,
      packets_sent: 1,
      packets_recv: 1,
      active_connections: [],
      dns_queries: [],
      unusual_ports: [],
    },
    power: {
      watts: 1,
      voltage: 120,
      current_amps: 0.01,
      energy_wh: 1,
      baseline_watts: 1,
      deviation_percent: 0,
    },
    sensors: { locked: true, remote_unlock_enabled: false, door_ajar: false },
    command_history: [
      command(),
      command({ timestamp: '2026-09-14T12:00:04.000Z', result: 'denied_by_containment' }),
    ],
    anomaly_indicators: [],
    attack_signals: ['unauthorized_commands'],
    containment: {
      response_state: 'restricted',
      isolated: false,
      safe_mode: true,
      extra_telemetry: true,
      blocked_ips: ['203.0.113.66'],
      blocked_ports: [4444],
      revoked_permissions: ['remote_unlock'],
      denied_commands: ['unlock'],
      allowed_peers: ['192.168.1.10'],
      network_mode: 'trusted_only',
      detected_at: '2026-09-14T12:00:02.100Z',
      requested_at: '2026-09-14T12:00:02.400Z',
      applied_at: '2026-09-14T12:00:02.450Z',
      first_denied_at: '2026-09-14T12:00:04.000Z',
    },
    ...overrides,
  }
}

const attack: ActiveAttack = {
  attack_id: 'atk-1',
  attack_type: 'unauthorized_commands',
  device_id: 'lock-front-door',
  intensity: 'high',
  started_at: '2026-09-14T12:00:01.000Z',
  expires_at: '2026-09-14T12:01:31.000Z',
}

const action = {
  action_id: 'act-1',
  timestamp: '2026-09-14T12:00:02.400Z',
  device_id: 'lock-front-door',
  device_kind: 'smart_lock',
  risk_score: 88,
  threat_type: 'unauthorized_commands',
  previous_state: 'normal',
  response_state: 'restricted',
  transition: 'escalated',
  autonomous: true,
  action: 'RESTRICTED MODE: reduce permissions and block suspicious communication',
  rationale: 'Unauthorized remote unlock',
  steps_executed: ['revoke remote_unlock', 'force lock'],
  enforced: true,
} as DefensiveAction

function row(view: ReturnType<typeof buildPhysicalConsequence>, id: string) {
  return view.rows.find((item) => item.id === id)
}

test('verified defense fills the focused before/after table from observed evidence', () => {
  const evidence = buildVerifiedContainment(sample(), attack, action)
  const view = buildPhysicalConsequence(sample(), evidence)
  assert.equal(view.phase, 'after')
  assert.equal(view.verified, true)
  assert.equal(view.focused, true)
  assert.equal(row(view, 'remote_unlock')?.before, 'Accepted')
  assert.equal(row(view, 'remote_unlock')?.after, 'Denied')
  assert.equal(row(view, 'latch')?.before, 'Unlocked')
  assert.equal(row(view, 'latch')?.after, 'Locked')
  assert.equal(row(view, 'untrusted_communication')?.before, 'Allowed')
  assert.equal(row(view, 'untrusted_communication')?.after, 'Blocked')
  assert.equal(view.communication.state, 'blocked')
  assert.equal(view.animateDevice, true)
  assert.equal(view.animatePath, true)
  assert.equal(isUnsupportedHarmClaim(view.scenarioAssessment), false)
  assert.match(view.scenarioAssessment, /scenario assessment/i)
})

test('door ajar remains independent of a locked latch after verified defense', () => {
  const containedAjar = sample({ sensors: { locked: true, remote_unlock_enabled: false, door_ajar: true } })
  const view = buildPhysicalConsequence(containedAjar, buildVerifiedContainment(containedAjar, attack, action))
  assert.equal(view.latchLocked, true)
  assert.equal(row(view, 'latch')?.after, 'Locked')
  assert.equal(view.doorAjar, true)
  assert.equal(view.doorNeedsAttention, true)
  assert.match(view.residualAttention ?? '', /ajar/i)
  assert.equal(isUnsupportedHarmClaim(view.scenarioAssessment), false)
  assert.equal(isUnsupportedHarmClaim(view.residualAttention ?? ''), false)
  assert.doesNotMatch(view.scenarioAssessment, /intrusion prevented/i)
  assert.doesNotMatch(view.residualAttention ?? '', /intrusion prevented/i)
})

test('before defense shows accepted unlock, unlocked latch, and open communications', () => {
  const live = sample({
    status: 'compromised',
    sensors: { locked: false, remote_unlock_enabled: true, door_ajar: true },
    command_history: [command()],
    containment: {
      response_state: 'normal',
      isolated: false,
      safe_mode: false,
      extra_telemetry: false,
      blocked_ips: [],
      blocked_ports: [],
      revoked_permissions: [],
      denied_commands: [],
      allowed_peers: ['*'],
      network_mode: 'allow_all',
      detected_at: '2026-09-14T12:00:02.100Z',
    },
    network: {
      interface: 'wlan0',
      local_ip: '192.168.1.55',
      mac_address: '3c:22:fb:10:a1:04',
      bytes_sent: 1,
      bytes_recv: 1,
      packets_sent: 1,
      packets_recv: 1,
      active_connections: [
        {
          remote_ip: '203.0.113.66',
          remote_port: 4444,
          protocol: 'tcp',
          direction: 'outbound',
          bytes_transferred: 900,
          reputation: 'suspicious',
        },
      ],
      dns_queries: [],
      unusual_ports: [4444],
    },
  })
  const view = buildPhysicalConsequence(live, buildVerifiedContainment(live, attack))
  assert.equal(view.phase, 'before')
  assert.equal(view.verified, false)
  assert.equal(row(view, 'remote_unlock')?.before, 'Accepted')
  assert.equal(row(view, 'latch')?.before, 'Unlocked')
  assert.equal(row(view, 'untrusted_communication')?.before, 'Allowed')
  assert.equal(view.communication.state, 'hostile')
  assert.equal(view.communication.from, '203.0.113.66')
  assert.equal(view.doorNeedsAttention, true)
  assert.equal(view.animatePath, true)
  assert.match(view.scenarioAssessment, /scenario assessment/i)
})

test('quiet home does not claim a physical incident', () => {
  const quiet = sample({
    status: 'online',
    sensors: { locked: true, remote_unlock_enabled: true, door_ajar: false },
    command_history: [
      command({
        command: 'lock',
        actor: 'owner',
        source_ip: '192.168.1.10',
        authorized: true,
        result: 'ok',
      }),
    ],
    attack_signals: [],
    containment: {
      response_state: 'normal',
      isolated: false,
      safe_mode: false,
      extra_telemetry: false,
      blocked_ips: [],
      blocked_ports: [],
      revoked_permissions: [],
      denied_commands: [],
      allowed_peers: ['*'],
      network_mode: 'allow_all',
    },
  })
  const view = buildPhysicalConsequence(quiet)
  assert.equal(view.phase, 'quiet')
  assert.equal(view.focused, false)
  assert.equal(view.animateDevice, false)
  assert.equal(row(view, 'remote_unlock')?.before, 'Idle')
  assert.equal(row(view, 'latch')?.before, 'Locked')
  assert.equal(isUnsupportedHarmClaim(view.scenarioAssessment), false)
  assert.deepEqual(emptyPhysicalConsequence().rows.map((item) => item.observation), [
    'Remote unlock',
    'Latch',
    'Untrusted communication',
  ])
})

test('unsupported harm claims are detected for copy review', () => {
  assert.equal(isUnsupportedHarmClaim('Intrusion prevented'), true)
  assert.equal(isUnsupportedHarmClaim('Scenario assessment: latch locked, door still ajar.'), false)
})

test('before column survives after accepted unlocks roll off the command buffer', () => {
  const rolled = sample({
    command_history: [
      command({ timestamp: '2026-09-14T12:00:04.000Z', result: 'denied_by_containment' }),
      command({ timestamp: '2026-09-14T12:00:05.000Z', result: 'denied_by_containment' }),
    ],
    verified_containment: {
      device_id: 'lock-front-door',
      verified: true,
      intended: [],
      observed: [],
      outcomes: [],
      sequence: [
        { id: 'detected', label: 'Unauthorized unlock detected', kind: 'observed', complete: true, at: '2026-09-14T12:00:02.000Z' },
        { id: 'requested', label: 'Containment requested', kind: 'intended', complete: true },
        { id: 'acknowledged', label: 'Simulator acknowledged', kind: 'observed', complete: true },
        { id: 'denied', label: 'Next unlock attempt: DENIED', kind: 'observed', complete: true },
      ],
    },
  })
  const view = buildPhysicalConsequence(rolled, rolled.verified_containment)
  assert.equal(row(view, 'remote_unlock')?.before, 'Accepted')
  assert.equal(row(view, 'remote_unlock')?.after, 'Denied')
  assert.equal(row(view, 'latch')?.before, 'Unlocked')
  assert.equal(row(view, 'latch')?.after, 'Locked')
  assert.equal(row(view, 'untrusted_communication')?.before, 'Allowed')
  assert.equal(row(view, 'untrusted_communication')?.after, 'Blocked')
})
