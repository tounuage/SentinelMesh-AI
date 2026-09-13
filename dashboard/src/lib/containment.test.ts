import assert from 'node:assert/strict'
import test from 'node:test'
import { buildVerifiedContainment, followUpDenied, formatLatency, latencyMs } from './containment.ts'
import type { ActiveAttack, CommandRecord, DefensiveAction, TelemetrySample } from '../types'

function command(overrides: Partial<CommandRecord>): CommandRecord {
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
    sensors: { locked: true, remote_unlock_enabled: false },
    command_history: [
      command({ timestamp: '2026-09-14T12:00:02.000Z' }),
      command({
        timestamp: '2026-09-14T12:00:04.000Z',
        result: 'denied_by_containment',
      }),
    ],
    anomaly_indicators: [],
    attack_signals: ['unauthorized_commands'],
    containment: {
      response_state: 'restricted',
      isolated: false,
      safe_mode: true,
      extra_telemetry: true,
      blocked_ips: [],
      blocked_ports: [],
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

test('latency is measured from actual timestamps', () => {
  assert.equal(latencyMs('2026-09-14T12:00:01.000Z', '2026-09-14T12:00:02.100Z'), 1100)
  assert.equal(formatLatency(1100), '1.1 s')
  assert.equal(formatLatency(240), '240 ms')
})

test('sequence separates intended containment from observed denial', () => {
  const evidence = buildVerifiedContainment(sample(), attack, action)
  assert.equal(evidence.verified, true)
  assert.deepEqual(
    evidence.sequence.map((step) => step.label),
    [
      'Unauthorized unlock detected',
      'Containment requested',
      'Simulator acknowledged',
      'Next unlock attempt: DENIED',
    ],
  )
  assert.equal(evidence.sequence[1]?.kind, 'intended')
  assert.equal(evidence.sequence[3]?.kind, 'observed')
  assert.equal(evidence.detection_latency_ms, 1100)
  assert.equal(evidence.containment_latency_ms, 1900)
  assert.equal(followUpDenied(sample()), true)
  const denied = evidence.outcomes.find((item) => item.label === 'Follow-up command')
  assert.equal(denied?.intended, 'DENIED')
  assert.equal(denied?.matched, true)
  const lock = evidence.outcomes.find((item) => item.label === 'Door lock')
  assert.equal(lock?.intended, 'forced shut')
  assert.equal(lock?.observed, 'locked')
})

test('risk score alone is not verified containment', () => {
  const evidence = buildVerifiedContainment(
    sample({
      sensors: { locked: false },
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
    }),
    attack,
  )
  assert.equal(evidence.verified, false)
  assert.equal(evidence.sequence[0]?.complete, true)
  assert.equal(evidence.sequence[3]?.complete, false)
  assert.equal(followUpDenied(sample({ command_history: [command()] })), false)
})
