import assert from 'node:assert/strict'
import test from 'node:test'
import {
  CORRELATION_WINDOW_SECONDS,
  ENTRY_DETAIL,
  ENTRY_TITLE,
  correlateEntryAttempt,
} from './correlation.ts'
import type { CommandRecord, TelemetrySample } from '../types'

const SOURCE = '203.0.113.66'
const CAMERA_AT = '2026-09-14T12:00:01.000Z'
const LOCK_AT = '2026-09-14T12:00:04.000Z'

function command(overrides: Partial<CommandRecord> = {}): CommandRecord {
  return {
    timestamp: CAMERA_AT,
    command: 'disable_recording',
    actor: 'unknown_session',
    source_ip: SOURCE,
    authorized: false,
    result: 'accepted_without_authz',
    ...overrides,
  }
}

function sample(overrides: Partial<TelemetrySample> = {}): TelemetrySample {
  return {
    timestamp: CAMERA_AT,
    device_id: 'cam-front-door',
    device_type: 'smart_camera',
    name: 'Front Door Camera',
    room: 'entryway',
    status: 'online',
    firmware_version: '2.4.11',
    firmware_signed: true,
    firmware_checksum: 'abc',
    network: {
      interface: 'wlan0',
      local_ip: '192.168.1.21',
      mac_address: '3c:22:fb:10:a1:01',
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
    sensors: {},
    command_history: [command()],
    anomaly_indicators: [],
    attack_signals: [],
    ...overrides,
  }
}

function camera(overrides: Partial<TelemetrySample> = {}) {
  return sample(overrides)
}

function lock(overrides: Partial<TelemetrySample> = {}) {
  return sample({
    timestamp: LOCK_AT,
    device_id: 'lock-front-door',
    device_type: 'smart_lock',
    name: 'Front Door Lock',
    network: {
      ...sample().network,
      local_ip: '192.168.1.55',
      mac_address: '3c:22:fb:10:a1:04',
    },
    command_history: [command({ timestamp: LOCK_AT, command: 'unlock' })],
    ...overrides,
  })
}

test('shared source camera then lock within 10s becomes one incident card', () => {
  const incident = correlateEntryAttempt([camera(), lock()])
  assert.ok(incident)
  assert.equal(incident.title, ENTRY_TITLE)
  assert.equal(incident.detail, ENTRY_DETAIL)
  assert.equal(incident.method, 'rule_based_correlation')
  assert.equal(incident.source_ip, SOURCE)
  assert.deepEqual(incident.device_ids, ['cam-front-door', 'lock-front-door'])
  assert.equal(incident.delta_seconds, 3)
  assert.equal(incident.window_seconds, CORRELATION_WINDOW_SECONDS)
  assert.deepEqual(
    incident.sequence.map((event) => event.command),
    ['disable_recording', 'unlock'],
  )
  assert.match(incident.explanation, /rule-based/i)
  assert.match(incident.explanation, /attack labels/i)
})

test('correlation uses observed commands, not attack labels', () => {
  const labeledOnly = correlateEntryAttempt([
    camera({
      command_history: [command({ authorized: true, result: 'ok', source_ip: '192.168.1.10', command: 'heartbeat' })],
      attack_signals: ['unauthorized_commands'],
    }),
    lock({
      command_history: [command({ timestamp: LOCK_AT, command: 'lock', authorized: true, result: 'ok', source_ip: '192.168.1.10' })],
      attack_signals: ['unauthorized_commands'],
    }),
  ])
  const observed = correlateEntryAttempt([
    camera({ attack_signals: [] }),
    lock({ attack_signals: [] }),
  ])
  assert.equal(labeledOnly, null)
  assert.ok(observed)
  assert.equal(correlateEntryAttempt.toString().includes('attack_signals'), false)
})

test('different IPs, reversed order, and lock-only do not correlate', () => {
  assert.equal(
    correlateEntryAttempt([
      camera(),
      lock({ command_history: [command({ timestamp: LOCK_AT, command: 'unlock', source_ip: '198.51.100.77' })] }),
    ]),
    null,
  )
  assert.equal(
    correlateEntryAttempt([
      camera({ command_history: [command({ timestamp: LOCK_AT })] }),
      lock({ command_history: [command({ timestamp: CAMERA_AT, command: 'unlock' })] }),
    ]),
    null,
  )
  assert.equal(
    correlateEntryAttempt([
      camera({
        command_history: [command({ authorized: true, result: 'ok', source_ip: '192.168.1.10', command: 'heartbeat' })],
      }),
      lock(),
    ]),
    null,
  )
})

test('window includes 10 seconds and excludes just beyond', () => {
  const inside = correlateEntryAttempt([
    camera(),
    lock({ command_history: [command({ timestamp: '2026-09-14T12:00:11.000Z', command: 'unlock' })] }),
  ])
  const outside = correlateEntryAttempt([
    camera(),
    lock({ command_history: [command({ timestamp: '2026-09-14T12:00:11.001Z', command: 'unlock' })] }),
  ])
  assert.ok(inside)
  assert.equal(inside.delta_seconds, 10)
  assert.equal(outside, null)
})
