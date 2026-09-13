import assert from 'node:assert/strict'
import test from 'node:test'
import { isScenarioClean, readinessLine } from './readiness.ts'
import type { ActiveAttack, TelemetrySample } from '../types'

function sample(overrides: Partial<TelemetrySample> = {}): TelemetrySample {
  return {
    timestamp: '2026-09-14T12:00:00Z',
    device_id: 'lock-front-door',
    device_type: 'smart_lock',
    name: 'Front Door Lock',
    room: 'entryway',
    status: 'online',
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
    sensors: { locked: true },
    command_history: [
      {
        timestamp: '2026-09-14T11:45:00Z',
        command: 'lock',
        actor: 'owner',
        source_ip: '192.168.1.10',
        authorized: true,
        result: 'ok',
      },
    ],
    anomaly_indicators: [],
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
    ...overrides,
  }
}

test('readiness line uses the compact presentation copy', () => {
  assert.equal(
    readinessLine({
      simulator: true,
      modelsReady: true,
      controllerActive: true,
      scenarioClean: true,
    }),
    'Simulator ✓   Models ready ✓   Controller active ✓   Scenario clean ✓',
  )
  assert.equal(
    readinessLine({
      simulator: true,
      modelsReady: false,
      controllerActive: true,
      scenarioClean: true,
    }),
    'Simulator ✓   Models ready —   Controller active ✓   Scenario clean ✓',
  )
})

test('scenario is clean only when hostile history, firmware, and containment are gone', () => {
  assert.equal(isScenarioClean([sample()], []), true)
  assert.equal(isScenarioClean([], []), false)
  assert.equal(
    isScenarioClean(
      [
        sample({
          command_history: [
            {
              timestamp: '2026-09-14T12:01:00Z',
              command: 'unlock',
              actor: 'unknown',
              source_ip: '203.0.113.66',
              authorized: false,
              result: 'accepted',
            },
          ],
        }),
      ],
      [],
    ),
    false,
  )
  assert.equal(
    isScenarioClean([sample({ firmware_signed: false })], []),
    false,
  )
  const attack: ActiveAttack = {
    attack_id: 'a1',
    attack_type: 'unauthorized_commands',
    device_id: 'lock-front-door',
    intensity: 'high',
    started_at: '2026-09-14T12:01:00Z',
    expires_at: '2026-09-14T12:02:00Z',
  }
  assert.equal(isScenarioClean([sample()], [attack]), false)
})
