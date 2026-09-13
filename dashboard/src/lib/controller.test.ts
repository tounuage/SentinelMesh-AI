import assert from 'node:assert/strict'
import test from 'node:test'
import { isControllerActive, newestFleetAction } from './controller.ts'
import type { ControllerHeartbeat } from '../types'

function heartbeat(overrides: Partial<ControllerHeartbeat> = {}): ControllerHeartbeat {
  return {
    active: true,
    fresh: true,
    last_beat_at: '2026-09-14T01:00:00.000Z',
    cycle_count: 4,
    last_error: null,
    poll_interval_seconds: 2,
    heartbeat_stale_seconds: 6,
    enforcement_enabled: true,
    last_enforced_at: '2026-09-14T01:00:00.000Z',
    last_ingest_count: 4,
    bootstrapped: true,
    ...overrides,
  }
}

test('controller is active only while the worker heartbeat is fresh', () => {
  const now = Date.parse('2026-09-14T01:00:04.000Z')
  assert.equal(isControllerActive(heartbeat(), now), true)
  assert.equal(isControllerActive(heartbeat({ last_beat_at: '2026-09-14T00:59:50.000Z' }), now), false)
  assert.equal(isControllerActive(heartbeat({ active: false }), now), false)
  assert.equal(isControllerActive(heartbeat({ last_beat_at: null }), now), false)
  assert.equal(isControllerActive(null, now), false)
})

test('newest fleet action is the recorded backend response', () => {
  const chosen = newestFleetAction([
    { last_action: { timestamp: '2026-09-14T01:00:01.000Z' } },
    { last_action: { timestamp: '2026-09-14T01:00:04.000Z' } },
    { last_action: null },
  ])
  assert.equal(chosen?.timestamp, '2026-09-14T01:00:04.000Z')
  assert.equal(newestFleetAction([]), null)
})
