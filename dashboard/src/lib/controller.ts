import type { ControllerHeartbeat } from '../types'

export const DEFAULT_HEARTBEAT_STALE_SECONDS = 6

export function isControllerActive(
  heartbeat: ControllerHeartbeat | null | undefined,
  nowMs = Date.now(),
): boolean {
  if (!heartbeat?.active || !heartbeat.last_beat_at) return false
  const beat = Date.parse(heartbeat.last_beat_at)
  if (Number.isNaN(beat)) return false
  const staleMs = (heartbeat.heartbeat_stale_seconds || DEFAULT_HEARTBEAT_STALE_SECONDS) * 1000
  return nowMs - beat <= staleMs
}

export function newestFleetAction<T extends { last_action?: { timestamp: string } | null }>(
  fleet: T[],
): T['last_action'] | null {
  const actions = fleet
    .map((row) => row.last_action)
    .filter((action): action is NonNullable<T['last_action']> => Boolean(action))
  if (actions.length === 0) return null
  return actions.reduce((newest, action) =>
    Date.parse(action.timestamp) > Date.parse(newest.timestamp) ? action : newest,
  )
}
