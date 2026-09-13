import type { CommandRecord, MeshIncident, TelemetrySample } from '../types'

export const CORRELATION_WINDOW_SECONDS = 10
export const ENTRY_TITLE = 'Possible coordinated entry attempt'
export const ENTRY_DETAIL = 'Shared source observed across camera and lock within 10 seconds.'
export const ENTRY_RULE = 'camera_then_lock_shared_source'
export const ENTRY_METHOD = 'rule_based_correlation'
export const ENTRY_EXPLANATION =
  'Rule-based correlation: an unauthorized camera command and an unauthorized lock command shared a source IP within 10 seconds. This is not a learned graph model, and it does not use simulator attack labels.'

const CAMERA_ID = 'cam-front-door'
const LOCK_ID = 'lock-front-door'

export function correlateEntryAttempt(
  samples: TelemetrySample[],
  windowSeconds = CORRELATION_WINDOW_SECONDS,
): MeshIncident | null {
  const cameras = samples.filter(isCamera)
  const locks = samples.filter(isLock)
  if (!cameras.length || !locks.length) return null

  let best: {
    delta: number
    camera: TelemetrySample
    lock: TelemetrySample
    cameraEvent: CommandRecord
    lockEvent: CommandRecord
  } | null = null

  for (const camera of cameras) {
    for (const cameraEvent of unauthorizedCommands(camera)) {
      for (const lock of locks) {
        for (const lockEvent of unauthorizedCommands(lock)) {
          if (!sameSource(cameraEvent, lockEvent)) continue
          const delta = (Date.parse(lockEvent.timestamp) - Date.parse(cameraEvent.timestamp)) / 1000
          if (!Number.isFinite(delta)) continue
          if (delta < 0 || delta > windowSeconds) continue
          if (!best || delta < best.delta) {
            best = { delta, camera, lock, cameraEvent, lockEvent }
          }
        }
      }
    }
  }

  if (!best) return null
  return {
    id: `mesh-entry-${best.cameraEvent.source_ip}-${best.cameraEvent.timestamp}-${best.lockEvent.timestamp}`,
    title: ENTRY_TITLE,
    detail: ENTRY_DETAIL,
    method: ENTRY_METHOD,
    rule: ENTRY_RULE,
    window_seconds: windowSeconds,
    source_ip: best.cameraEvent.source_ip,
    device_ids: [best.camera.device_id, best.lock.device_id],
    sequence: [asEvent(best.camera, best.cameraEvent), asEvent(best.lock, best.lockEvent)],
    observed_at: best.lockEvent.timestamp,
    delta_seconds: Math.round(best.delta * 1000) / 1000,
    explanation: ENTRY_EXPLANATION,
  }
}

function isCamera(sample: TelemetrySample) {
  return sample.device_type === 'smart_camera' || sample.device_id === CAMERA_ID
}

function isLock(sample: TelemetrySample) {
  return sample.device_type === 'smart_lock' || sample.device_id === LOCK_ID
}

function unauthorizedCommands(sample: TelemetrySample) {
  return sample.command_history.filter((command) => !command.authorized)
}

function sameSource(left: CommandRecord, right: CommandRecord) {
  const source = left.source_ip?.trim() ?? ''
  return Boolean(source) && source === right.source_ip
}

function asEvent(sample: TelemetrySample, command: CommandRecord) {
  return {
    device_id: sample.device_id,
    device_name: sample.name,
    device_type: sample.device_type,
    command: command.command,
    source_ip: command.source_ip,
    timestamp: command.timestamp,
    authorized: command.authorized,
    result: command.result,
  }
}
