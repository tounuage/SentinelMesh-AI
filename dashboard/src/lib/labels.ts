import type { AttackType, DeviceStatus, DeviceType, ResponseState } from '../types'

export const DEVICE_TYPE_LABEL: Record<DeviceType, string> = {
  smart_camera: 'Camera',
  smart_plug: 'Smart Plug',
  smart_thermostat: 'Thermostat',
  smart_lock: 'Smart Lock',
}

export const ATTACK_LABEL: Record<AttackType, string> = {
  abnormal_network_traffic: 'Abnormal network traffic',
  unauthorized_commands: 'Unauthorized commands',
  suspicious_ip_connections: 'Suspicious IP connections',
  firmware_modification: 'Firmware modification',
  abnormal_power_usage: 'Abnormal power usage',
}

export const THREAT_LABEL: Record<string, string> = {
  ...ATTACK_LABEL,
  benign: 'Benign',
  multi_stage_compromise: 'Multi-stage compromise',
  unknown_anomaly: 'Unknown anomaly',
}

export const RESPONSE_LABEL: Record<ResponseState, string> = {
  normal: 'Normal',
  monitor: 'Monitor',
  restricted: 'Restricted',
  quarantine: 'Quarantine',
}

export const STATUS_LABEL: Record<DeviceStatus, string> = {
  online: 'Online',
  degraded: 'Degraded',
  offline: 'Offline',
  compromised: 'Compromised',
  monitoring: 'Monitoring',
  restricted: 'Restricted',
  quarantined: 'Quarantined',
}

export function prettyRoom(room: string): string {
  return room.replaceAll('_', ' ')
}

export function formatClock(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return '—'
  return date.toLocaleTimeString([], { hour12: false })
}

export function relativeTime(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime()
  if (!Number.isFinite(delta)) return '—'
  if (delta < 5_000) return 'just now'
  if (delta < 60_000) return `${Math.floor(delta / 1000)}s ago`
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`
  return formatClock(iso)
}

export function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`
  return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

export function threatLabel(value: string): string {
  return THREAT_LABEL[value] ?? value.replaceAll('_', ' ')
}

export function riskTone(score: number): 'ok' | 'watch' | 'high' | 'critical' {
  if (score >= 75) return 'critical'
  if (score >= 45) return 'high'
  if (score >= 20) return 'watch'
  return 'ok'
}

export function riskColor(score: number): string {
  const tone = riskTone(score)
  if (tone === 'critical') return '#ff5c7a'
  if (tone === 'high') return '#f5b942'
  if (tone === 'watch') return '#5aa8ff'
  return '#3ee0a0'
}

export function statusTone(status: string): string {
  if (status === 'quarantined' || status === 'compromised') return 'text-soc-red'
  if (status === 'restricted' || status === 'degraded') return 'text-soc-amber'
  if (status === 'monitoring') return 'text-soc-blue'
  if (status === 'offline') return 'text-slate-500'
  return 'text-soc-green'
}

export function responseTone(state: string): string {
  if (state === 'quarantine') return 'text-soc-red'
  if (state === 'restricted') return 'text-soc-amber'
  if (state === 'monitor') return 'text-soc-blue'
  return 'text-soc-green'
}
