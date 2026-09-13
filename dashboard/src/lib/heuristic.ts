import type { AnalysisResult, ResponseState, TelemetrySample } from '../types'
import { threatLabel } from './labels'
import { assessPhysical } from './physical'

const STATE_RANK: Record<ResponseState, number> = {
  normal: 0,
  monitor: 1,
  restricted: 2,
  quarantine: 3,
}

export function desiredState(risk: number, threat: string): ResponseState {
  const byRisk: ResponseState =
    risk >= 75 ? 'quarantine' : risk >= 45 ? 'restricted' : risk >= 20 ? 'monitor' : 'normal'
  const floor: ResponseState =
    threat === 'firmware_modification' || threat === 'multi_stage_compromise'
      ? 'quarantine'
      : threat === 'unauthorized_commands' ||
          threat === 'suspicious_ip_connections' ||
          threat === 'abnormal_network_traffic' ||
          threat === 'abnormal_power_usage'
        ? 'restricted'
        : threat === 'unknown_anomaly'
          ? 'monitor'
          : 'normal'
  if (threat === 'benign') return byRisk
  return STATE_RANK[byRisk] >= STATE_RANK[floor] ? byRisk : floor
}

export function analyzeLocally(sample: TelemetrySample): AnalysisResult {
  const unauthorized = sample.command_history
    .filter((command) => !command.authorized && command.result !== 'denied_by_containment')
    .slice(-6)
  const suspicious = sample.network.active_connections.filter(
    (connection) => connection.reputation === 'suspicious',
  )
  const signals = new Set(sample.attack_signals)
  const reasons: string[] = []
  let risk = 6
  let threat = 'benign'

  if (signals.has('firmware_modification') || !sample.firmware_signed) {
    risk = Math.max(risk, 88)
    threat = 'firmware_modification'
    reasons.push(
      `firmware changed to ${sample.firmware_version} (${sample.firmware_signed ? 'unexpected version' : 'unsigned'})`,
    )
  }
  if (signals.has('unauthorized_commands') || unauthorized.length) {
    risk = Math.max(risk, 82)
    if (threat === 'benign') threat = 'unauthorized_commands'
    const commands = [...new Set(unauthorized.map((item) => item.command))].join(', ') || 'remote control'
    const actors = [...new Set(unauthorized.map((item) => item.actor))].join(', ') || 'unknown actors'
    reasons.push(`unauthorized commands (${commands}) from ${actors}`)
  }
  if (signals.has('suspicious_ip_connections') || suspicious.length) {
    risk = Math.max(risk, 76)
    if (threat === 'benign') threat = 'suspicious_ip_connections'
    const hosts = suspicious.map((item) => item.remote_ip).slice(0, 4).join(', ') || 'untrusted hosts'
    reasons.push(`outbound sessions to untrusted hosts ${hosts}`)
  }
  if (signals.has('abnormal_network_traffic') || sample.network.unusual_ports.length) {
    risk = Math.max(risk, 68)
    if (threat === 'benign') threat = 'abnormal_network_traffic'
    if (sample.network.unusual_ports.length) {
      reasons.push(`non-standard egress ports ${sample.network.unusual_ports.slice(0, 6).join(', ')}`)
    } else {
      reasons.push('burst in outbound volume versus the device baseline')
    }
  }
  if (signals.has('abnormal_power_usage') || sample.power.deviation_percent >= 80) {
    risk = Math.max(risk, 62)
    if (threat === 'benign') threat = 'abnormal_power_usage'
    reasons.push(
      `power draw ${sample.power.watts.toFixed(1)} W is ${sample.power.deviation_percent.toFixed(1)}% off baseline`,
    )
  }
  if (sample.anomaly_indicators.length && risk < 40) {
    risk = Math.max(risk, 34)
    if (threat === 'benign') threat = 'unknown_anomaly'
    reasons.push(sample.anomaly_indicators.slice(0, 3).join(', ').replaceAll('_', ' '))
  }
  if (signals.size >= 2) {
    threat = 'multi_stage_compromise'
    risk = Math.max(risk, 91)
  }
  if (sample.status === 'compromised') risk = Math.max(risk, 80)
  if (sample.status === 'quarantined') risk = Math.max(risk, risk)

  const response = desiredState(risk, threat)
  const joined = reasons.join('; ') || 'behavior is within the learned envelope'
  const explanation =
    threat === 'benign'
      ? `${sample.name} (${sample.device_id}) matches its learned behavior. Risk ${risk.toFixed(1)}/100.`
      : `${sample.name} (${sample.device_id}) is suspicious because ${joined}. Classified as ${threat} with risk ${risk.toFixed(1)}/100.`

  return {
    device: sample.device_id,
    risk_score: Number(risk.toFixed(1)),
    threat_type: threat,
    explanation,
    recommended_action: recommend(sample.device_id, threat, reasons),
    response_state: response,
    defensive_action: actionText(sample.device_id, response, threat),
    physical: assessPhysical(sample, threat, risk),
    source: 'heuristic',
  }
}

function recommend(deviceId: string, threat: string, reasons: string[]): string {
  if (threat === 'benign') {
    return `Continue monitoring ${deviceId}; no containment action required.`
  }
  if (threat === 'firmware_modification') {
    return `Quarantine ${deviceId}, block OTA channels, and roll back to the last signed firmware image.`
  }
  if (threat === 'unauthorized_commands') {
    return `Revoke sessions on ${deviceId}, rotate credentials, and force a known-good locked state.`
  }
  if (threat === 'suspicious_ip_connections') {
    return `Isolate ${deviceId} from the LAN and block the observed untrusted destinations.`
  }
  if (threat === 'abnormal_network_traffic') {
    return `Rate-limit ${deviceId}, sinkhole suspicious DNS, and inspect for exfiltration.`
  }
  if (threat === 'abnormal_power_usage') {
    return `Cap power on ${deviceId} and inspect for mining, stuck actuators, or tampering.`
  }
  if (threat === 'multi_stage_compromise') {
    return `Treat ${deviceId} as compromised: isolate, revoke credentials, and rebuild from signed firmware.`
  }
  return `Place ${deviceId} under elevated watch. Evidence: ${reasons[0] ?? 'feature deviation'}.`
}

function actionText(deviceId: string, state: ResponseState, threat: string): string {
  const labels: Record<ResponseState, string> = {
    normal: 'NORMAL: allow all activity',
    monitor: 'MONITOR: collect additional telemetry',
    restricted: 'RESTRICTED MODE: reduce permissions and block suspicious communication',
    quarantine: 'QUARANTINE: isolate device completely',
  }
  return `${labels[state]} on ${deviceId} (threat=${threatLabel(threat)}).`
}
