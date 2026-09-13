export type DeviceType =
  | 'smart_camera'
  | 'smart_plug'
  | 'smart_thermostat'
  | 'smart_lock'

export type DeviceStatus =
  | 'online'
  | 'degraded'
  | 'offline'
  | 'compromised'
  | 'monitoring'
  | 'restricted'
  | 'quarantined'

export type AttackType =
  | 'abnormal_network_traffic'
  | 'unauthorized_commands'
  | 'suspicious_ip_connections'
  | 'firmware_modification'
  | 'abnormal_power_usage'

export const ATTACK_TYPES: AttackType[] = [
  'unauthorized_commands',
  'suspicious_ip_connections',
  'abnormal_network_traffic',
  'firmware_modification',
  'abnormal_power_usage',
]

export type AttackIntensity = 'low' | 'medium' | 'high'

export type ResponseState = 'normal' | 'monitor' | 'restricted' | 'quarantine'

export type DemoStage =
  | 'idle'
  | 'normal'
  | 'attack'
  | 'detect'
  | 'explain'
  | 'respond'
  | 'recover'
  | 'complete'

export type NetworkConnection = {
  remote_ip: string
  remote_port: number
  protocol: string
  direction: string
  bytes_transferred: number
  reputation: string
  process?: string | null
}

export type NetworkActivity = {
  interface: string
  local_ip: string
  mac_address: string
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
  active_connections: NetworkConnection[]
  dns_queries: string[]
  unusual_ports: number[]
}

export type PowerConsumption = {
  watts: number
  voltage: number
  current_amps: number
  energy_wh: number
  baseline_watts: number
  deviation_percent: number
}

export type CommandRecord = {
  timestamp: string
  command: string
  actor: string
  source_ip: string
  authorized: boolean
  result: string
  metadata?: Record<string, unknown>
}

export type ContainmentReport = {
  response_state: string
  isolated: boolean
  safe_mode: boolean
  extra_telemetry: boolean
  blocked_ips: string[]
  blocked_ports: number[]
  revoked_permissions: string[]
  denied_commands: string[]
  allowed_peers: string[]
  network_mode: string
  detected_at?: string | null
  requested_at?: string | null
  applied_at?: string | null
  first_denied_at?: string | null
}

export type IncidentStep = {
  id: string
  label: string
  kind: 'intended' | 'observed'
  complete: boolean
  at?: string | null
  detail?: string
}

export type ActionOutcome = {
  label: string
  intended: string
  observed: string
  matched: boolean
}

export type VerifiedContainment = {
  device_id: string
  verified: boolean
  detection_latency_ms?: number | null
  containment_latency_ms?: number | null
  intended: string[]
  observed: string[]
  outcomes: ActionOutcome[]
  sequence: IncidentStep[]
}

export type TelemetrySample = {
  timestamp: string
  device_id: string
  device_type: DeviceType
  name: string
  room: string
  status: DeviceStatus
  firmware_version: string
  firmware_signed: boolean
  firmware_checksum: string
  last_firmware_change?: string | null
  network: NetworkActivity
  power: PowerConsumption
  sensors: Record<string, unknown>
  command_history: CommandRecord[]
  anomaly_indicators: string[]
  attack_signals: string[]
  containment?: ContainmentReport
  verified_containment?: VerifiedContainment | null
}

export type DeviceSnapshot = {
  device_id: string
  device_type: DeviceType
  name: string
  room: string
  status: DeviceStatus
  firmware_version: string
  response_state?: string
  contained?: boolean
  latest_telemetry?: TelemetrySample | null
}

export type ActiveAttack = {
  attack_id: string
  attack_type: AttackType
  device_id: string
  intensity: AttackIntensity
  started_at: string
  expires_at: string
}

export type EnvironmentSnapshot = {
  generated_at: string
  tick: number
  devices: TelemetrySample[]
  active_attacks: ActiveAttack[]
}

export type PhysicalAssessment = {
  score: number
  hazard: string
  severity: string
  consequences: string[]
  safe_mode: string
}

export type AnalysisResult = {
  device: string
  risk_score: number
  threat_type: string
  explanation: string
  recommended_action: string
  response_state?: string | null
  defensive_action?: string | null
  physical?: PhysicalAssessment
  source?: string
}

export type CorrelatedEvent = {
  device_id: string
  device_name: string
  device_type: string
  command: string
  source_ip: string
  timestamp: string
  authorized: boolean
  result: string
}

export type MeshIncident = {
  id: string
  title: string
  detail: string
  method: string
  rule: string
  window_seconds: number
  source_ip: string
  device_ids: string[]
  sequence: CorrelatedEvent[]
  observed_at: string
  delta_seconds: number
  explanation: string
}

export type SimulatedEffects = {
  network_blocking: {
    applied: boolean
    mode: string
    blocked_peers?: string[]
    blocked_ports?: number[]
    allowed_peers?: string[]
    description?: string
  }
  permission_reduction: {
    applied: boolean
    revoked?: string[]
    remaining?: string[]
    description?: string
  }
  safe_operation_mode: {
    applied: boolean
    actions?: string[]
    description?: string
  }
  recovery: {
    eligible: boolean
    in_progress: boolean
    restored?: string[]
    next_state?: string | null
    conditions?: string
    description?: string
  }
}

export type DefensiveAction = {
  action_id: string
  timestamp: string
  device_id: string
  device_kind: string
  risk_score: number
  threat_type: string
  previous_state: ResponseState
  response_state: ResponseState
  transition: string
  autonomous: boolean
  action: string
  rationale: string
  steps_executed: string[]
  effects?: SimulatedEffects
  telemetry_policy?: {
    collect_additional: boolean
    packet_capture: boolean
    dns_logging: boolean
    command_audit: string
    sample_multiplier: number
  }
  enforced?: boolean
  enforcement_target?: string | null
}

export type DeviceResponseStatus = {
  device_id: string
  response_state: ResponseState
  last_risk_score: number
  last_threat_type: string
  consecutive_low_scores: number
  last_action?: DefensiveAction | null
}

export type StatusEvent = {
  id: string
  at: string
  deviceId: string
  deviceName: string
  kind: 'status' | 'containment' | 'attack' | 'response' | 'recovery' | 'detection'
  title?: string
  from?: string
  to: string
  detail: string
}

export type ControllerHeartbeat = {
  active: boolean
  fresh?: boolean
  last_beat_at: string | null
  cycle_count: number
  last_error: string | null
  poll_interval_seconds: number
  heartbeat_stale_seconds: number
  enforcement_enabled: boolean
  last_enforced_at: string | null
  last_ingest_count: number
  bootstrapped?: boolean
}

export type ServiceHealth = {
  simulator: boolean
  engine: boolean
}

export type AttackRequest = {
  attack_type: AttackType
  device_id?: string | null
  duration_seconds: number
  intensity: AttackIntensity
}
