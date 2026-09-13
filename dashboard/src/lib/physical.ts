import type { PhysicalAssessment, TelemetrySample } from '../types'

const CRITICALITY: Record<string, number> = {
  smart_lock: 1,
  smart_camera: 0.88,
  smart_thermostat: 0.84,
  smart_plug: 0.76,
}

const HAZARDS: Record<string, { hazard: string; consequence: string; multiplier: number }> = {
  'smart_lock:unauthorized_commands': {
    hazard: 'forced_entry',
    consequence: 'A hostile session can unlock the door and admit an intruder.',
    multiplier: 1.15,
  },
  'smart_lock:firmware_modification': {
    hazard: 'lock_hijack',
    consequence: 'Unsigned firmware can silently disable locking or ignore owner PINs.',
    multiplier: 1.12,
  },
  'smart_camera:abnormal_network_traffic': {
    hazard: 'privacy_exfiltration',
    consequence: 'Live video from the entryway may be leaving the home.',
    multiplier: 1.08,
  },
  'smart_camera:suspicious_ip_connections': {
    hazard: 'surveillance_hijack',
    consequence: 'An attacker may be watching occupants and casing the property.',
    multiplier: 1.1,
  },
  'smart_thermostat:unauthorized_commands': {
    hazard: 'climate_extremes',
    consequence: 'HVAC can be driven to freeze pipes or overheat occupied rooms.',
    multiplier: 1.1,
  },
  'smart_plug:abnormal_power_usage': {
    hazard: 'electrical_fire',
    consequence: 'Sustained overload on a lamp circuit can ignite nearby furnishings.',
    multiplier: 1.18,
  },
  'smart_lock:multi_stage_compromise': {
    hazard: 'forced_entry',
    consequence: 'A coordinated compromise of the lock can open the home to an intruder.',
    multiplier: 1.2,
  },
}

const GENERIC: Record<string, { hazard: string; consequence: string; multiplier: number }> = {
  multi_stage_compromise: {
    hazard: 'coordinated_physical_compromise',
    consequence: 'Multiple hostile behaviors at once raise the chance of a real-world incident.',
    multiplier: 1.2,
  },
  unauthorized_commands: {
    hazard: 'hostile_actuation',
    consequence: 'Physical actuators may fire without the homeowner’s consent.',
    multiplier: 1.06,
  },
  firmware_modification: {
    hazard: 'untrusted_control',
    consequence: 'The device can no longer be trusted to fail safe.',
    multiplier: 1.08,
  },
  abnormal_power_usage: {
    hazard: 'energy_hazard',
    consequence: 'Power anomalies often precede overheating, mining, or stuck actuators.',
    multiplier: 1.02,
  },
  suspicious_ip_connections: {
    hazard: 'external_command_channel',
    consequence: 'An untrusted host can reach a device that moves or observes the home.',
    multiplier: 1,
  },
  abnormal_network_traffic: {
    hazard: 'data_and_control_leak',
    consequence: 'Unexpected egress can carry sensor data or accept remote control.',
    multiplier: 0.95,
  },
}

const SAFE_MODE: Record<string, string> = {
  smart_lock: 'Force the deadbolt locked, disable remote unlock, and shorten auto-relock.',
  smart_camera: 'Close the privacy shutter, stop recording, and cut the live stream.',
  smart_thermostat: 'Hold an eco setpoint, idle HVAC, and lock climate controls.',
  smart_plug: 'Open the relay, cap power draw, and freeze the schedule.',
}

function sensorSignals(sample: TelemetrySample, threat: string): { boost: number; notes: string[] } {
  const notes: string[] = []
  let boost = 0
  const sensors = sample.sensors
  if (sample.device_type === 'smart_lock') {
    if (sensors.locked === false) {
      boost += 22
      notes.push('The latch is currently unlocked.')
    }
    if (sensors.door_ajar) {
      boost += 16
      notes.push(
        sensors.locked === true
          ? 'The door sensor still reports ajar; locking the latch did not close the leaf.'
          : 'The door is ajar, so a remote unlock becomes physical entry.',
      )
    }
    if (Number(sensors.failed_pin_attempts ?? 0) >= 3) {
      boost += 10
      notes.push('Repeated PIN failures look like a physical bypass attempt.')
    }
  } else if (sample.device_type === 'smart_camera' && threat !== 'benign') {
    if (sensors.privacy_shutter_open && sensors.recording) {
      boost += 8
      notes.push('The shutter is open and the camera is recording.')
    }
    if (Number(sensors.motion_probability ?? 0) >= 0.4) {
      boost += 10
      notes.push('Motion at the entryway while the camera is hostile raises stalking risk.')
    }
  } else if (sample.device_type === 'smart_thermostat') {
    const setpoint = Number(sensors.setpoint_c ?? 21)
    if (setpoint >= 30 || setpoint <= 12) {
      boost += 20
      notes.push(`Setpoint is ${setpoint.toFixed(1)}°C, outside a safe occupied range.`)
    }
  }
  return { boost, notes }
}

export function assessPhysical(sample: TelemetrySample, threat: string, cyberRisk: number): PhysicalAssessment {
  const { boost, notes } = sensorSignals(sample, threat)

  if (threat === 'benign') {
    if (sample.device_type === 'smart_camera' || boost < 8) {
      return {
        score: Number(Math.min(12, cyberRisk * 0.15).toFixed(1)),
        hazard: 'none',
        severity: 'none',
        consequences: ['No material physical hazard predicted from this tick.'],
        safe_mode: 'Device remains in its normal operating posture.',
      }
    }
    return {
      score: Number(Math.min(55, 20 + boost).toFixed(1)),
      hazard: 'unsafe_physical_state',
      severity: 20 + boost >= 55 ? 'high' : 20 + boost >= 30 ? 'moderate' : 'low',
      consequences: notes.length ? notes : ['Sensors show an unsafe posture without a classified cyber attack.'],
      safe_mode: SAFE_MODE[sample.device_type] ?? 'Enter failsafe and disable remote admin.',
    }
  }

  const profile =
    HAZARDS[`${sample.device_type}:${threat}`] ??
    GENERIC[threat] ?? {
      hazard: 'device_misuse',
      consequence: 'Anomalous control of a cyber-physical device can affect the home.',
      multiplier: 0.8,
    }

  const score = Math.min(100, cyberRisk * (CRITICALITY[sample.device_type] ?? 0.6) * profile.multiplier + boost)
  const severity = score >= 80 ? 'critical' : score >= 55 ? 'high' : score >= 30 ? 'moderate' : score >= 15 ? 'low' : 'none'
  return {
    score: Number(score.toFixed(1)),
    hazard: score >= 20 ? profile.hazard : 'watch',
    severity,
    consequences: [profile.consequence, ...notes].slice(0, 4),
    safe_mode: SAFE_MODE[sample.device_type] ?? 'Enter failsafe and disable remote admin.',
  }
}
