import type {
  ActiveAttack,
  AnalysisResult,
  AttackRequest,
  ControllerHeartbeat,
  DefensiveAction,
  DeviceResponseStatus,
  DeviceSnapshot,
  EnvironmentSnapshot,
  MeshIncident,
  TelemetrySample,
} from './types'

const SIM = '/sim'
const ENG = '/sec'

async function parseJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text()
    throw new Error(text || `${response.status} ${response.statusText}`)
  }
  return (await response.json()) as T
}

async function getJson<T>(url: string, timeoutMs = 4000): Promise<T> {
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, { signal: controller.signal })
    return await parseJson<T>(response)
  } finally {
    window.clearTimeout(timer)
  }
}

async function sendJson<T>(
  url: string,
  method: 'POST',
  body?: unknown,
  timeoutMs = 8000,
): Promise<T> {
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    })
    return await parseJson<T>(response)
  } finally {
    window.clearTimeout(timer)
  }
}

export async function ping(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, { method: 'GET' })
    return response.ok
  } catch {
    return false
  }
}

export const api = {
  simHealth: () => ping(`${SIM}/api/v1/health`),
  engHealth: () => ping(`${ENG}/api/v1/health`),
  devices: () => getJson<DeviceSnapshot[]>(`${SIM}/api/v1/devices`),
  telemetry: () => getJson<EnvironmentSnapshot>(`${SIM}/api/v1/telemetry`),
  history: (deviceId: string, limit = 40) =>
    getJson<TelemetrySample[]>(
      `${SIM}/api/v1/telemetry/${encodeURIComponent(deviceId)}/history?limit=${limit}`,
    ),
  attacks: () => getJson<ActiveAttack[]>(`${SIM}/api/v1/attacks`),
  injectAttack: (request: AttackRequest) =>
    sendJson<ActiveAttack>(`${SIM}/api/v1/attacks`, 'POST', request),
  stopAttacks: (deviceId?: string) =>
    sendJson<{ stopped: number }>(`${SIM}/api/v1/attacks/stop`, 'POST', {
      device_id: deviceId ?? null,
    }),
  tick: () => sendJson<EnvironmentSnapshot>(`${SIM}/api/v1/simulation/tick`, 'POST'),
  resetSim: (demo = false) => sendJson<{ status: string }>(`${SIM}/api/v1/simulation/reset?demo=${demo}`, 'POST'),
  profiles: () => getJson<{ device: string; baseline_ready: boolean }[]>(`${ENG}/api/v1/profiles`),
  ingest: (bootstrapHistory = false) =>
    sendJson<AnalysisResult[]>(
      `${ENG}/api/v1/ingest/simulator?bootstrap_history=${bootstrapHistory ? 'true' : 'false'}`,
      'POST',
      undefined,
      bootstrapHistory ? 20000 : 6000,
    ),
  findings: () => getJson<AnalysisResult[]>(`${ENG}/api/v1/findings`),
  incidents: () => getJson<MeshIncident[]>(`${ENG}/api/v1/incidents`),
  engineAction: (deviceId: string, riskScore: number, threatType: string) =>
    sendJson<DefensiveAction>(`${ENG}/device/action`, 'POST', {
      device_id: deviceId,
      risk_score: riskScore,
      threat_type: threatType,
    }),
  simAction: (deviceId: string, riskScore: number, threatType: string) =>
    sendJson<DefensiveAction>(`${SIM}/device/action`, 'POST', {
      device_id: deviceId,
      risk_score: riskScore,
      threat_type: threatType,
    }),
  recoverEngine: (deviceId: string, force = true) =>
    sendJson<DefensiveAction>(`${ENG}/device/recover`, 'POST', {
      device_id: deviceId,
      force,
    }),
  recoverSim: (deviceId: string, force = true) =>
    sendJson<DefensiveAction>(`${SIM}/device/recover`, 'POST', {
      device_id: deviceId,
      force,
    }),
  fleetResponses: () => getJson<DeviceResponseStatus[]>(`${ENG}/api/v1/devices/responses`),
  controller: () => getJson<ControllerHeartbeat>(`${ENG}/api/v1/controller`),
  setController: (body: { enforcement_enabled: boolean }) =>
    sendJson<ControllerHeartbeat>(`${ENG}/api/v1/controller`, 'POST', body),
  resetEngine: () => sendJson<{ status: string }>(`${ENG}/api/v1/reset`, 'POST'),
}

export async function applyAutonomousAction(
  engineUp: boolean,
  deviceId: string,
  riskScore: number,
  threatType: string,
): Promise<DefensiveAction> {
  if (engineUp) {
    try {
      const action = await api.engineAction(deviceId, riskScore, threatType)
      if (action.enforced !== false) return action
    } catch {
      // Fall through to the simulator enforcement plane.
    }
  }
  return api.simAction(deviceId, riskScore, threatType)
}

export async function recoverDevice(
  engineUp: boolean,
  deviceId: string,
  force = true,
): Promise<DefensiveAction> {
  if (engineUp) {
    try {
      return await api.recoverEngine(deviceId, force)
    } catch {
      return api.recoverSim(deviceId, force)
    }
  }
  return api.recoverSim(deviceId, force)
}
