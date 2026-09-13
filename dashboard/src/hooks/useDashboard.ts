import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { api, applyAutonomousAction, recoverDevice as recoverViaApi } from '../api'
import { followUpDenied, formatLatency } from '../lib/containment'
import { isControllerActive, newestFleetAction } from '../lib/controller'
import { analyzeLocally, desiredState } from '../lib/heuristic'
import { correlateEntryAttempt } from '../lib/correlation'
import { assessPhysical } from '../lib/physical'
import { isScenarioClean } from '../lib/readiness'
import type {
  ActiveAttack,
  AnalysisResult,
  AttackRequest,
  ControllerHeartbeat,
  DefensiveAction,
  DemoStage,
  DeviceResponseStatus,
  DeviceSnapshot,
  EnvironmentSnapshot,
  MeshIncident,
  ServiceHealth,
  StatusEvent,
  TelemetrySample,
} from '../types'

const POLL_MS = 2000
const HISTORY_LIMIT = 36
const DEMO_LOCK = 'lock-front-door'
const DEMO_CAMERA = 'cam-front-door'

function containmentOf(sample: TelemetrySample | null | undefined, snapshot?: DeviceSnapshot) {
  return (
    sample?.containment?.response_state ??
    snapshot?.response_state ??
    (snapshot?.contained ? 'restricted' : 'normal')
  )
}

function withPhysical(sample: TelemetrySample, finding: AnalysisResult): AnalysisResult {
  if (finding.physical) return finding
  return { ...finding, physical: assessPhysical(sample, finding.threat_type, finding.risk_score) }
}

export function useDashboard() {
  const [health, setHealth] = useState<ServiceHealth>({ simulator: false, engine: false })
  const [snapshot, setSnapshot] = useState<EnvironmentSnapshot | null>(null)
  const [inventory, setInventory] = useState<DeviceSnapshot[]>([])
  const [attacks, setAttacks] = useState<ActiveAttack[]>([])
  const [findings, setFindings] = useState<AnalysisResult[]>([])
  const [incidents, setIncidents] = useState<MeshIncident[]>([])
  const [responses, setResponses] = useState<DeviceResponseStatus[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(DEMO_LOCK)
  const [events, setEvents] = useState<StatusEvent[]>([])
  const [riskHistory, setRiskHistory] = useState<Record<string, number[]>>({})
  const [lastAction, setLastAction] = useState<DefensiveAction | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [analysisSource, setAnalysisSource] = useState<'engine' | 'heuristic'>('heuristic')
  const [clock, setClock] = useState(() => new Date().toISOString())
  const [autoRespond, setAutoRespondState] = useState(true)
  const [demoStage, setDemoStage] = useState<DemoStage>('idle')
  const [demoRunning, setDemoRunning] = useState(false)
  const [modelsReady, setModelsReady] = useState(false)
  const [demoNote, setDemoNote] = useState('Press Run demo to walk the immune system through a break-in.')
  const [controller, setController] = useState<ControllerHeartbeat | null>(null)

  const prevStatus = useRef<Record<string, string>>({})
  const prevContainment = useRef<Record<string, string>>({})
  const prevAttacks = useRef<Set<string>>(new Set())
  const lastApplied = useRef<Record<string, { state: string; at: number }>>({})
  const responding = useRef(false)
  const demoHold = useRef(0)
  const modelsReadyAt = useRef(0)
  const demoBusy = useRef(false)
  const demoVerified = useRef(false)
  const demoContainedAt = useRef(0)
  const bootstrapped = useRef(false)
  const resetting = useRef(false)
  const refreshInFlight = useRef<Promise<void> | null>(null)
  const autoRespondRef = useRef(true)

  const pushEvent = useCallback((event: Omit<StatusEvent, 'id'>) => {
    const item: StatusEvent = { ...event, id: `${event.deviceId}-${event.at}-${event.to}-${Math.random()}` }
    setEvents((current) => [item, ...current].slice(0, 48))
  }, [])

  const mergeFindings = useCallback((samples: TelemetrySample[], engineFindings: AnalysisResult[] | null) => {
    const byDevice = new Map(engineFindings?.map((item) => [item.device, item]))
    const usedEngine = Boolean(engineFindings && engineFindings.length)
    setAnalysisSource(usedEngine ? 'engine' : 'heuristic')
    return samples.map((sample) => {
      const finding = byDevice.get(sample.device_id) ?? analyzeLocally(sample)
      return withPhysical(sample, { ...finding, source: usedEngine ? finding.source ?? 'engine' : 'heuristic' })
    })
  }, [])

  const refreshWork = useCallback(async () => {
    const [simOk, engOk] = await Promise.all([api.simHealth(), api.engHealth()])
    setHealth({ simulator: simOk, engine: engOk })
    setClock(new Date().toISOString())
    if (!simOk) {
      setError('IoT simulator is unreachable on :8080')
      return
    }

    try {
      const [telemetry, devices, liveAttacks] = await Promise.all([
        api.telemetry(),
        api.devices(),
        api.attacks().catch(() => [] as ActiveAttack[]),
      ])

      setSnapshot(telemetry)
      setInventory(devices)
      setAttacks(liveAttacks)
      setSelectedId((current) => current ?? telemetry.devices[0]?.device_id ?? null)
      if (!bootstrapped.current) {
        setFindings(mergeFindings(telemetry.devices, null))
      }

      let engineFindings: AnalysisResult[] | null = null
      let heartbeat: ControllerHeartbeat | null = null
      if (engOk) {
        heartbeat = await api.controller().catch(() => null)
        setController(heartbeat)
        const observing = isControllerActive(heartbeat)
        try {
          engineFindings = observing
            ? await api.findings()
            : await api.ingest(!bootstrapped.current)
          if (engineFindings?.length) bootstrapped.current = true
        } catch {
          engineFindings = await api.findings().catch(() => null)
        }
      } else {
        setController(null)
      }

      const profiles = engOk ? await api.profiles().catch(() => []) : []
      const ready =
        telemetry.devices.length > 0 &&
        telemetry.devices.every((sample) =>
          profiles.some((profile) => profile.device === sample.device_id && profile.baseline_ready),
        )
      if (!ready) modelsReadyAt.current = 0
      else if (modelsReadyAt.current === 0) modelsReadyAt.current = Date.now()
      setModelsReady(ready)
      const fleet = engOk ? await api.fleetResponses().catch(() => [] as DeviceResponseStatus[]) : []
      const nextFindings = mergeFindings(telemetry.devices, engineFindings)
      const localIncident = correlateEntryAttempt(telemetry.devices)
      const remoteIncidents = engOk ? await api.incidents().catch(() => [] as MeshIncident[]) : []
      setAttacks(liveAttacks)
      setFindings(nextFindings)
      setIncidents(remoteIncidents.length ? remoteIncidents : localIncident ? [localIncident] : [])
      setResponses(fleet)
      setError(null)

      const recorded = newestFleetAction(fleet)
      if (recorded && recorded.transition !== 'hold') {
        setLastAction(recorded)
        lastApplied.current[recorded.device_id] = {
          state: recorded.response_state,
          at: Date.parse(recorded.timestamp) || Date.now(),
        }
      }

      setRiskHistory((current) => {
        const next = { ...current }
        for (const finding of nextFindings) {
          const series = [...(next[finding.device] ?? []), finding.risk_score]
          next[finding.device] = series.slice(-HISTORY_LIMIT)
        }
        return next
      })

      const names = new Map(telemetry.devices.map((device) => [device.device_id, device.name]))
      for (const sample of telemetry.devices) {
        const snapshotRow = devices.find((row) => row.device_id === sample.device_id)
        const containment = containmentOf(sample, snapshotRow)
        const previousStatus = prevStatus.current[sample.device_id]
        const previousContainment = prevContainment.current[sample.device_id]
        if (previousStatus && previousStatus !== sample.status) {
          pushEvent({
            at: sample.timestamp,
            deviceId: sample.device_id,
            deviceName: sample.name,
            kind: 'status',
            from: previousStatus,
            to: sample.status,
            detail: `${sample.name} moved from ${previousStatus} to ${sample.status}.`,
          })
        }
        if (previousContainment && previousContainment !== containment) {
          pushEvent({
            at: sample.timestamp,
            deviceId: sample.device_id,
            deviceName: sample.name,
            kind: containment === 'normal' ? 'recovery' : 'containment',
            from: previousContainment,
            to: containment,
            detail: `Autonomous response changed containment ${previousContainment} → ${containment}.`,
          })
        }
        prevStatus.current[sample.device_id] = sample.status
        prevContainment.current[sample.device_id] = containment
      }

      const seen = new Set<string>()
      for (const attack of liveAttacks) {
        seen.add(attack.attack_id)
        if (!prevAttacks.current.has(attack.attack_id)) {
          pushEvent({
            at: attack.started_at,
            deviceId: attack.device_id,
            deviceName: names.get(attack.device_id) ?? attack.device_id,
            kind: 'attack',
            to: attack.attack_type,
            detail: `Injected ${attack.attack_type.replaceAll('_', ' ')} (${attack.intensity}).`,
          })
        }
      }
      prevAttacks.current = seen

      const observing = isControllerActive(heartbeat)
      if (autoRespondRef.current && !observing && !responding.current) {
        responding.current = true
        try {
          for (const finding of nextFindings) {
            const target =
              (finding.response_state as ReturnType<typeof desiredState>) ??
              desiredState(finding.risk_score, finding.threat_type)
            const prior = lastApplied.current[finding.device]
            const shouldAct =
              finding.threat_type !== 'benign' &&
              finding.risk_score >= 40 &&
              target !== 'normal' &&
              (!prior || prior.state !== target || Date.now() - prior.at > 12_000)
            if (!shouldAct) continue
            const action = await applyAutonomousAction(engOk, finding.device, finding.risk_score, finding.threat_type)
            lastApplied.current[finding.device] = { state: action.response_state, at: Date.now() }
            setLastAction(action)
            pushEvent({
              at: action.timestamp,
              deviceId: action.device_id,
              deviceName: names.get(action.device_id) ?? action.device_id,
              kind: 'response',
              from: action.previous_state,
              to: action.response_state,
              detail: action.action,
            })
          }
        } catch {
          // Keep the mesh live even if a single enforcement call fails.
        } finally {
          responding.current = false
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh mesh telemetry')
    }
  }, [mergeFindings, pushEvent])

  const refresh = useCallback(async () => {
    if (resetting.current) return
    if (refreshInFlight.current) return refreshInFlight.current
    const task = refreshWork()
    refreshInFlight.current = task
    try {
      await task
    } finally {
      refreshInFlight.current = null
    }
  }, [refreshWork])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), POLL_MS)
    return () => {
      window.clearInterval(timer)
    }
  }, [refresh])

  const selected = useMemo(() => {
    if (!snapshot) return null
    return snapshot.devices.find((device) => device.device_id === selectedId) ?? snapshot.devices[0] ?? null
  }, [snapshot, selectedId])

  const selectedFinding = useMemo(() => {
    if (!selected) return null
    return findings.find((item) => item.device === selected.device_id) ?? null
  }, [findings, selected])

  const selectedResponse = useMemo(() => {
    if (!selected) return null
    const fromEngine = responses.find((item) => item.device_id === selected.device_id)
    if (fromEngine) return fromEngine
    return {
      device_id: selected.device_id,
      response_state: (containmentOf(selected) as DeviceResponseStatus['response_state']) ?? 'normal',
      last_risk_score: selectedFinding?.risk_score ?? 0,
      last_threat_type: selectedFinding?.threat_type ?? 'benign',
      consecutive_low_scores: 0,
      last_action: lastAction?.device_id === selected.device_id ? lastAction : null,
    } satisfies DeviceResponseStatus
  }, [lastAction, responses, selected, selectedFinding])

  const inject = useCallback(
    async (request: AttackRequest) => {
      setBusy(true)
      setError(null)
      try {
        await api.injectAttack(request)
        await refresh()
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Attack injection failed')
      } finally {
        setBusy(false)
      }
    },
    [refresh],
  )

  const stopAttacks = useCallback(
    async (deviceId?: string) => {
      setBusy(true)
      try {
        await api.stopAttacks(deviceId)
        await refresh()
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to stop attacks')
      } finally {
        setBusy(false)
      }
    },
    [refresh],
  )

  const recover = useCallback(
    async (deviceId: string, force = true) => {
      setBusy(true)
      try {
        const action = await recoverViaApi(health.engine, deviceId, force)
        lastApplied.current[deviceId] = { state: action.response_state, at: Date.now() }
        setLastAction(action)
        await refresh()
        return action
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Recovery failed')
        return null
      } finally {
        setBusy(false)
      }
    },
    [health.engine, refresh],
  )

  const resetAll = useCallback(async (demo = false) => {
    if (resetting.current) return false
    resetting.current = true
    setBusy(true)
    try {
      await refreshInFlight.current
      setModelsReady(false)
      modelsReadyAt.current = 0
      await api.resetSim(demo)
      if (health.engine || demo) await api.resetEngine()
      lastApplied.current = {}
      prevStatus.current = {}
      prevContainment.current = {}
      prevAttacks.current = new Set()
      demoVerified.current = false
      demoContainedAt.current = 0
      bootstrapped.current = false
      setEvents([])
      setRiskHistory({})
      setLastAction(null)
      setSnapshot(null)
      setFindings([])
      setIncidents([])
      setResponses([])
      resetting.current = false
      await refresh()
      return true
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset failed')
      return false
    } finally {
      resetting.current = false
      setBusy(false)
    }
  }, [health.engine, refresh])

  const forceTick = useCallback(async () => {
    setBusy(true)
    try {
      await api.tick()
      await refresh()
    } finally {
      setBusy(false)
    }
  }, [refresh])

  const setAutoRespond = useCallback((value: boolean) => {
    autoRespondRef.current = value
    setAutoRespondState(value)
    void api.setController({ enforcement_enabled: value }).catch(() => {})
  }, [])

  const runDemo = useCallback(async () => {
    setDemoRunning(false)
    setModelsReady(false)
    modelsReadyAt.current = 0
    setAutoRespond(false)
    setSelectedId(DEMO_LOCK)
    setDemoStage('normal')
    setDemoNote('Learning the quiet home. The attack waits until behavioral baselines are ready.')
    demoHold.current = Date.now()
    const reset = await resetAll(true)
    setDemoRunning(reset)
  }, [resetAll])

  const stopDemo = useCallback(() => {
    setDemoRunning(false)
    setDemoStage('idle')
    setDemoNote('Demo paused. The mesh keeps running.')
  }, [])

  useEffect(() => {
    if (!demoRunning || demoBusy.current || !snapshot) return
    const lock = snapshot.devices.find((device) => device.device_id === DEMO_LOCK)
    const lockFinding = findings.find((item) => item.device === DEMO_LOCK)
    const lockState = containmentOf(lock)
    const fleetState = responses.find((item) => item.device_id === DEMO_LOCK)?.response_state
    const policyState = fleetState ?? lockFinding?.response_state ?? lockState
    const contained =
      lockState === 'restricted' ||
      lockState === 'quarantine' ||
      policyState === 'restricted' ||
      policyState === 'quarantine' ||
      Boolean(lock?.containment?.safe_mode)

    const advance = async () => {
      demoBusy.current = true
      try {
        if (demoStage === 'normal') {
          if (!modelsReady || !health.engine) {
            setDemoNote('Learning quiet-home baselines. Attack waits until models are actually ready.')
            return
          }
          if (Date.now() - modelsReadyAt.current < 900) {
            setDemoNote('Baselines ready. Injecting the lock attack.')
            return
          }
          setAutoRespond(true)
          setDemoStage('attack')
          setDemoNote('Suspicious camera activity, then an unauthorized lock command from the same source.')
          setSelectedId(DEMO_LOCK)
          await inject({
            attack_type: 'unauthorized_commands',
            device_id: DEMO_CAMERA,
            duration_seconds: 90,
            intensity: 'high',
          })
          await inject({
            attack_type: 'unauthorized_commands',
            device_id: DEMO_LOCK,
            duration_seconds: 90,
            intensity: 'high',
          })
          demoHold.current = Date.now()
          return
        }
        if (demoStage === 'attack' && (attacks.length > 0 || (lockFinding?.risk_score ?? 0) >= 40)) {
          setDemoStage('detect')
          setDemoNote('Anomaly models left the learned envelope. The lock is no longer behaving like itself.')
          demoHold.current = Date.now()
          return
        }
        if (demoStage === 'detect' && (lockFinding?.risk_score ?? 0) >= 45 && Date.now() - demoHold.current > 1600) {
          setDemoStage('explain')
          setDemoNote(lockFinding?.explanation ?? 'AI is writing the incident narrative and physical-risk forecast.')
          demoHold.current = Date.now()
          return
        }
        if (demoStage === 'explain' && Date.now() - demoHold.current > 2800) {
          setDemoStage('respond')
          setDemoNote('Immune response: force lock, revoke remote unlock, isolate untrusted peers.')
          demoHold.current = Date.now()
          return
        }
        if (demoStage === 'respond') {
          const waited = Date.now() - demoHold.current
          const deniedFollowUp = followUpDenied(lock)
          const verified = Boolean(lock?.verified_containment?.verified) || (contained && deniedFollowUp)
          if (!contained && waited > 8000 && lockFinding && !isControllerActive(controller)) {
            const action = await applyAutonomousAction(
              health.engine,
              DEMO_LOCK,
              lockFinding.risk_score,
              lockFinding.threat_type,
            )
            lastApplied.current[DEMO_LOCK] = { state: action.response_state, at: Date.now() }
            setLastAction(action)
            return
          }
          if (contained && demoContainedAt.current === 0) {
            demoContainedAt.current = Date.now()
            setDemoNote('Containment applied. Attack still running so the next remote unlock can be denied.')
            return
          }
          if (contained && !verified) {
            setDemoNote('Containment applied. Attack still running so the next remote unlock can be denied.')
            return
          }
          if (verified && !demoVerified.current) {
            demoVerified.current = true
            demoHold.current = Date.now()
            const detection = formatLatency(lock?.verified_containment?.detection_latency_ms)
            const containmentMs = formatLatency(lock?.verified_containment?.containment_latency_ms)
            setDemoNote(
              `Verified containment: next unlock DENIED. Detection ${detection}, containment ${containmentMs}.`,
            )
            return
          }
          const holdMs = demoVerified.current ? Date.now() - demoHold.current : 0
          const stuck = contained && !verified && demoContainedAt.current > 0 && Date.now() - demoContainedAt.current > 10000
          if ((verified && holdMs > 2800) || stuck) {
            setAutoRespond(false)
            setDemoStage('recover')
            setDemoNote(
              stuck
                ? 'Containment applied, but no follow-up unlock was observed. Recovering.'
                : 'Campaign stopped. Stepping the lock back toward a trusted state.',
            )
            await stopAttacks()
            await recover(DEMO_LOCK, true)
            await recover(DEMO_CAMERA, true)
            demoHold.current = Date.now()
          }
          return
        }
        if (
          demoStage === 'recover' &&
          (lockState === 'normal' || policyState === 'normal') &&
          attacks.length === 0 &&
          Date.now() - demoHold.current > 2500
        ) {
          setDemoStage('complete')
          setDemoNote('Home restored. SentinelMesh learned, explained, contained, and recovered.')
          setDemoRunning(false)
        }
      } finally {
        demoBusy.current = false
      }
    }

    void advance()
  }, [attacks, controller, modelsReady, demoRunning, demoStage, findings, health.engine, inject, recover, responses, setAutoRespond, snapshot, stopAttacks])

  const samples = snapshot?.devices ?? []
  const simHealthy = health.simulator
  const engineHealthy = health.engine
  const controllerActive = isControllerActive(controller)
  const scenarioClean = isScenarioClean(samples, attacks)
  const meshIncident = incidents[0] ?? null

  return {
    health,
    snapshot,
    inventory,
    attacks,
    findings,
    incidents,
    meshIncident,
    responses,
    selected,
    selectedFinding,
    selectedResponse,
    selectedId: selected?.device_id ?? null,
    setSelectedId,
    events,
    riskHistory,
    lastAction,
    busy,
    error,
    lastError: error,
    analysisSource,
    clock,
    autoRespond,
    setAutoRespond,
    demoStage,
    demoRunning,
    modelsReady,
    scenarioClean,
    demoNote,
    samples,
    selectedSample: selected,
    simHealthy,
    engineHealthy,
    controller,
    controllerActive,
    inject,
    injectAttack: inject,
    stopAttacks,
    recover,
    recoverDevice: recover,
    resetAll,
    resetMesh: resetAll,
    forceTick,
    refresh,
    runDemo,
    stopDemo,
  }
}

export type DashboardModel = ReturnType<typeof useDashboard>

const DashboardContext = createContext<DashboardModel | null>(null)

export function DashboardProvider({ children }: { children: ReactNode }) {
  const model = useDashboard()
  return createElement(DashboardContext.Provider, { value: model }, children)
}

export function useSoc(): DashboardModel {
  const value = useContext(DashboardContext)
  if (!value) {
    throw new Error('useSoc must be used inside DashboardProvider')
  }
  return value
}
