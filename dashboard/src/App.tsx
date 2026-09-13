import { DashboardProvider } from './hooks/useDashboard'
import { AlertFeed } from './components/AlertFeed'
import { AttackConsole } from './components/AttackConsole'
import { DemoRail } from './components/DemoRail'
import { DeviceGrid } from './components/DeviceGrid'
import { DeviceInspector } from './components/DeviceInspector'
import { ExplanationPanel } from './components/ExplanationPanel'
import { HomeFloor } from './components/HomeFloor'
import { KillChain } from './components/KillChain'
import { KpiStrip } from './components/KpiStrip'
import { MeshIncidentCard } from './components/MeshIncidentCard'
import { PhysicalRiskPanel } from './components/PhysicalRiskPanel'
import { RiskPanel } from './components/RiskPanel'
import { StatusTimeline } from './components/StatusTimeline'
import { TopBar } from './components/TopBar'
import { TopologyMap } from './components/TopologyMap'
import { VerifiedContainmentPanel } from './components/VerifiedContainment'

function Shell() {
  return (
    <div className="soc-shell scanlines min-h-screen mesh-grid">
      <TopBar />
      <main className="mx-auto max-w-[1680px] space-y-4 px-4 py-4">
        <DemoRail />
        <KpiStrip />
        <div className="grid items-start gap-4 xl:grid-cols-[1.35fr_0.9fr]">
          <div className="space-y-4">
            <HomeFloor />
            <KillChain />
            <MeshIncidentCard />
            <VerifiedContainmentPanel />
            <DeviceGrid />
          </div>
          <div className="space-y-4">
            <DeviceInspector />
            <PhysicalRiskPanel />
            <ExplanationPanel />
            <AttackConsole />
          </div>
        </div>
        <div className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr_0.9fr]">
          <TopologyMap />
          <RiskPanel />
          <div className="space-y-4">
            <AlertFeed />
            <StatusTimeline />
          </div>
        </div>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <DashboardProvider>
      <Shell />
    </DashboardProvider>
  )
}
