import { Camera, Lock, Plug, Thermometer } from "lucide-react";
import type { DeviceType, TelemetrySample } from "../types";
import { Chip, Panel } from "./Panel";
import { useSoc } from "../hooks/useDashboard";
import { containmentOf, findingFor, pretty, riskColor, statusChip } from "../lib/format";

const LAYOUT: Record<string, { x: number; y: number }> = {
  "cam-front-door": { x: 230, y: 92 },
  "lock-front-door": { x: 230, y: 268 },
  "plug-living-lamp": { x: 560, y: 92 },
  "thermo-hallway": { x: 560, y: 268 },
};

function DeviceGlyph({ type, className }: { type: DeviceType; className?: string }) {
  const props = { className: className ?? "h-4 w-4" };
  if (type === "smart_camera") return <Camera {...props} />;
  if (type === "smart_plug") return <Plug {...props} />;
  if (type === "smart_lock") return <Lock {...props} />;
  return <Thermometer {...props} />;
}

function nodeFill(sample: TelemetrySample, risk: number): string {
  if (containmentOf(sample) === "quarantine" || sample.status === "quarantined") return "#881337";
  if (containmentOf(sample) === "restricted" || sample.status === "restricted") return "#9a3412";
  if (risk >= 45 || sample.status === "compromised") return "#9f1239";
  if (risk >= 20 || sample.status === "degraded" || sample.status === "monitoring") return "#854d0e";
  return "#0f766e";
}

export function TopologyMap() {
  const { samples, findings, selectedId, setSelectedId, meshIncident } = useSoc();
  const hub = { x: 395, y: 180 };
  const remotes = collectRemotes(samples);

  return (
    <Panel
      eyebrow="Mesh"
      title="Network topology"
      icon={<span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />}
      action={<Chip className="border-cyan-400/20 bg-cyan-400/10 text-cyan-200">LAN 192.168.1.0/24</Chip>}
      className="h-full"
    >
      <div className="overflow-hidden rounded-xl border border-white/5 bg-[#070d16]">
        <svg viewBox="0 0 790 360" className="h-[360px] w-full">
          <defs>
            <radialGradient id="hubGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
            </radialGradient>
          </defs>
          {samples.map((sample) => {
            const pos = LAYOUT[sample.device_id] ?? { x: 395, y: 180 };
            const finding = findingFor(findings, sample.device_id);
            const hot = (finding?.risk_score ?? 0) >= 20 || sample.attack_signals.length > 0;
            return (
              <g key={`edge-${sample.device_id}`}>
                <line
                  x1={hub.x}
                  y1={hub.y}
                  x2={pos.x}
                  y2={pos.y}
                  stroke={hot ? "#fb7185" : "#22d3ee"}
                  strokeOpacity={hot ? 0.7 : 0.28}
                  strokeWidth={hot ? 2 : 1.2}
                  className={hot ? "flow-line" : undefined}
                />
              </g>
            );
          })}
          {remotes.map((remote) => (
            <g key={remote.ip}>
              <line
                x1={remote.from.x}
                y1={remote.from.y}
                x2={remote.x}
                y2={remote.y}
                stroke={remote.suspicious ? "#fb7185" : "#64748b"}
                strokeOpacity={0.55}
                strokeWidth={1}
                strokeDasharray={remote.suspicious ? "4 4" : "2 6"}
                className={remote.suspicious ? "flow-line" : undefined}
              />
              <circle
                cx={remote.x}
                cy={remote.y}
                r={7}
                fill={remote.suspicious ? "#9f1239" : "#1e293b"}
                stroke={remote.suspicious ? "#fb7185" : "#94a3b8"}
              />
              <text x={remote.x + 10} y={remote.y + 4} fill="#94a3b8" fontSize="9" fontFamily="IBM Plex Mono">
                {remote.ip}
              </text>
            </g>
          ))}

          {meshIncident ? (
            <g>
              <line
                x1={LAYOUT['cam-front-door'].x}
                y1={LAYOUT['cam-front-door'].y}
                x2={LAYOUT['lock-front-door'].x}
                y2={LAYOUT['lock-front-door'].y}
                stroke="#fb7185"
                strokeOpacity="0.85"
                strokeWidth="2.2"
                strokeDasharray="5 6"
                className="flow-line"
              />
              <text
                x={LAYOUT['cam-front-door'].x + 16}
                y={(LAYOUT['cam-front-door'].y + LAYOUT['lock-front-door'].y) / 2}
                fill="#fda4af"
                fontSize="9"
                fontFamily="IBM Plex Mono"
              >
                shared source
              </text>
            </g>
          ) : null}

          <circle cx={hub.x} cy={hub.y} r="42" fill="url(#hubGlow)" />
          <circle cx={hub.x} cy={hub.y} r="22" fill="#08202b" stroke="#22d3ee" strokeWidth="1.6" />
          <text x={hub.x} y={hub.y - 2} textAnchor="middle" fill="#ecfeff" fontSize="10" fontWeight="600">
            Controller
          </text>
          <text x={hub.x} y={hub.y + 12} textAnchor="middle" fill="#67e8f9" fontSize="8" fontFamily="IBM Plex Mono">
            192.168.1.10
          </text>

          {samples.map((sample) => {
            const pos = LAYOUT[sample.device_id] ?? hub;
            const finding = findingFor(findings, sample.device_id);
            const risk = finding?.risk_score ?? 0;
            const selected = selectedId === sample.device_id;
            const fill = nodeFill(sample, risk);
            return (
              <g
                key={sample.device_id}
                onClick={() => setSelectedId(sample.device_id)}
                className="cursor-pointer"
              >
                {risk >= 45 ? (
                  <circle cx={pos.x} cy={pos.y} r="28" fill={fill} className="pulse-ring" opacity="0.35" />
                ) : null}
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={selected ? 24 : 20}
                  fill={fill}
                  stroke={selected ? "#ecfeff" : riskColor(risk)}
                  strokeWidth={selected ? 2.4 : 1.4}
                />
                <text x={pos.x} y={pos.y + 36} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontWeight="600">
                  {sample.name}
                </text>
                <text x={pos.x} y={pos.y + 50} textAnchor="middle" fill="#94a3b8" fontSize="9" fontFamily="IBM Plex Mono">
                  {sample.network.local_ip} · {pretty(containmentOf(sample))}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="mt-3 flex flex-wrap gap-3 text-[11px] text-slate-400">
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-teal-600" /> Normal</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-600" /> Watch</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-rose-700" /> Threat / contained</span>
        <span className="inline-flex items-center gap-1.5"><Chip className={statusChip("compromised")}>Click a node</Chip></span>
      </div>
      <div className="sr-only">
        {samples.map((s) => (
          <DeviceGlyph key={s.device_id} type={s.device_type} />
        ))}
      </div>
    </Panel>
  );
}

function collectRemotes(samples: TelemetrySample[]) {
  const out: {
    ip: string;
    x: number;
    y: number;
    from: { x: number; y: number };
    suspicious: boolean;
  }[] = [];
  const seen = new Set<string>();
  let index = 0;
  for (const sample of samples) {
    const from = LAYOUT[sample.device_id] ?? { x: 395, y: 180 };
    for (const conn of sample.network.active_connections) {
      if (seen.has(conn.remote_ip) || conn.remote_ip.startsWith("192.168.1.")) continue;
      seen.add(conn.remote_ip);
      const side = from.x < 400 ? 70 : 720;
      out.push({
        ip: conn.remote_ip,
        x: side,
        y: 48 + (index % 6) * 52,
        from,
        suspicious: conn.reputation === "suspicious",
      });
      index += 1;
    }
  }
  return out;
}
