import { ArrowRight, Brain, Radar, ShieldCheck } from "lucide-react";
import { Chip } from "./Panel";
import { useSoc } from "../hooks/useDashboard";
import { containmentOf, responseChip, riskColor, statusChip } from "../lib/format";

export function KillChain() {
  const { selectedSample, selectedFinding, selectedResponse, autoRespond, controllerActive } = useSoc();
  if (!selectedSample) {
    return (
      <section className="panel rounded-2xl px-4 py-6 text-center text-sm text-slate-400">
        Waiting for simulator telemetry…
      </section>
    );
  }

  const detectionLive =
    selectedSample.attack_signals.length > 0 ||
    selectedSample.anomaly_indicators.length > 0 ||
    (selectedFinding?.risk_score ?? 0) >= 20;
  const reasoningLive = Boolean(selectedFinding);
  const responseState = containmentOf(
    selectedSample,
    selectedResponse?.response_state ?? selectedFinding?.response_state ?? "normal",
  );
  const verified = Boolean(selectedSample.verified_containment?.verified);
  const responseLive = responseState !== "normal" || Boolean(selectedFinding?.defensive_action) || verified;

  const stages = [
    {
      key: "detect",
      icon: Radar,
      label: "Detection",
      live: detectionLive,
      kicker: detectionLive ? "Anomaly observed" : "Baseline",
      body: detectionLive
        ? [...selectedSample.attack_signals, ...selectedSample.anomaly_indicators].slice(0, 3).join(" · ") ||
          "Behavioral deviation from device profile"
        : "No hostile indicators on this tick",
    },
    {
      key: "reason",
      icon: Brain,
      label: "AI reasoning",
      live: reasoningLive && (selectedFinding?.threat_type ?? "benign") !== "benign",
      kicker: selectedFinding
        ? `${selectedFinding.threat_type.replaceAll("_", " ")} · risk ${selectedFinding.risk_score.toFixed(1)}`
        : "Waiting",
      body: selectedFinding?.explanation ?? "Security engine has not produced an explanation yet.",
    },
    {
      key: "respond",
      icon: ShieldCheck,
      label: "Autonomous response",
      live: (responseLive && responseState !== "normal") || verified,
      kicker: verified ? "Verified" : controllerActive ? `Controller ${responseState}` : autoRespond ? `Policy ${responseState}` : "Paused",
      body: verified
        ? "Next hostile unlock was denied. The lock changed behavior; this is not just a red risk score."
        : selectedFinding?.defensive_action ??
          selectedFinding?.recommended_action ??
          "Allow all activity until risk exceeds policy thresholds.",
    },
  ];

  return (
    <section className="panel overflow-hidden rounded-2xl">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyan-500/10 px-4 py-3">
        <div>
          <p className="font-mono text-[10px] tracking-[0.22em] text-cyan-400/70 uppercase">
            Decision pipeline
          </p>
          <h2 className="text-sm font-semibold text-white">
            Detection → AI reasoning → Autonomous response
          </h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Chip className={statusChip(selectedSample.status)}>{selectedSample.status}</Chip>
          <Chip className={responseChip(responseState)}>{responseState}</Chip>
          <span className="font-mono text-[11px] text-slate-400">{selectedSample.name}</span>
        </div>
      </div>
      <div className="grid gap-0 lg:grid-cols-[1fr_auto_1fr_auto_1fr]">
        {stages.map((stage, index) => (
          <div key={stage.key} className="contents">
            <div className="relative p-4">
              <div
                className={`mb-3 flex items-center gap-2 ${stage.live ? "text-cyan-200" : "text-slate-400"}`}
              >
                <span
                  className={`flex h-8 w-8 items-center justify-center rounded-lg border ${
                    stage.live
                      ? "border-cyan-400/40 bg-cyan-400/10"
                      : "border-white/10 bg-white/5"
                  }`}
                >
                  <stage.icon className="h-4 w-4" />
                </span>
                <div>
                  <p className="font-mono text-[10px] tracking-[0.18em] uppercase">0{index + 1}</p>
                  <p className="text-sm font-semibold text-white">{stage.label}</p>
                </div>
              </div>
              <p className="text-xs font-medium" style={{ color: stage.live ? riskColor(72) : "#94a3b8" }}>
                {stage.kicker}
              </p>
              <p className="mt-2 line-clamp-4 text-sm leading-relaxed text-slate-300">{stage.body}</p>
            </div>
            {index < stages.length - 1 ? (
              <div className="hidden items-center justify-center text-cyan-500/70 lg:flex">
                <ArrowRight className={`h-5 w-5 ${stage.live ? "opacity-100" : "opacity-30"}`} />
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </section>
  );
}
