import { Brain } from "lucide-react";
import { Chip, Panel } from "./Panel";
import { useSoc } from "../hooks/useDashboard";
import { pretty } from "../lib/format";

export function ExplanationPanel() {
  const { selectedSample, selectedFinding, selectedResponse, engineHealthy } = useSoc();
  const action = selectedResponse?.last_action;

  return (
    <Panel
      eyebrow="Analyst narrative"
      title="AI explanations"
      icon={<Brain className="h-4 w-4 text-violet-300" />}
      action={
        <Chip className="border-violet-400/30 bg-violet-400/10 text-violet-200">
          {engineHealthy ? "Security engine" : "On-box heuristic"}
          {selectedFinding?.source === "heuristic" ? " fallback" : ""}
        </Chip>
      }
    >
      {!selectedSample || !selectedFinding ? (
        <p className="text-sm text-slate-400">Select a device to inspect model reasoning.</p>
      ) : (
        <div className="space-y-3">
          <div>
            <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">Why this is flagged</p>
            <p className="mt-1 text-sm leading-relaxed text-slate-200">{selectedFinding.explanation}</p>
          </div>
          <div className="rounded-xl border border-white/8 bg-black/20 p-3">
            <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">
              Recommended action
            </p>
            <p className="mt-1 text-sm text-cyan-50">{selectedFinding.recommended_action}</p>
          </div>
          {action ? (
            <div className="space-y-2">
              <p className="font-mono text-[10px] tracking-[0.18em] text-cyan-400/70 uppercase">
                Autonomous rationale
              </p>
              <p className="text-sm text-slate-300">{action.rationale}</p>
              <ul className="space-y-1 font-mono text-[11px] text-slate-400">
                {action.steps_executed.map((step) => (
                  <li key={step} className="flex gap-2">
                    <span className="text-cyan-400">›</span>
                    {step}
                  </li>
                ))}
              </ul>
              <div className="flex flex-wrap gap-1.5">
                {action.effects?.network_blocking.applied ? (
                  <Chip className="border-orange-400/30 text-orange-200">
                    net {pretty(action.effects.network_blocking.mode)}
                  </Chip>
                ) : null}
                {action.effects?.safe_operation_mode.applied ? (
                  <Chip className="border-amber-400/30 text-amber-200">safe mode</Chip>
                ) : null}
                {action.enforced ? (
                  <Chip className="border-emerald-400/30 text-emerald-200">enforced</Chip>
                ) : (
                  <Chip className="border-slate-500/30 text-slate-300">decision only</Chip>
                )}
              </div>
            </div>
          ) : null}
        </div>
      )}
    </Panel>
  );
}
