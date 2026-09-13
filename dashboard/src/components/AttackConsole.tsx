import { useState } from "react";
import { Play, RotateCcw, Square, StepForward } from "lucide-react";
import { Chip, Panel } from "./Panel";
import { useSoc } from "../hooks/useDashboard";
import { ATTACK_BLURBS, ATTACK_LABELS, pretty } from "../lib/format";
import type { AttackIntensity, AttackType } from "../types";
import { ATTACK_TYPES } from "../types";

export function AttackConsole() {
  const { samples, attacks, busy, injectAttack, stopAttacks, resetMesh, forceTick, recoverDevice, selectedSample } =
    useSoc();
  const [attackType, setAttackType] = useState<AttackType>("unauthorized_commands");
  const [deviceId, setDeviceId] = useState<string>("auto");
  const [intensity, setIntensity] = useState<AttackIntensity>("high");
  const [duration, setDuration] = useState(90);

  return (
    <Panel
      eyebrow="Red team"
      title="Attack simulation"
      action={
        <Chip className="border-amber-400/30 bg-amber-400/10 text-amber-200">
          {attacks.length} live
        </Chip>
      }
    >
      <div className="space-y-3">
        <div className="grid gap-2">
          {ATTACK_TYPES.map((type) => (
            <button
              key={type}
              type="button"
              onClick={() => setAttackType(type)}
              className={`rounded-lg border px-3 py-2 text-left ${
                attackType === type
                  ? "border-amber-300/50 bg-amber-400/10"
                  : "border-white/8 bg-white/[0.03] hover:border-white/15"
              }`}
            >
              <p className="text-xs font-semibold text-white">{ATTACK_LABELS[type]}</p>
              <p className="mt-0.5 text-[11px] text-slate-400">{ATTACK_BLURBS[type]}</p>
            </button>
          ))}
        </div>

        <label className="block text-[11px] text-slate-400">
          Target
          <select
            value={deviceId}
            onChange={(event) => setDeviceId(event.target.value)}
            className="mt-1 w-full rounded-lg border border-white/10 bg-[#0b1522] px-2 py-2 text-sm text-slate-100"
          >
            <option value="auto">Compatible device (auto)</option>
            {samples.map((sample) => (
              <option key={sample.device_id} value={sample.device_id}>
                {sample.name}
              </option>
            ))}
          </select>
        </label>

        <div className="flex gap-2">
          {(["low", "medium", "high"] as AttackIntensity[]).map((level) => (
            <button
              key={level}
              type="button"
              onClick={() => setIntensity(level)}
              className={`flex-1 rounded-lg border py-1.5 font-mono text-[11px] uppercase ${
                intensity === level
                  ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-100"
                  : "border-white/10 text-slate-400"
              }`}
            >
              {level}
            </button>
          ))}
        </div>

        <label className="block text-[11px] text-slate-400">
          Duration {duration}s
          <input
            type="range"
            min={15}
            max={180}
            value={duration}
            onChange={(event) => setDuration(Number(event.target.value))}
            className="mt-2 w-full"
          />
        </label>

        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void injectAttack({
                attack_type: attackType,
                device_id: deviceId === "auto" ? null : deviceId,
                duration_seconds: duration,
                intensity,
              })
            }
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-rose-500 px-3 py-2 text-sm font-semibold text-white hover:bg-rose-400 disabled:opacity-50"
          >
            <Play className="h-4 w-4" /> Inject
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void stopAttacks()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-slate-200 hover:bg-white/5 disabled:opacity-50"
          >
            <Square className="h-4 w-4" /> Stop
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void forceTick()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-slate-200 hover:bg-white/5 disabled:opacity-50"
          >
            <StepForward className="h-4 w-4" /> Tick
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void resetMesh()}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-slate-200 hover:bg-white/5 disabled:opacity-50"
          >
            <RotateCcw className="h-4 w-4" /> Reset
          </button>
        </div>
        {selectedSample ? (
          <button
            type="button"
            disabled={busy}
            onClick={() => void recoverDevice(selectedSample.device_id)}
            className="w-full rounded-lg border border-emerald-400/30 bg-emerald-400/10 py-2 text-sm text-emerald-100 hover:bg-emerald-400/15 disabled:opacity-50"
          >
            Force recover {selectedSample.name}
          </button>
        ) : null}
        {attacks.length ? (
          <p className="font-mono text-[11px] text-amber-200/80">
            Live: {attacks.map((a) => pretty(a.attack_type)).join(" · ")}
          </p>
        ) : null}
      </div>
    </Panel>
  );
}
