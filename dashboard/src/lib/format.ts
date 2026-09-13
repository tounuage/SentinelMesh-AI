import type { AnalysisResult, AttackType, DeviceStatus, DeviceType, ResponseState, TelemetrySample } from "../types";

export const DEVICE_LABELS: Record<DeviceType, string> = {
  smart_camera: "Smart Camera",
  smart_plug: "Smart Plug",
  smart_thermostat: "Thermostat",
  smart_lock: "Smart Lock",
};

export const ATTACK_LABELS: Record<AttackType, string> = {
  abnormal_network_traffic: "Abnormal network traffic",
  unauthorized_commands: "Unauthorized commands",
  suspicious_ip_connections: "Suspicious IP connections",
  firmware_modification: "Firmware modification",
  abnormal_power_usage: "Abnormal power usage",
};

export const ATTACK_BLURBS: Record<AttackType, string> = {
  abnormal_network_traffic: "Burst egress, unusual ports, possible exfil.",
  unauthorized_commands: "Unauthenticated lock/HVAC control from hostile IPs.",
  suspicious_ip_connections: "C2-style sessions to documentation-range hosts.",
  firmware_modification: "Unsigned OTA image and checksum mismatch.",
  abnormal_power_usage: "Load spike consistent with mining or stuck actuators.",
};

const RESPONSE_RANK: Record<string, number> = {
  normal: 0,
  monitor: 1,
  restricted: 2,
  quarantine: 3,
};

export function pretty(value: string): string {
  return value.replaceAll("_", " ");
}

export function titleCase(value: string): string {
  return pretty(value).replace(/\b\w/g, (ch) => ch.toUpperCase());
}

export function formatTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function formatRoom(room: string): string {
  return titleCase(room);
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function riskTone(score: number): "ok" | "watch" | "high" | "crit" {
  if (score >= 75) return "crit";
  if (score >= 45) return "high";
  if (score >= 20) return "watch";
  return "ok";
}

export function riskColor(score: number): string {
  const tone = riskTone(score);
  if (tone === "crit") return "#f43f5e";
  if (tone === "high") return "#fb923c";
  if (tone === "watch") return "#fbbf24";
  return "#34d399";
}

export function statusColor(status: DeviceStatus | string): string {
  switch (status) {
    case "online":
      return "text-emerald-300";
    case "monitoring":
      return "text-cyan-300";
    case "degraded":
      return "text-amber-300";
    case "restricted":
      return "text-orange-300";
    case "compromised":
    case "quarantined":
      return "text-rose-300";
    default:
      return "text-slate-400";
  }
}

export function statusChip(status: DeviceStatus | string): string {
  switch (status) {
    case "online":
      return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
    case "monitoring":
      return "border-cyan-400/30 bg-cyan-400/10 text-cyan-200";
    case "degraded":
      return "border-amber-400/30 bg-amber-400/10 text-amber-200";
    case "restricted":
      return "border-orange-400/30 bg-orange-400/10 text-orange-200";
    case "compromised":
    case "quarantined":
      return "border-rose-400/40 bg-rose-500/15 text-rose-200";
    default:
      return "border-slate-500/30 bg-slate-500/10 text-slate-300";
  }
}

export function responseChip(state: string): string {
  switch (state) {
    case "normal":
      return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
    case "monitor":
      return "border-cyan-400/30 bg-cyan-400/10 text-cyan-200";
    case "restricted":
      return "border-orange-400/30 bg-orange-400/10 text-orange-200";
    case "quarantine":
      return "border-rose-400/40 bg-rose-500/15 text-rose-200";
    default:
      return "border-slate-500/30 bg-slate-500/10 text-slate-300";
  }
}

export function containmentOf(sample?: TelemetrySample | null, fallback?: string | null): ResponseState {
  const fromSample = normalizeState(sample?.containment?.response_state)
  const fromFallback = normalizeState(fallback)
  return RESPONSE_RANK[fromSample] >= RESPONSE_RANK[fromFallback] ? fromSample : fromFallback
}

function normalizeState(value?: string | null): ResponseState {
  if (value === "monitor" || value === "restricted" || value === "quarantine") return value
  return "normal"
}

export function desiredState(score: number, threat: string): ResponseState {
  const byRisk: ResponseState =
    score >= 75 ? "quarantine" : score >= 45 ? "restricted" : score >= 20 ? "monitor" : "normal";
  const floor: ResponseState =
    threat === "firmware_modification" || threat === "multi_stage_compromise"
      ? "quarantine"
      : threat === "benign" || threat === "unknown_anomaly"
        ? threat === "unknown_anomaly" && score >= 20
          ? "monitor"
          : "normal"
        : "restricted";
  if (threat === "benign") return byRisk;
  return (RESPONSE_RANK[byRisk] ?? 0) >= (RESPONSE_RANK[floor] ?? 0) ? byRisk : floor;
}

export function findingFor(
  findings: AnalysisResult[],
  deviceId: string,
): AnalysisResult | undefined {
  return findings.find((item) => item.device === deviceId);
}

export function highestRisk(findings: AnalysisResult[]): AnalysisResult | undefined {
  return [...findings].sort((a, b) => b.risk_score - a.risk_score)[0];
}
