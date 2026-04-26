import { clsx } from "clsx";
import type { RiskLevel } from "@/types";
import { scoreToRisk, riskLabel } from "@/types";

interface RiskBadgeProps {
  level?: RiskLevel;
  score?: number;
  className?: string;
}

const badgeClasses: Record<RiskLevel, string> = {
  clean: "badge-clean",
  low: "badge-low",
  medium: "badge-medium",
  high: "badge-high",
  critical: "badge-critical",
};

export function RiskBadge({ level, score, className }: RiskBadgeProps) {
  const risk = level ?? (score !== undefined ? scoreToRisk(score) : "clean");
  return (
    <span className={clsx(badgeClasses[risk], className)}>
      {riskLabel(risk)}
    </span>
  );
}

interface ThreatTypeBadgeProps {
  type: string;
  className?: string;
}

const threatTypeClasses: Record<string, string> = {
  Malware: "bg-threat-critical/20 text-threat-critical",
  Ransomware: "bg-red-900/40 text-red-300",
  PUA: "bg-threat-medium/20 text-threat-medium",
  Suspicious: "bg-threat-high/20 text-threat-high",
  Network: "bg-blue-500/20 text-blue-300",
  LOLBin: "bg-purple-500/20 text-purple-300",
};

export function ThreatTypeBadge({ type, className }: ThreatTypeBadgeProps) {
  const cls = threatTypeClasses[type] ?? "bg-surface-600 text-gray-300";
  return (
    <span
      className={clsx(
        "text-xs px-2 py-0.5 rounded-full font-medium",
        cls,
        className
      )}
    >
      {type}
    </span>
  );
}

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const severityClasses: Record<string, string> = {
  Info: "bg-blue-500/20 text-blue-300",
  Low: "badge-low",
  Medium: "badge-medium",
  High: "badge-high",
  Critical: "badge-critical",
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const cls = severityClasses[severity] ?? "bg-surface-600 text-gray-300";
  return (
    <span
      className={clsx(
        "text-xs px-2 py-0.5 rounded-full font-medium",
        cls,
        className
      )}
    >
      {severity}
    </span>
  );
}

interface StatusBadgeProps {
  status: string;
  className?: string;
}

const statusClasses: Record<string, string> = {
  Active: "badge-critical",
  Quarantined: "badge-medium",
  Whitelisted: "badge-clean",
  Resolved: "bg-surface-500 text-gray-400",
  OK: "badge-clean",
  Error: "badge-critical",
  Updating: "badge-medium",
  Pending: "bg-surface-500 text-gray-400",
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const cls = statusClasses[status] ?? "bg-surface-500 text-gray-400";
  return (
    <span
      className={clsx(
        "text-xs px-2 py-0.5 rounded-full font-medium",
        cls,
        className
      )}
    >
      {status}
    </span>
  );
}
