import { clsx } from "clsx";

type IndicatorStatus = "online" | "offline" | "warning" | "updating";

interface StatusIndicatorProps {
  status: IndicatorStatus;
  label?: string;
  showPulse?: boolean;
  size?: "sm" | "md";
}

const dotClasses: Record<IndicatorStatus, string> = {
  online: "bg-threat-clean",
  offline: "bg-threat-critical",
  warning: "bg-threat-medium",
  updating: "bg-shield-500",
};

const pulseClasses: Record<IndicatorStatus, string> = {
  online: "bg-threat-clean",
  offline: "bg-threat-critical",
  warning: "bg-threat-medium",
  updating: "bg-shield-500",
};

export function StatusIndicator({
  status,
  label,
  showPulse = true,
  size = "md",
}: StatusIndicatorProps) {
  const dotSize = size === "sm" ? "h-2 w-2" : "h-3 w-3";
  const pulseSize = size === "sm" ? "h-2 w-2" : "h-3 w-3";

  return (
    <div className="flex items-center gap-2">
      <div className="relative flex items-center justify-center">
        {showPulse && (status === "online" || status === "updating") && (
          <div
            className={clsx(
              "absolute animate-ping opacity-75 rounded-full",
              pulseSize,
              pulseClasses[status]
            )}
          />
        )}
        <div
          className={clsx("relative rounded-full", dotSize, dotClasses[status])}
        />
      </div>
      {label && (
        <span
          className={clsx(
            "font-medium",
            size === "sm" ? "text-xs" : "text-sm",
            status === "online" && "text-threat-clean",
            status === "offline" && "text-threat-critical",
            status === "warning" && "text-threat-medium",
            status === "updating" && "text-shield-500"
          )}
        >
          {label}
        </span>
      )}
    </div>
  );
}
