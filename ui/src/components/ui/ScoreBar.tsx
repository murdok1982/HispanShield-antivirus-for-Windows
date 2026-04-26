import { clsx } from "clsx";
import { scoreToRisk } from "@/types";

interface ScoreBarProps {
  score: number;
  showLabel?: boolean;
  size?: "sm" | "md";
}

const colorMap = {
  clean: "bg-threat-clean",
  low: "bg-threat-low",
  medium: "bg-threat-medium",
  high: "bg-threat-high",
  critical: "bg-threat-critical",
};

const textColorMap = {
  clean: "text-threat-clean",
  low: "text-threat-low",
  medium: "text-threat-medium",
  high: "text-threat-high",
  critical: "text-threat-critical",
};

export function ScoreBar({ score, showLabel = true, size = "md" }: ScoreBarProps) {
  const risk = scoreToRisk(score);
  const barColor = colorMap[risk];
  const textColor = textColorMap[risk];
  const clampedScore = Math.min(100, Math.max(0, score));

  return (
    <div className={clsx("flex items-center gap-2", size === "sm" ? "w-24" : "w-32")}>
      <div
        className={clsx(
          "flex-1 bg-surface-600 rounded-full overflow-hidden",
          size === "sm" ? "h-1.5" : "h-2"
        )}
      >
        <div
          className={clsx("h-full rounded-full transition-all duration-300", barColor)}
          style={{ width: `${clampedScore}%` }}
        />
      </div>
      {showLabel && (
        <span className={clsx("font-mono text-xs font-medium tabular-nums", textColor)}>
          {score}
        </span>
      )}
    </div>
  );
}
