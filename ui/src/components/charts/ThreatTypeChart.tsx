import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import type { Threat } from "@/types";

interface ThreatTypeChartProps {
  threats: Threat[];
}

const COLORS: Record<string, string> = {
  Malware: "#ef4444",
  Ransomware: "#dc2626",
  PUA: "#eab308",
  Suspicious: "#f97316",
  Network: "#3b82f6",
  LOLBin: "#a855f7",
};

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; payload: { fill: string } }>;
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const item = payload[0];
  return (
    <div className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-2 shadow-xl text-xs">
      <p style={{ color: item.payload.fill }} className="font-semibold">
        {item.name}
      </p>
      <p className="text-gray-400">
        Cantidad: <span className="text-gray-200 font-mono">{item.value}</span>
      </p>
    </div>
  );
}

export function ThreatTypeChart({ threats }: ThreatTypeChartProps) {
  const counts: Record<string, number> = {};
  for (const t of threats) {
    counts[t.threat_type] = (counts[t.threat_type] ?? 0) + 1;
  }

  const data = Object.entries(counts).map(([name, value]) => ({
    name,
    value,
    fill: COLORS[name] ?? "#6b7280",
  }));

  if (data.length === 0) {
    return (
      <div className="h-[200px] flex items-center justify-center text-gray-500 text-sm">
        Sin datos de amenazas
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={75}
          paddingAngle={3}
          dataKey="value"
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.fill} />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend
          wrapperStyle={{ fontSize: "11px" }}
          formatter={(value) => (
            <span style={{ color: "#9ca3af" }}>{value}</span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
