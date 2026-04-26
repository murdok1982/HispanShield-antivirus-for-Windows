import { useEffect, useState } from "react";
import { Cpu, RefreshCw, ShieldOff, X } from "lucide-react";
import { useAgentStore } from "../store/useAgentStore";
import { ProcessInfo, scoreToRisk } from "../types";
import { ScoreBar } from "../components/ui/ScoreBar";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Spinner } from "../components/ui/Spinner";
import { clsx } from "clsx";

export default function Processes() {
  const { processes, fetchProcesses, killProcess } = useAgentStore();
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [sortBy, setSortBy] = useState<"score" | "name" | "pid" | "connections">("score");
  const [confirmKill, setConfirmKill] = useState<ProcessInfo | null>(null);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 15000);
    return () => clearInterval(id);
  }, []);

  function refresh() {
    setLoading(true);
    fetchProcesses().finally(() => setLoading(false));
  }

  const filtered = processes
    .filter((p) => {
      if (!filter) return true;
      return (
        p.name.toLowerCase().includes(filter.toLowerCase()) ||
        p.pid.toString().includes(filter) ||
        (p.path || "").toLowerCase().includes(filter.toLowerCase())
      );
    })
    .sort((a, b) => {
      if (sortBy === "score") return b.score - a.score;
      if (sortBy === "name") return a.name.localeCompare(b.name);
      if (sortBy === "pid") return a.pid - b.pid;
      if (sortBy === "connections") return b.connections - a.connections;
      return 0;
    });

  function rowBg(score: number) {
    if (score >= 80) return "bg-threat-critical/5 hover:bg-threat-critical/10";
    if (score >= 60) return "bg-threat-high/5 hover:bg-threat-high/10";
    if (score >= 30) return "bg-threat-medium/5 hover:bg-threat-medium/10";
    return "hover:bg-surface-700/50";
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu className="w-5 h-5 text-shield-500" />
          <h1 className="text-xl font-semibold">Procesos Activos</h1>
          <span className="text-xs text-gray-400 bg-surface-700 px-2 py-0.5 rounded-full">
            {processes.length}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {loading && <Spinner size="sm" />}
          <span className="text-xs text-gray-500">Auto-actualiza cada 15s</span>
          <button onClick={refresh} className="btn-ghost p-2">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Controls */}
      <div className="card flex gap-3 items-center">
        <input
          type="text"
          placeholder="Filtrar por nombre, PID o ruta..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
        />
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
          className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
        >
          <option value="score">Ordenar: Score</option>
          <option value="name">Ordenar: Nombre</option>
          <option value="pid">Ordenar: PID</option>
          <option value="connections">Ordenar: Conexiones</option>
        </select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600 text-gray-400 text-xs">
                <th className="text-left px-4 py-3 font-medium">PID</th>
                <th className="text-left px-4 py-3 font-medium">PROCESO</th>
                <th className="text-left px-4 py-3 font-medium">RUTA</th>
                <th className="text-left px-4 py-3 font-medium">FIRMA</th>
                <th className="text-left px-4 py-3 font-medium">CONEX.</th>
                <th className="text-left px-4 py-3 font-medium">SCORE</th>
                <th className="text-left px-4 py-3 font-medium">FLAGS</th>
                <th className="text-left px-4 py-3 font-medium">ACCIÓN</th>
              </tr>
            </thead>
            <tbody>
              {loading && filtered.length === 0 && (
                <tr><td colSpan={8} className="text-center py-8"><Spinner /></td></tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={8} className="text-center py-8 text-gray-500">No hay procesos</td></tr>
              )}
              {filtered.map((proc) => (
                <tr key={proc.pid} className={`border-b border-surface-600/50 transition-colors ${rowBg(proc.score)}`}>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-400">{proc.pid}</td>
                  <td className="px-4 py-2.5 font-medium text-gray-200">{proc.name}</td>
                  <td className="px-4 py-2.5 max-w-xs">
                    <span className="text-xs font-mono text-gray-500 truncate block">{proc.path || "—"}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={clsx("text-xs px-2 py-0.5 rounded-full", proc.signed ? "bg-threat-clean/20 text-threat-clean" : "bg-threat-high/20 text-threat-high")}>
                      {proc.signed ? "✓ Firmado" : "✗ Sin firma"}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-400 font-mono">{proc.connections}</td>
                  <td className="px-4 py-2.5 w-28">
                    <ScoreBar score={proc.score} size="sm" showLabel />
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {(proc.flags || []).map((flag) => (
                        <span key={flag} className="text-xs bg-threat-high/20 text-threat-high px-1.5 py-0.5 rounded">
                          {flag}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => setConfirmKill(proc)}
                      className="p-1.5 text-threat-critical hover:text-red-300 hover:bg-surface-600 rounded transition-colors"
                      title="Terminar proceso"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <ConfirmDialog
        open={!!confirmKill}
        title="¿Terminar proceso?"
        message={`Se terminará "${confirmKill?.name}" (PID: ${confirmKill?.pid}). Los trabajos no guardados se perderán.`}
        confirmLabel="Terminar"
        variant="danger"
        onConfirm={async () => {
          if (confirmKill) await killProcess(confirmKill.pid);
          setConfirmKill(null);
        }}
        onCancel={() => setConfirmKill(null)}
      />
    </div>
  );
}
