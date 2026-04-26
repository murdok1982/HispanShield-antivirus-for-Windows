import { useEffect, useState } from "react";
import { FileText, RefreshCw } from "lucide-react";
import { useAgentStore } from "../store/useAgentStore";
import { Event } from "../types";
import { Spinner } from "../components/ui/Spinner";
import { format } from "date-fns";
import { es } from "date-fns/locale";
import { clsx } from "clsx";

const SEVERITY_STYLES: Record<string, string> = {
  Info: "text-gray-400",
  Low: "text-threat-low",
  Medium: "text-threat-medium",
  High: "text-threat-high",
  Critical: "text-threat-critical",
};

const SEVERITY_BADGE: Record<string, string> = {
  Info: "bg-gray-500/20 text-gray-400",
  Low: "bg-threat-low/20 text-threat-low",
  Medium: "bg-threat-medium/20 text-threat-medium",
  High: "bg-threat-high/20 text-threat-high",
  Critical: "bg-threat-critical/20 text-threat-critical",
};

export default function Logs() {
  const { events, fetchEvents } = useAgentStore();
  const [loading, setLoading] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterType, setFilterType] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 30000);
    return () => clearInterval(id);
  }, []);

  function refresh() {
    setLoading(true);
    fetchEvents().finally(() => setLoading(false));
  }

  const eventTypes = [...new Set(events.map((e) => e.event_type))].sort();

  const filtered = events.filter((e) => {
    if (filterSeverity && e.severity !== filterSeverity) return false;
    if (filterType && e.event_type !== filterType) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        e.event_type.toLowerCase().includes(q) ||
        (e.path || "").toLowerCase().includes(q) ||
        (e.process_name || "").toLowerCase().includes(q) ||
        (e.details || "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText className="w-5 h-5 text-shield-500" />
          <h1 className="text-xl font-semibold">Logs y Eventos</h1>
          <span className="text-xs text-gray-400 bg-surface-700 px-2 py-0.5 rounded-full">{events.length}</span>
        </div>
        <button onClick={refresh} className="btn-ghost flex items-center gap-2">
          {loading ? <Spinner size="sm" /> : <RefreshCw className="w-4 h-4" />}
        </button>
      </div>

      {/* Filters */}
      <div className="card flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Buscar en logs..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-48 bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
        />
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
        >
          <option value="">Toda severidad</option>
          {["Info", "Low", "Medium", "High", "Critical"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
        >
          <option value="">Todos los tipos</option>
          {eventTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {/* Log table */}
      <div className="card overflow-hidden p-0">
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-800 z-10">
              <tr className="border-b border-surface-600 text-gray-400 text-xs">
                <th className="text-left px-4 py-3 font-medium">FECHA</th>
                <th className="text-left px-4 py-3 font-medium">SEVERIDAD</th>
                <th className="text-left px-4 py-3 font-medium">TIPO</th>
                <th className="text-left px-4 py-3 font-medium">MÓDULO</th>
                <th className="text-left px-4 py-3 font-medium">RUTA / PROCESO</th>
                <th className="text-left px-4 py-3 font-medium">SCORE</th>
                <th className="text-left px-4 py-3 font-medium">DETALLES</th>
              </tr>
            </thead>
            <tbody>
              {loading && filtered.length === 0 && (
                <tr><td colSpan={7} className="text-center py-8"><Spinner /></td></tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={7} className="text-center py-8 text-gray-500">Sin eventos</td></tr>
              )}
              {filtered.map((event) => (
                <tr key={event.id} className="border-b border-surface-600/30 hover:bg-surface-700/30 transition-colors">
                  <td className="px-4 py-2 text-xs font-mono text-gray-500 whitespace-nowrap">
                    {format(new Date(event.timestamp), "HH:mm:ss", { locale: es })}
                    <div className="text-gray-600 text-xs">
                      {format(new Date(event.timestamp), "dd/MM/yy")}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className={clsx("text-xs px-2 py-0.5 rounded-full", SEVERITY_BADGE[event.severity] || "bg-surface-600 text-gray-400")}>
                      {event.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-gray-300">{event.event_type}</td>
                  <td className="px-4 py-2 text-xs text-gray-500">{event.source || "—"}</td>
                  <td className="px-4 py-2">
                    <div className="text-xs font-mono text-gray-400 truncate max-w-xs">
                      {event.path || event.process_name || "—"}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-xs font-mono">
                    {event.score != null && (
                      <span className={clsx(
                        "px-1.5 py-0.5 rounded",
                        event.score >= 80 ? "bg-threat-critical/20 text-threat-critical" :
                        event.score >= 60 ? "bg-threat-high/20 text-threat-high" :
                        event.score >= 30 ? "bg-threat-medium/20 text-threat-medium" :
                        "text-gray-500"
                      )}>
                        {event.score}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs text-gray-500 max-w-xs truncate">
                    {event.details ? (
                      <span title={event.details}>{event.details.substring(0, 60)}{event.details.length > 60 ? "…" : ""}</span>
                    ) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
