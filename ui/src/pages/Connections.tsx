import { useEffect, useState } from "react";
import { Network, RefreshCw, AlertTriangle, ShieldOff } from "lucide-react";
import { useAgentStore } from "../store/useAgentStore";
import { ConnectionInfo } from "../types";
import { ScoreBar } from "../components/ui/ScoreBar";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Spinner } from "../components/ui/Spinner";
import { api } from "../lib/ipc";

export default function Connections() {
  const { connections, fetchConnections } = useAgentStore();
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [confirmBlock, setConfirmBlock] = useState<ConnectionInfo | null>(null);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 10000);
    return () => clearInterval(id);
  }, []);

  function refresh() {
    setLoading(true);
    fetchConnections().finally(() => setLoading(false));
  }

  const filtered = connections.filter((c) => {
    if (!filter) return true;
    return (
      c.remote_addr.includes(filter) ||
      c.process_name.toLowerCase().includes(filter.toLowerCase()) ||
      c.pid.toString().includes(filter) ||
      c.remote_port.toString().includes(filter)
    );
  });

  const alerts = filtered.filter((c) => c.score >= 30);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-shield-500" />
          <h1 className="text-xl font-semibold">Conexiones de Red</h1>
          {alerts.length > 0 && (
            <span className="badge-critical">{alerts.length} alertas</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {loading && <Spinner size="sm" />}
          <span className="text-xs text-gray-500">Auto-actualiza cada 10s</span>
          <button onClick={refresh} className="btn-ghost p-2">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter */}
      <div className="card py-3">
        <input
          type="text"
          placeholder="Filtrar por proceso, IP, puerto..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
        />
      </div>

      {/* Alerts banner */}
      {alerts.length > 0 && (
        <div className="card border border-threat-high/30 bg-threat-high/5">
          <div className="flex items-center gap-2 text-threat-high text-sm">
            <AlertTriangle className="w-4 h-4" />
            <span>{alerts.length} conexión(es) con score de riesgo elevado</span>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="card overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600 text-gray-400 text-xs">
                <th className="text-left px-4 py-3 font-medium">PROCESO</th>
                <th className="text-left px-4 py-3 font-medium">PID</th>
                <th className="text-left px-4 py-3 font-medium">ORIGEN</th>
                <th className="text-left px-4 py-3 font-medium">DESTINO</th>
                <th className="text-left px-4 py-3 font-medium">PROTO</th>
                <th className="text-left px-4 py-3 font-medium">ESTADO</th>
                <th className="text-left px-4 py-3 font-medium">SCORE</th>
                <th className="text-left px-4 py-3 font-medium">IOC</th>
                <th className="text-left px-4 py-3 font-medium">ACCIÓN</th>
              </tr>
            </thead>
            <tbody>
              {loading && filtered.length === 0 && (
                <tr><td colSpan={9} className="text-center py-8"><Spinner /></td></tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={9} className="text-center py-8 text-gray-500">Sin conexiones activas</td></tr>
              )}
              {filtered.map((conn) => (
                <tr
                  key={conn.id}
                  className={`border-b border-surface-600/50 transition-colors ${
                    conn.ioc_match ? "bg-threat-critical/5 hover:bg-threat-critical/10" :
                    conn.score >= 60 ? "bg-threat-high/5 hover:bg-threat-high/10" :
                    conn.score >= 30 ? "bg-threat-medium/5 hover:bg-threat-medium/10" :
                    "hover:bg-surface-700/50"
                  }`}
                >
                  <td className="px-4 py-2.5 font-medium text-gray-200">{conn.process_name}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-400">{conn.pid}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-400">
                    {conn.local_addr}:{conn.local_port}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs">
                    <span className={conn.ioc_match ? "text-threat-critical font-medium" : "text-gray-300"}>
                      {conn.remote_addr}:{conn.remote_port}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs bg-surface-600 px-1.5 py-0.5 rounded">{conn.protocol}</span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-400">{conn.state}</td>
                  <td className="px-4 py-2.5 w-24">
                    <ScoreBar score={conn.score} size="sm" showLabel />
                  </td>
                  <td className="px-4 py-2.5">
                    {conn.ioc_match && (
                      <span className="text-xs bg-threat-critical/20 text-threat-critical px-2 py-0.5 rounded-full">
                        IOC match
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <button
                      onClick={() => setConfirmBlock(conn)}
                      className="p-1.5 text-threat-high hover:text-orange-300 hover:bg-surface-600 rounded transition-colors"
                      title="Bloquear IP en firewall"
                    >
                      <ShieldOff className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <ConfirmDialog
        open={!!confirmBlock}
        title="¿Bloquear IP?"
        message={`Se añadirá ${confirmBlock?.remote_addr} a la lista de bloqueo de IOCs y se creará una regla en el Firewall de Windows.`}
        confirmLabel="Bloquear"
        variant="warning"
        onConfirm={async () => {
          if (confirmBlock) {
            await api.blockIoc("ip", confirmBlock.remote_addr);
          }
          setConfirmBlock(null);
        }}
        onCancel={() => setConfirmBlock(null)}
      />
    </div>
  );
}
