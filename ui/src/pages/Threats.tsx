import { useEffect, useState } from "react";
import { AlertTriangle, Shield, Trash2, Lock, Cpu, Eye } from "lucide-react";
import { useAgentStore } from "../store/useAgentStore";
import { Threat, scoreToRisk } from "../types";
import { RiskBadge } from "../components/ui/RiskBadge";
import { ScoreBar } from "../components/ui/ScoreBar";
import { Modal } from "../components/ui/Modal";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Spinner } from "../components/ui/Spinner";
import { format } from "date-fns";
import { es } from "date-fns/locale";

const METHOD_LABELS: Record<string, string> = {
  Hash: "Hash",
  YARA: "YARA",
  Heuristic: "Heurística",
  Network: "Red",
  Behavior: "Comportamiento",
};

const STATUS_LABELS: Record<string, string> = {
  Active: "Activo",
  Quarantined: "Cuarentena",
  Whitelisted: "Lista blanca",
  Resolved: "Resuelto",
};

export default function Threats() {
  const { threats, fetchThreats, quarantineFile, killProcess } = useAgentStore();
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Threat | null>(null);
  const [confirmKill, setConfirmKill] = useState<Threat | null>(null);
  const [confirmQuarantine, setConfirmQuarantine] = useState<Threat | null>(null);
  const [filterType, setFilterType] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [filterMethod, setFilterMethod] = useState("");
  const [minScore, setMinScore] = useState(0);

  useEffect(() => {
    setLoading(true);
    fetchThreats().finally(() => setLoading(false));
  }, []);

  const filtered = threats.filter((t) => {
    if (filterType && t.threat_type !== filterType) return false;
    if (filterStatus && t.status !== filterStatus) return false;
    if (filterMethod && t.detection_method !== filterMethod) return false;
    if (t.score < minScore) return false;
    return true;
  });

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-threat-high" />
          <h1 className="text-xl font-semibold">Amenazas Detectadas</h1>
          <span className="badge-critical ml-2">{threats.filter((t) => t.status === "Active").length} activas</span>
        </div>
        <button onClick={() => { setLoading(true); fetchThreats().finally(() => setLoading(false)); }} className="btn-ghost flex items-center gap-2">
          {loading ? <Spinner size="sm" /> : null}
          Actualizar
        </button>
      </div>

      {/* Filters */}
      <div className="card flex flex-wrap gap-3">
        <select
          className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
        >
          <option value="">Todos los tipos</option>
          {["Malware", "Ransomware", "PUA", "Suspicious", "Network", "LOLBin"].map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <select
          className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
        >
          <option value="">Todos los estados</option>
          {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>

        <select
          className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
          value={filterMethod}
          onChange={(e) => setFilterMethod(e.target.value)}
        >
          <option value="">Todos los métodos</option>
          {Object.entries(METHOD_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>

        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400">Score mín.</span>
          <input
            type="range" min={0} max={100} value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            className="w-24 accent-shield-500"
          />
          <span className="text-xs font-mono text-gray-300 w-6">{minScore}</span>
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600 text-gray-400 text-xs">
                <th className="text-left px-4 py-3 font-medium">FECHA</th>
                <th className="text-left px-4 py-3 font-medium">NOMBRE / RUTA</th>
                <th className="text-left px-4 py-3 font-medium">TIPO</th>
                <th className="text-left px-4 py-3 font-medium">MÉTODO</th>
                <th className="text-left px-4 py-3 font-medium">SCORE</th>
                <th className="text-left px-4 py-3 font-medium">ESTADO</th>
                <th className="text-left px-4 py-3 font-medium">ACCIONES</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={7} className="text-center py-8 text-gray-500"><Spinner /></td></tr>
              )}
              {!loading && filtered.length === 0 && (
                <tr><td colSpan={7} className="text-center py-8 text-gray-500">No se encontraron amenazas</td></tr>
              )}
              {filtered.map((threat) => (
                <tr
                  key={threat.id}
                  className={`border-b border-surface-600/50 hover:bg-surface-700/50 transition-colors ${
                    threat.score >= 80 ? "bg-threat-critical/5" : threat.score >= 60 ? "bg-threat-high/5" : ""
                  }`}
                >
                  <td className="px-4 py-3 text-xs text-gray-400 font-mono">
                    {format(new Date(threat.detected_at), "dd/MM HH:mm", { locale: es })}
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <div className="font-medium text-gray-200 truncate">{threat.name || "Desconocido"}</div>
                    <div className="text-xs text-gray-500 truncate font-mono">{threat.path || threat.process_name || "—"}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs bg-surface-600 px-2 py-0.5 rounded">{threat.threat_type}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-300">
                    {METHOD_LABELS[threat.detection_method] || threat.detection_method}
                  </td>
                  <td className="px-4 py-3 w-28">
                    <ScoreBar score={threat.score} size="sm" showLabel />
                  </td>
                  <td className="px-4 py-3">
                    <RiskBadge level={scoreToRisk(threat.score)} label={STATUS_LABELS[threat.status] || threat.status} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      <button
                        onClick={() => setSelected(threat)}
                        className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-surface-600 rounded transition-colors"
                        title="Ver detalles"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      {threat.path && threat.status === "Active" && (
                        <button
                          onClick={() => setConfirmQuarantine(threat)}
                          className="p-1.5 text-yellow-400 hover:text-yellow-200 hover:bg-surface-600 rounded transition-colors"
                          title="Mover a cuarentena"
                        >
                          <Lock className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {threat.pid && threat.status === "Active" && (
                        <button
                          onClick={() => setConfirmKill(threat)}
                          className="p-1.5 text-threat-critical hover:text-red-300 hover:bg-surface-600 rounded transition-colors"
                          title="Terminar proceso"
                        >
                          <Cpu className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Modal */}
      {selected && (
        <Modal title="Detalle de Amenaza" onClose={() => setSelected(null)}>
          <div className="space-y-3 text-sm">
            <Row label="Nombre" value={selected.name || "—"} />
            <Row label="Tipo" value={selected.threat_type} />
            <Row label="Ruta" value={selected.path || "—"} mono />
            <Row label="Proceso" value={selected.process_name || "—"} />
            <Row label="PID" value={selected.pid?.toString() || "—"} mono />
            <Row label="Score" value={<ScoreBar score={selected.score} showLabel />} />
            <Row label="Método" value={METHOD_LABELS[selected.detection_method] || selected.detection_method} />
            <Row label="Fuente IOC" value={selected.ioc_source || "—"} />
            <Row label="SHA-256" value={selected.hash_sha256 || "—"} mono />
            <Row label="Detectado" value={format(new Date(selected.detected_at), "dd/MM/yyyy HH:mm:ss")} />
            <Row label="Estado" value={STATUS_LABELS[selected.status] || selected.status} />
            {selected.action_taken && <Row label="Acción tomada" value={selected.action_taken} />}
          </div>
        </Modal>
      )}

      {/* Confirm Kill */}
      <ConfirmDialog
        open={!!confirmKill}
        title="¿Terminar proceso?"
        message={`Se terminará el proceso ${confirmKill?.process_name} (PID: ${confirmKill?.pid}). Esta acción no se puede deshacer.`}
        confirmLabel="Terminar proceso"
        variant="danger"
        onConfirm={async () => {
          if (confirmKill?.pid) await killProcess(confirmKill.pid);
          setConfirmKill(null);
        }}
        onCancel={() => setConfirmKill(null)}
      />

      {/* Confirm Quarantine */}
      <ConfirmDialog
        open={!!confirmQuarantine}
        title="¿Mover a cuarentena?"
        message={`Se moverá el archivo a cuarentena: ${confirmQuarantine?.path}`}
        confirmLabel="Cuarentenar"
        variant="warning"
        onConfirm={async () => {
          if (confirmQuarantine?.path) await quarantineFile(confirmQuarantine.path);
          setConfirmQuarantine(null);
        }}
        onCancel={() => setConfirmQuarantine(null)}
      />
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="text-gray-400 w-28 shrink-0">{label}</span>
      <span className={`text-gray-200 break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
