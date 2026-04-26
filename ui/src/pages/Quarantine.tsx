import { useEffect, useState } from "react";
import { Lock, RotateCcw, Trash2, Eye } from "lucide-react";
import { useAgentStore } from "../store/useAgentStore";
import { QuarantineEntry } from "../types";
import { Modal } from "../components/ui/Modal";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { ScoreBar } from "../components/ui/ScoreBar";
import { Spinner } from "../components/ui/Spinner";
import { format } from "date-fns";
import { es } from "date-fns/locale";

export default function Quarantine() {
  const { quarantine, fetchQuarantine, restoreQuarantine, deleteQuarantine } = useAgentStore();
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<QuarantineEntry | null>(null);
  const [confirmRestore, setConfirmRestore] = useState<QuarantineEntry | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<QuarantineEntry | null>(null);

  useEffect(() => {
    setLoading(true);
    fetchQuarantine().finally(() => setLoading(false));
  }, []);

  const totalSize = quarantine.reduce((acc, q) => acc + (q.file_size || 0), 0);

  function formatBytes(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lock className="w-5 h-5 text-yellow-400" />
          <h1 className="text-xl font-semibold">Cuarentena</h1>
          <span className="text-xs text-gray-400 bg-surface-700 px-2 py-0.5 rounded-full ml-1">
            {quarantine.length} archivos · {formatBytes(totalSize)}
          </span>
        </div>
        <button
          onClick={() => { setLoading(true); fetchQuarantine().finally(() => setLoading(false)); }}
          className="btn-ghost"
        >
          Actualizar
        </button>
      </div>

      <div className="card overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-600 text-gray-400 text-xs">
                <th className="text-left px-4 py-3 font-medium">NOMBRE ORIGINAL</th>
                <th className="text-left px-4 py-3 font-medium">FECHA</th>
                <th className="text-left px-4 py-3 font-medium">AMENAZA</th>
                <th className="text-left px-4 py-3 font-medium">SCORE</th>
                <th className="text-left px-4 py-3 font-medium">TAMAÑO</th>
                <th className="text-left px-4 py-3 font-medium">ESTADO</th>
                <th className="text-left px-4 py-3 font-medium">ACCIONES</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={7} className="text-center py-8"><Spinner /></td></tr>
              )}
              {!loading && quarantine.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-gray-500">
                    <Lock className="w-8 h-8 mx-auto mb-2 opacity-30" />
                    La cuarentena está vacía
                  </td>
                </tr>
              )}
              {quarantine.map((entry) => (
                <tr key={entry.id} className="border-b border-surface-600/50 hover:bg-surface-700/50 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-200">{entry.original_name}</div>
                    <div className="text-xs text-gray-500 font-mono truncate max-w-xs">{entry.original_path}</div>
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400 font-mono">
                    {format(new Date(entry.quarantined_at), "dd/MM HH:mm", { locale: es })}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-300">{entry.threat_name || "—"}</td>
                  <td className="px-4 py-3 w-24">
                    {entry.score != null ? <ScoreBar score={entry.score} size="sm" showLabel /> : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400">
                    {entry.file_size != null ? formatBytes(entry.file_size) : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${
                      entry.status === "Quarantined"
                        ? "bg-yellow-500/20 text-yellow-400"
                        : entry.status === "Restored"
                        ? "bg-shield-500/20 text-shield-400"
                        : "bg-surface-600 text-gray-400"
                    }`}>
                      {entry.status === "Quarantined" ? "En cuarentena" : entry.status === "Restored" ? "Restaurado" : "Eliminado"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1">
                      <button onClick={() => setSelected(entry)} className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-surface-600 rounded" title="Detalles">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                      {entry.status === "Quarantined" && (
                        <>
                          <button onClick={() => setConfirmRestore(entry)} className="p-1.5 text-shield-400 hover:text-shield-200 hover:bg-surface-600 rounded" title="Restaurar">
                            <RotateCcw className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => setConfirmDelete(entry)} className="p-1.5 text-threat-critical hover:text-red-300 hover:bg-surface-600 rounded" title="Eliminar">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </>
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
        <Modal title="Detalles de Cuarentena" onClose={() => setSelected(null)}>
          <div className="space-y-3 text-sm">
            {[
              ["Nombre", selected.original_name],
              ["Ruta original", selected.original_path, true],
              ["ID", selected.id, true],
              ["SHA-256", selected.hash_sha256 || "—", true],
              ["Amenaza", selected.threat_name || "—"],
              ["Método", selected.detection_method || "—"],
              ["Tamaño", selected.file_size != null ? formatBytes(selected.file_size) : "—"],
              ["Fecha", format(new Date(selected.quarantined_at), "dd/MM/yyyy HH:mm:ss")],
            ].map(([label, value, mono]) => (
              <div key={label as string} className="flex gap-3">
                <span className="text-gray-400 w-28 shrink-0">{label}</span>
                <span className={`text-gray-200 break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
              </div>
            ))}
          </div>
        </Modal>
      )}

      <ConfirmDialog
        open={!!confirmRestore}
        title="¿Restaurar archivo?"
        message={`El archivo "${confirmRestore?.original_name}" se moverá de vuelta a:\n${confirmRestore?.original_path}`}
        confirmLabel="Restaurar"
        variant="warning"
        onConfirm={async () => {
          if (confirmRestore) await restoreQuarantine(confirmRestore.id);
          setConfirmRestore(null);
        }}
        onCancel={() => setConfirmRestore(null)}
      />

      <ConfirmDialog
        open={!!confirmDelete}
        title="¿Eliminar permanentemente?"
        message={`El archivo "${confirmDelete?.original_name}" se eliminará de forma definitiva. Esta acción no se puede deshacer.`}
        confirmLabel="Eliminar"
        variant="danger"
        onConfirm={async () => {
          if (confirmDelete) await deleteQuarantine(confirmDelete.id);
          setConfirmDelete(null);
        }}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  );

  function formatBytes(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }
}
