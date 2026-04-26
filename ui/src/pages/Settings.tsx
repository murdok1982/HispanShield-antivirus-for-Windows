import { useState } from "react";
import { Settings as SettingsIcon, Save, Plus, X, Shield, Globe, Lock, Sliders } from "lucide-react";
import { Spinner } from "../components/ui/Spinner";
import { api } from "../lib/ipc";

export default function Settings() {
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [exclusion, setExclusion] = useState("");
  const [exclusions, setExclusions] = useState<string[]>([]);

  const [protection, setProtection] = useState({
    realtime_enabled: true,
    scan_on_access: true,
    scan_on_execute: true,
    monitor_network: true,
    monitor_registry: true,
    action_on_threat: "Quarantine" as "AlertOnly" | "Quarantine" | "Block" | "KillAndQuarantine",
  });

  const [scoring, setScoring] = useState({
    alert_threshold: 30,
    high_threshold: 60,
    critical_threshold: 80,
  });

  const [feeds, setFeeds] = useState({
    auto_update: true,
    update_interval_hours: 6,
  });

  async function handleSave() {
    setSaving(true);
    try {
      await api.setConfig({ protection, scoring, feeds });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      console.error(e);
    } finally {
      setSaving(false);
    }
  }

  function addExclusion() {
    const val = exclusion.trim();
    if (val && !exclusions.includes(val)) {
      setExclusions([...exclusions, val]);
      api.addException(val).catch(console.error);
    }
    setExclusion("");
  }

  return (
    <div className="space-y-5 animate-fade-in max-w-2xl">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-shield-500" />
          <h1 className="text-xl font-semibold">Configuración</h1>
        </div>
        <button onClick={handleSave} disabled={saving} className="btn-primary flex items-center gap-2">
          {saving ? <Spinner size="sm" /> : <Save className="w-4 h-4" />}
          {saved ? "¡Guardado!" : "Guardar cambios"}
        </button>
      </div>

      {/* Protection */}
      <section className="card space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Shield className="w-4 h-4 text-shield-500" /> Protección en tiempo real
        </h2>
        {([
          { key: "realtime_enabled", label: "Activar protección en tiempo real" },
          { key: "scan_on_access", label: "Escanear al acceder a archivos" },
          { key: "scan_on_execute", label: "Escanear al ejecutar procesos" },
          { key: "monitor_network", label: "Monitorizar conexiones de red" },
          { key: "monitor_registry", label: "Monitorizar cambios en registro" },
        ] as const).map(({ key, label }) => (
          <div key={key} className="flex items-center justify-between">
            <span className="text-sm text-gray-300">{label}</span>
            <button
              onClick={() => setProtection((p) => ({ ...p, [key]: !p[key] }))}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                protection[key] ? "bg-shield-500" : "bg-surface-500"
              }`}
            >
              <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
                protection[key] ? "translate-x-4" : "translate-x-0.5"
              }`} />
            </button>
          </div>
        ))}

        <div className="flex items-center justify-between pt-2 border-t border-surface-600">
          <span className="text-sm text-gray-300">Acción ante amenaza detectada</span>
          <select
            value={protection.action_on_threat}
            onChange={(e) => setProtection((p) => ({ ...p, action_on_threat: e.target.value as typeof p.action_on_threat }))}
            className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
          >
            <option value="AlertOnly">Solo alertar</option>
            <option value="Quarantine">Cuarentenar automáticamente</option>
            <option value="Block">Bloquear y alertar</option>
            <option value="KillAndQuarantine">Matar proceso y cuarentenar</option>
          </select>
        </div>
      </section>

      {/* Scoring thresholds */}
      <section className="card space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Sliders className="w-4 h-4 text-shield-500" /> Umbrales de puntuación
        </h2>
        {([
          { key: "alert_threshold", label: "Umbral de alerta (sospechoso)", color: "text-threat-medium" },
          { key: "high_threshold", label: "Umbral alto (peligroso)", color: "text-threat-high" },
          { key: "critical_threshold", label: "Umbral crítico (malicioso)", color: "text-threat-critical" },
        ] as const).map(({ key, label, color }) => (
          <div key={key} className="space-y-1">
            <div className="flex justify-between">
              <span className="text-sm text-gray-300">{label}</span>
              <span className={`text-sm font-mono font-bold ${color}`}>{scoring[key]}</span>
            </div>
            <input
              type="range" min={0} max={100} step={5}
              value={scoring[key]}
              onChange={(e) => setScoring((s) => ({ ...s, [key]: Number(e.target.value) }))}
              className="w-full accent-shield-500"
            />
          </div>
        ))}
        <div className="text-xs text-gray-500 bg-surface-700/50 rounded p-2">
          <strong className="text-threat-clean">0-{scoring.alert_threshold - 1}</strong> Limpio ·{" "}
          <strong className="text-threat-medium">{scoring.alert_threshold}-{scoring.high_threshold - 1}</strong> Sospechoso ·{" "}
          <strong className="text-threat-high">{scoring.high_threshold}-{scoring.critical_threshold - 1}</strong> Alto riesgo ·{" "}
          <strong className="text-threat-critical">{scoring.critical_threshold}-100</strong> Crítico
        </div>
      </section>

      {/* Feeds config */}
      <section className="card space-y-4">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Globe className="w-4 h-4 text-shield-500" /> Inteligencia de amenazas
        </h2>
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-300">Actualización automática de feeds</span>
          <button
            onClick={() => setFeeds((f) => ({ ...f, auto_update: !f.auto_update }))}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
              feeds.auto_update ? "bg-shield-500" : "bg-surface-500"
            }`}
          >
            <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
              feeds.auto_update ? "translate-x-4" : "translate-x-0.5"
            }`} />
          </button>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-300">Intervalo de actualización</span>
          <select
            value={feeds.update_interval_hours}
            onChange={(e) => setFeeds((f) => ({ ...f, update_interval_hours: Number(e.target.value) }))}
            className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none"
          >
            <option value={1}>Cada hora</option>
            <option value={6}>Cada 6 horas</option>
            <option value={12}>Cada 12 horas</option>
            <option value={24}>Cada 24 horas</option>
          </select>
        </div>
      </section>

      {/* Exclusions */}
      <section className="card space-y-3">
        <h2 className="font-semibold text-gray-200 flex items-center gap-2">
          <Lock className="w-4 h-4 text-shield-500" /> Rutas excluidas
        </h2>
        <div className="flex gap-2">
          <input
            type="text"
            value={exclusion}
            onChange={(e) => setExclusion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addExclusion()}
            placeholder="C:\\Ruta\\a\\excluir"
            className="flex-1 bg-surface-700 border border-surface-500 rounded-lg px-3 py-1.5 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-shield-500"
          />
          <button onClick={addExclusion} className="btn-primary px-3">
            <Plus className="w-4 h-4" />
          </button>
        </div>
        {exclusions.length === 0 && (
          <p className="text-xs text-gray-500">No hay rutas excluidas configuradas.</p>
        )}
        <div className="space-y-1">
          {exclusions.map((path) => (
            <div key={path} className="flex items-center justify-between bg-surface-700/50 px-3 py-2 rounded-lg">
              <span className="text-xs font-mono text-gray-300 truncate">{path}</span>
              <button
                onClick={() => setExclusions(exclusions.filter((e) => e !== path))}
                className="text-gray-500 hover:text-threat-critical transition-colors ml-2 shrink-0"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
