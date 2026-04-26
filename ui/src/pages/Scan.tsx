import { useState } from "react";
import { Search, FolderOpen, Zap, CheckCircle, AlertTriangle } from "lucide-react";
import { api } from "../lib/ipc";
import { ScanResult, scoreToRisk } from "../types";
import { ScoreBar } from "../components/ui/ScoreBar";
import { Spinner } from "../components/ui/Spinner";

type ScanMode = "quick" | "full" | "custom";

const QUICK_PATHS = [
  "C:\\Users",
  "C:\\Windows\\Temp",
  "C:\\Windows\\System32",
  "C:\\ProgramData",
];

export default function Scan() {
  const [mode, setMode] = useState<ScanMode>("quick");
  const [customPath, setCustomPath] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function startScan() {
    if (mode === "custom" && !customPath) return;
    setScanning(true);
    setResult(null);
    setError(null);
    setProgress(0);

    // Simulate progress while waiting
    const progressInterval = setInterval(() => {
      setProgress((p) => Math.min(p + Math.random() * 3, 90));
    }, 500);

    try {
      let scanResult: ScanResult;
      if (mode === "quick") {
        scanResult = await api.scanPath(QUICK_PATHS[0]);
      } else if (mode === "full") {
        scanResult = await api.scanPath("C:\\");
      } else {
        scanResult = await api.scanPath(customPath);
      }
      setProgress(100);
      setResult(scanResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      clearInterval(progressInterval);
      setScanning(false);
    }
  }

  async function pickFolder() {
    try {
      const folder = await api.openFolderDialog();
      if (folder) setCustomPath(folder);
    } catch {
      // dialog cancelled
    }
  }

  return (
    <div className="space-y-4 animate-fade-in max-w-3xl">
      <div className="flex items-center gap-2">
        <Search className="w-5 h-5 text-shield-500" />
        <h1 className="text-xl font-semibold">Escaneo</h1>
      </div>

      {/* Mode selector */}
      <div className="card space-y-4">
        <h2 className="text-sm font-medium text-gray-300">Tipo de escaneo</h2>
        <div className="grid grid-cols-3 gap-3">
          {(["quick", "full", "custom"] as ScanMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`p-4 rounded-xl border text-left transition-colors ${
                mode === m
                  ? "border-shield-500 bg-shield-600/10 text-shield-400"
                  : "border-surface-600 hover:border-surface-500 text-gray-400"
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                {m === "quick" && <Zap className="w-4 h-4" />}
                {m === "full" && <Search className="w-4 h-4" />}
                {m === "custom" && <FolderOpen className="w-4 h-4" />}
                <span className="font-medium">
                  {m === "quick" ? "Rápido" : m === "full" ? "Completo" : "Personalizado"}
                </span>
              </div>
              <p className="text-xs text-gray-500">
                {m === "quick" && "Rutas críticas del sistema"}
                {m === "full" && "Todo el disco (puede tardar)"}
                {m === "custom" && "Selecciona una carpeta"}
              </p>
            </button>
          ))}
        </div>

        {mode === "custom" && (
          <div className="flex gap-2">
            <input
              type="text"
              value={customPath}
              onChange={(e) => setCustomPath(e.target.value)}
              placeholder="C:\\Ruta\\a\\escanear"
              className="flex-1 bg-surface-700 border border-surface-500 rounded-lg px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-shield-500"
            />
            <button onClick={pickFolder} className="btn-ghost px-3 py-2">
              <FolderOpen className="w-4 h-4" />
            </button>
          </div>
        )}

        <button
          onClick={startScan}
          disabled={scanning || (mode === "custom" && !customPath)}
          className="btn-primary w-full flex items-center justify-center gap-2 py-3"
        >
          {scanning ? <Spinner size="sm" /> : <Search className="w-4 h-4" />}
          {scanning ? "Escaneando..." : "Iniciar escaneo"}
        </button>
      </div>

      {/* Progress */}
      {scanning && (
        <div className="card space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-300">Escaneando...</span>
            <span className="text-gray-400 font-mono">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-surface-600 rounded-full h-2">
            <div
              className="bg-shield-500 h-2 rounded-full transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="card border border-threat-critical/30 bg-threat-critical/5">
          <div className="flex items-center gap-2 text-threat-critical">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-sm">{error}</span>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-3 animate-fade-in">
          <div className="card">
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle className="w-5 h-5 text-threat-clean" />
              <h2 className="font-semibold">Resultados del escaneo</h2>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <Stat label="Archivos analizados" value={result.scanned.toLocaleString()} />
              <Stat
                label="Amenazas encontradas"
                value={result.threats_found.toString()}
                highlight={result.threats_found > 0}
              />
              <Stat
                label="Duración"
                value={`${(result.duration_ms / 1000).toFixed(1)}s`}
              />
            </div>
          </div>

          {result.threats.length > 0 && (
            <div className="card overflow-hidden p-0">
              <div className="px-4 py-3 border-b border-surface-600 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-threat-high" />
                <span className="font-medium text-sm">Amenazas encontradas</span>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-surface-600 text-gray-400 text-xs">
                    <th className="text-left px-4 py-2 font-medium">RUTA</th>
                    <th className="text-left px-4 py-2 font-medium">TIPO</th>
                    <th className="text-left px-4 py-2 font-medium">SCORE</th>
                    <th className="text-left px-4 py-2 font-medium">MÉTODO</th>
                  </tr>
                </thead>
                <tbody>
                  {result.threats.map((t) => (
                    <tr key={t.id} className="border-b border-surface-600/50 hover:bg-surface-700/50">
                      <td className="px-4 py-2 font-mono text-xs text-gray-300 truncate max-w-sm">{t.path || t.name || "—"}</td>
                      <td className="px-4 py-2 text-xs">{t.threat_type}</td>
                      <td className="px-4 py-2 w-28"><ScoreBar score={t.score} size="sm" showLabel /></td>
                      <td className="px-4 py-2 text-xs text-gray-400">{t.detection_method}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.threats.length === 0 && (
            <div className="card flex items-center gap-3 text-threat-clean">
              <CheckCircle className="w-5 h-5" />
              <span>No se encontraron amenazas</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="text-center">
      <div className={`text-2xl font-bold ${highlight ? "text-threat-critical" : "text-gray-100"}`}>{value}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  );
}
