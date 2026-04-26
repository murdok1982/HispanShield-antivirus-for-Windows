import { useEffect, useState } from "react";
import { Globe, RefreshCw, CheckCircle, XCircle, Clock, Search, AlertTriangle } from "lucide-react";
import { useAgentStore } from "../store/useAgentStore";
import { FeedStatus } from "../types";
import { Spinner } from "../components/ui/Spinner";
import { api } from "../lib/ipc";
import { format, formatDistanceToNow } from "date-fns";
import { es } from "date-fns/locale";

export default function ThreatIntel() {
  const { feedStatus, fetchFeeds, updateFeeds, stats } = useAgentStore();
  const [updating, setUpdating] = useState(false);
  const [searchValue, setSearchValue] = useState("");
  const [searchType, setSearchType] = useState("sha256");
  const [searchResult, setSearchResult] = useState<string | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    fetchFeeds();
  }, []);

  async function handleUpdateAll() {
    setUpdating(true);
    try {
      await updateFeeds();
      await fetchFeeds();
    } finally {
      setUpdating(false);
    }
  }

  async function handleSearch() {
    if (!searchValue.trim()) return;
    setSearching(true);
    setSearchResult(null);
    try {
      const result = await api.call<{ found: boolean; ioc?: unknown }>("search_ioc", {
        ioc_type: searchType,
        value: searchValue.trim(),
      });
      setSearchResult(result?.found ? JSON.stringify(result.ioc, null, 2) : "No encontrado en cache local");
    } catch (e) {
      setSearchResult(`Error: ${e}`);
    } finally {
      setSearching(false);
    }
  }

  function FeedStatusIcon({ status }: { status: FeedStatus["status"] }) {
    switch (status) {
      case "OK": return <CheckCircle className="w-4 h-4 text-threat-clean" />;
      case "Error": return <XCircle className="w-4 h-4 text-threat-critical" />;
      case "Updating": return <Spinner size="sm" />;
      default: return <Clock className="w-4 h-4 text-gray-500" />;
    }
  }

  const totalIOCs = feedStatus.reduce((a, f) => a + (f.ioc_count || 0), 0);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-shield-500" />
          <h1 className="text-xl font-semibold">Inteligencia de Amenazas</h1>
        </div>
        <button onClick={handleUpdateAll} disabled={updating} className="btn-primary flex items-center gap-2">
          {updating ? <Spinner size="sm" /> : <RefreshCw className="w-4 h-4" />}
          Actualizar todos los feeds
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Total IOCs", value: totalIOCs.toLocaleString(), color: "text-shield-400" },
          { label: "Feeds activos", value: feedStatus.filter(f => f.status === "OK").length.toString(), color: "text-threat-clean" },
          { label: "Feeds con error", value: feedStatus.filter(f => f.status === "Error").length.toString(), color: "text-threat-critical" },
          { label: "Eventos hoy", value: (stats?.events_today || 0).toLocaleString(), color: "text-gray-300" },
        ].map((s) => (
          <div key={s.label} className="card text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-gray-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Feed list */}
      <div className="card space-y-2">
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Feeds OSINT</h2>
        {feedStatus.length === 0 && (
          <div className="text-gray-500 text-sm text-center py-6">Sin datos de feeds</div>
        )}
        {feedStatus.map((feed) => (
          <div key={feed.name} className="flex items-center gap-4 p-3 bg-surface-700/50 rounded-lg">
            <FeedStatusIcon status={feed.status} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-sm text-gray-200">{feed.name}</span>
                <span className={`text-xs px-2 py-0.5 rounded-full ${
                  feed.status === "OK" ? "bg-threat-clean/20 text-threat-clean" :
                  feed.status === "Error" ? "bg-threat-critical/20 text-threat-critical" :
                  feed.status === "Updating" ? "bg-shield-500/20 text-shield-400" :
                  "bg-surface-600 text-gray-400"
                }`}>
                  {feed.status === "OK" ? "Activo" : feed.status === "Error" ? "Error" : feed.status === "Updating" ? "Actualizando" : "Pendiente"}
                </span>
              </div>
              <div className="flex gap-4 mt-0.5">
                <span className="text-xs text-gray-400">
                  {feed.ioc_count.toLocaleString()} IOCs
                </span>
                {feed.last_updated && (
                  <span className="text-xs text-gray-500">
                    Actualizado {formatDistanceToNow(new Date(feed.last_updated), { addSuffix: true, locale: es })}
                  </span>
                )}
                {feed.next_update && (
                  <span className="text-xs text-gray-500">
                    Próx. actualización: {formatDistanceToNow(new Date(feed.next_update), { addSuffix: true, locale: es })}
                  </span>
                )}
                {feed.error_msg && (
                  <span className="text-xs text-threat-critical truncate">{feed.error_msg}</span>
                )}
              </div>
            </div>
            <button
              onClick={handleUpdateAll}
              className="btn-ghost p-1.5 shrink-0"
              title="Actualizar este feed"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>

      {/* IOC Search */}
      <div className="card space-y-3">
        <h2 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
          <Search className="w-4 h-4" />
          Buscar IOC en cache local
        </h2>
        <div className="flex gap-2">
          <select
            value={searchType}
            onChange={(e) => setSearchType(e.target.value)}
            className="bg-surface-700 border border-surface-500 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-shield-500"
          >
            <option value="sha256">SHA-256</option>
            <option value="md5">MD5</option>
            <option value="sha1">SHA-1</option>
            <option value="ip">IP</option>
            <option value="domain">Dominio</option>
            <option value="url">URL</option>
          </select>
          <input
            type="text"
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder="Introduce el valor a buscar..."
            className="flex-1 bg-surface-700 border border-surface-500 rounded-lg px-3 py-2 text-sm text-gray-200 font-mono focus:outline-none focus:ring-1 focus:ring-shield-500"
          />
          <button onClick={handleSearch} disabled={searching || !searchValue.trim()} className="btn-primary flex items-center gap-2">
            {searching ? <Spinner size="sm" /> : <Search className="w-4 h-4" />}
            Buscar
          </button>
        </div>
        {searchResult && (
          <div className={`p-3 rounded-lg text-sm font-mono text-xs whitespace-pre-wrap ${
            searchResult.includes("No encontrado") ? "bg-threat-clean/10 text-threat-clean" : "bg-threat-critical/10 text-threat-critical"
          }`}>
            {searchResult}
          </div>
        )}
      </div>
    </div>
  );
}
