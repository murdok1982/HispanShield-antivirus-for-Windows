import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Lock,
  Database,
  Activity,
  Shield,
  ShieldOff,
  ScanLine,
  RefreshCw,
  CheckCircle,
  Clock,
} from "lucide-react";
import { format } from "date-fns";
import { es } from "date-fns/locale";
import { clsx } from "clsx";
import { useAgentStore } from "@/store/useAgentStore";
import { Header } from "@/components/layout/Header";
import { EventsChart } from "@/components/charts/EventsChart";
import { ThreatTypeChart } from "@/components/charts/ThreatTypeChart";
import { ScoreBar } from "@/components/ui/ScoreBar";
import { ThreatTypeBadge, StatusBadge } from "@/components/ui/RiskBadge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Spinner } from "@/components/ui/Spinner";
import type { ChartDataPoint } from "@/types";
import { formatUptime } from "@/types";

interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  variant?: "default" | "danger" | "warning" | "success";
  sub?: string;
}

function StatCard({ label, value, icon, variant = "default", sub }: StatCardProps) {
  const variantClasses = {
    default: "border-surface-600",
    danger: "border-threat-critical/40 bg-threat-critical/5",
    warning: "border-threat-medium/40 bg-threat-medium/5",
    success: "border-threat-clean/30 bg-threat-clean/5",
  };
  const iconClasses = {
    default: "text-shield-400 bg-shield-600/20",
    danger: "text-threat-critical bg-threat-critical/20",
    warning: "text-threat-medium bg-threat-medium/20",
    success: "text-threat-clean bg-threat-clean/20",
  };

  return (
    <div className={clsx("card", variantClasses[variant])}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wide font-medium mb-1">
            {label}
          </p>
          <p
            className={clsx(
              "text-3xl font-bold font-mono tabular-nums",
              variant === "danger" && "text-threat-critical",
              variant === "warning" && "text-threat-medium",
              variant === "success" && "text-threat-clean",
              variant === "default" && "text-gray-100"
            )}
          >
            {typeof value === "number" ? value.toLocaleString() : value}
          </p>
          {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
        </div>
        <div className={clsx("p-2.5 rounded-xl", iconClasses[variant])}>
          {icon}
        </div>
      </div>
    </div>
  );
}

function generateChartData(events: { timestamp: string; threat_type?: string; event_type?: string }[]): ChartDataPoint[] {
  const now = new Date();
  const hours: ChartDataPoint[] = [];

  for (let i = 23; i >= 0; i--) {
    const hour = new Date(now);
    hour.setHours(hour.getHours() - i, 0, 0, 0);
    const label = format(hour, "HH:00");
    const hourStart = hour.getTime();
    const hourEnd = hourStart + 3600000;

    let eventsCount = 0;
    let threatsCount = 0;

    for (const e of events) {
      const ts = new Date(e.timestamp).getTime();
      if (ts >= hourStart && ts < hourEnd) {
        eventsCount++;
        if ("threat_type" in e) threatsCount++;
      }
    }

    hours.push({ time: label, events: eventsCount, threats: threatsCount });
  }

  return hours;
}

export function Dashboard() {
  const navigate = useNavigate();
  const {
    status,
    stats,
    threats,
    events,
    feedStatus,
    connections,
    isConnected,
    isProtectionPaused,
    fetchAll,
    fetchFeeds,
    fetchConnections,
    pauseProtection,
    resumeProtection,
  } = useAgentStore();

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isTogglingProtection, setIsTogglingProtection] = useState(false);

  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    await Promise.all([fetchAll(), fetchFeeds(), fetchConnections()]);
    setIsRefreshing(false);
  }, [fetchAll, fetchFeeds, fetchConnections]);

  useEffect(() => {
    void refresh();
    const interval = setInterval(() => void refresh(), 30000);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleToggleProtection = async () => {
    setIsTogglingProtection(true);
    try {
      if (isProtectionPaused) {
        await resumeProtection();
      } else {
        await pauseProtection();
      }
    } finally {
      setIsTogglingProtection(false);
    }
  };

  const chartData = generateChartData(events);
  const recentThreats = threats.slice(0, 5);
  const topConnections = [...connections]
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Dashboard" onRefresh={refresh} isRefreshing={isRefreshing} />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Stats row */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard
            label="Amenazas activas"
            value={stats?.threats ?? 0}
            icon={<AlertTriangle size={20} />}
            variant={(stats?.threats ?? 0) > 0 ? "danger" : "success"}
            sub={(stats?.threats ?? 0) > 0 ? "Requieren atencion" : "Todo limpio"}
          />
          <StatCard
            label="En cuarentena"
            value={stats?.quarantined ?? 0}
            icon={<Lock size={20} />}
            variant={(stats?.quarantined ?? 0) > 0 ? "warning" : "default"}
          />
          <StatCard
            label="IOCs cargados"
            value={stats?.ioc_count?.toLocaleString() ?? "0"}
            icon={<Database size={20} />}
            variant="default"
            sub="Firmas activas"
          />
          <StatCard
            label="Eventos hoy"
            value={stats?.events_today ?? 0}
            icon={<Activity size={20} />}
            variant="default"
          />
        </div>

        {/* Main row */}
        <div className="grid grid-cols-3 gap-4">
          {/* Protection status */}
          <div className="card col-span-1 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-300">
                Estado de proteccion
              </h3>
              <StatusIndicator
                status={
                  !isConnected
                    ? "offline"
                    : isProtectionPaused
                    ? "warning"
                    : "online"
                }
                size="sm"
              />
            </div>

            {/* Big status badge */}
            <div
              className={clsx(
                "rounded-xl p-4 flex flex-col items-center gap-2 text-center",
                !isConnected && "bg-surface-700 border border-surface-500",
                isConnected &&
                  !isProtectionPaused &&
                  "bg-threat-clean/10 border border-threat-clean/30",
                isConnected &&
                  isProtectionPaused &&
                  "bg-threat-medium/10 border border-threat-medium/30"
              )}
            >
              {!isConnected ? (
                <ShieldOff size={32} className="text-gray-500" />
              ) : isProtectionPaused ? (
                <ShieldOff size={32} className="text-threat-medium" />
              ) : (
                <Shield size={32} className="text-threat-clean" />
              )}
              <span
                className={clsx(
                  "font-bold text-lg",
                  !isConnected && "text-gray-500",
                  isConnected && !isProtectionPaused && "text-threat-clean",
                  isConnected && isProtectionPaused && "text-threat-medium"
                )}
              >
                {!isConnected
                  ? "DESCONECTADO"
                  : isProtectionPaused
                  ? "PAUSADO"
                  : "PROTEGIDO"}
              </span>
              {status && (
                <span className="text-xs text-gray-500 font-mono">
                  v{status.version}
                </span>
              )}
            </div>

            {/* Info rows */}
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-gray-500 flex items-center gap-1.5">
                  <Clock size={13} />
                  Uptime
                </span>
                <span className="text-gray-300 font-mono text-xs">
                  {status ? formatUptime(status.uptime_seconds) : "--"}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-500 flex items-center gap-1.5">
                  <RefreshCw size={13} />
                  Ultima actualizacion
                </span>
                <span className="text-gray-300 text-xs">
                  {status?.last_update
                    ? format(new Date(status.last_update), "dd/MM HH:mm", {
                        locale: es,
                      })
                    : "--"}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-500">Procesos mon.</span>
                <span className="text-gray-300 font-mono text-xs">
                  {stats?.processes_monitored ?? 0}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-500">Conexiones activas</span>
                <span className="text-gray-300 font-mono text-xs">
                  {stats?.connections_active ?? 0}
                </span>
              </div>
            </div>

            {/* Actions */}
            <div className="flex flex-col gap-2 mt-auto">
              <button
                onClick={handleToggleProtection}
                disabled={!isConnected || isTogglingProtection}
                className={clsx(
                  "w-full text-sm py-2 rounded-lg font-medium transition-colors disabled:opacity-50",
                  isProtectionPaused
                    ? "bg-threat-clean/20 hover:bg-threat-clean/30 text-threat-clean border border-threat-clean/30"
                    : "bg-threat-medium/20 hover:bg-threat-medium/30 text-threat-medium border border-threat-medium/30"
                )}
              >
                {isTogglingProtection
                  ? "Procesando..."
                  : isProtectionPaused
                  ? "Reanudar proteccion"
                  : "Pausar proteccion"}
              </button>
              <button
                onClick={() => void navigate("/scan")}
                className="w-full btn-primary text-sm py-2 flex items-center justify-center gap-2"
              >
                <ScanLine size={15} />
                Escaneo rapido
              </button>
            </div>
          </div>

          {/* Events chart */}
          <div className="card col-span-2">
            <h3 className="text-sm font-semibold text-gray-300 mb-4">
              Actividad ultimas 24h
            </h3>
            {isRefreshing && events.length === 0 ? (
              <div className="h-[200px] flex items-center justify-center">
                <Spinner size="lg" />
              </div>
            ) : (
              <EventsChart data={chartData} />
            )}
          </div>
        </div>

        {/* Bottom row */}
        <div className="grid grid-cols-3 gap-4">
          {/* Recent threats */}
          <div className="card col-span-2">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-300">
                Amenazas recientes
              </h3>
              <button
                onClick={() => void navigate("/threats")}
                className="text-xs text-shield-400 hover:text-shield-300 transition-colors"
              >
                Ver todas
              </button>
            </div>
            {recentThreats.length === 0 ? (
              <div className="flex flex-col items-center py-8 gap-2 text-gray-500">
                <CheckCircle size={28} className="text-threat-clean/60" />
                <p className="text-sm">Sin amenazas detectadas</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-surface-600">
                      <th className="text-left text-gray-500 pb-2 font-medium">
                        Hora
                      </th>
                      <th className="text-left text-gray-500 pb-2 font-medium">
                        Nombre
                      </th>
                      <th className="text-left text-gray-500 pb-2 font-medium">
                        Tipo
                      </th>
                      <th className="text-left text-gray-500 pb-2 font-medium">
                        Score
                      </th>
                      <th className="text-left text-gray-500 pb-2 font-medium">
                        Metodo
                      </th>
                      <th className="text-left text-gray-500 pb-2 font-medium">
                        Estado
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentThreats.map((threat) => (
                      <tr
                        key={threat.id}
                        className="border-b border-surface-600/50 table-row-hover"
                      >
                        <td className="py-2 text-gray-500 font-mono">
                          {format(new Date(threat.detected_at), "HH:mm:ss")}
                        </td>
                        <td className="py-2 text-gray-200 max-w-[140px] truncate pr-2">
                          {threat.name ?? threat.path?.split("\\").pop() ?? "Desconocido"}
                        </td>
                        <td className="py-2">
                          <ThreatTypeBadge type={threat.threat_type} />
                        </td>
                        <td className="py-2">
                          <ScoreBar score={threat.score} size="sm" />
                        </td>
                        <td className="py-2 text-gray-400">
                          {threat.detection_method}
                        </td>
                        <td className="py-2">
                          <StatusBadge status={threat.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Feed status */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-300">
                Feeds de inteligencia
              </h3>
              <button
                onClick={() => void navigate("/intel")}
                className="text-xs text-shield-400 hover:text-shield-300 transition-colors"
              >
                Ver todos
              </button>
            </div>
            <div className="space-y-2.5">
              {feedStatus.length === 0 ? (
                <div className="text-gray-500 text-xs text-center py-4">
                  Sin datos de feeds
                </div>
              ) : (
                feedStatus.map((feed) => (
                  <div
                    key={feed.name}
                    className="flex items-center justify-between py-1.5 border-b border-surface-600/40 last:border-0"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <div
                        className={clsx(
                          "h-2 w-2 rounded-full flex-shrink-0",
                          feed.status === "OK" && "bg-threat-clean",
                          feed.status === "Error" && "bg-threat-critical",
                          feed.status === "Updating" && "bg-shield-500 animate-pulse",
                          feed.status === "Pending" && "bg-gray-500"
                        )}
                      />
                      <span className="text-xs text-gray-300 truncate">
                        {feed.name}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 font-mono flex-shrink-0 ml-2">
                      {feed.ioc_count.toLocaleString()}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Top connections + Threat type chart */}
        <div className="grid grid-cols-2 gap-4">
          {/* Top connections */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-gray-300">
                Conexiones de mayor riesgo
              </h3>
              <button
                onClick={() => void navigate("/connections")}
                className="text-xs text-shield-400 hover:text-shield-300 transition-colors"
              >
                Ver todas
              </button>
            </div>
            {topConnections.length === 0 ? (
              <p className="text-gray-500 text-xs text-center py-4">
                Sin conexiones activas
              </p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-surface-600">
                    <th className="text-left text-gray-500 pb-2 font-medium">
                      Proceso
                    </th>
                    <th className="text-left text-gray-500 pb-2 font-medium">
                      Destino
                    </th>
                    <th className="text-left text-gray-500 pb-2 font-medium">
                      Score
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topConnections.map((conn) => (
                    <tr
                      key={conn.id}
                      className="border-b border-surface-600/50 table-row-hover"
                    >
                      <td className="py-2 text-gray-300 max-w-[100px] truncate">
                        {conn.process_name}
                      </td>
                      <td className="py-2 text-gray-400 font-mono">
                        {conn.remote_addr}:{conn.remote_port}
                      </td>
                      <td className="py-2">
                        <ScoreBar score={conn.score} size="sm" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Threat type distribution */}
          <div className="card">
            <h3 className="text-sm font-semibold text-gray-300 mb-2">
              Distribucion de amenazas
            </h3>
            <ThreatTypeChart threats={threats} />
          </div>
        </div>
      </div>
    </div>
  );
}
