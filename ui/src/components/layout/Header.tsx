import { RefreshCw, Bell, AlertTriangle } from "lucide-react";
import { clsx } from "clsx";
import { format } from "date-fns";
import { es } from "date-fns/locale";
import { useAgentStore } from "@/store/useAgentStore";
import { StatusIndicator } from "@/components/ui/StatusIndicator";

interface HeaderProps {
  title: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function Header({ title, onRefresh, isRefreshing = false }: HeaderProps) {
  const { lastRefresh, isConnected, stats } = useAgentStore();
  const activeThreats = stats?.threats ?? 0;

  return (
    <header className="h-14 flex-shrink-0 flex items-center justify-between px-6 bg-surface-800 border-b border-surface-600">
      {/* Title */}
      <div>
        <h2 className="font-semibold text-gray-100 text-base">{title}</h2>
        {lastRefresh && (
          <p className="text-xs text-gray-500">
            Actualizado{" "}
            {format(lastRefresh, "HH:mm:ss", { locale: es })}
          </p>
        )}
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        {/* Connection status */}
        <StatusIndicator
          status={isConnected ? "online" : "offline"}
          label={isConnected ? "Conectado" : "Sin conexion"}
          size="sm"
          showPulse={isConnected}
        />

        {/* Threat notifications */}
        {activeThreats > 0 && (
          <div className="flex items-center gap-1.5 bg-threat-critical/10 border border-threat-critical/30 text-threat-critical text-xs px-2.5 py-1 rounded-lg">
            <AlertTriangle size={13} />
            <span className="font-medium">
              {activeThreats} amenaza{activeThreats !== 1 ? "s" : ""} activa
              {activeThreats !== 1 ? "s" : ""}
            </span>
          </div>
        )}

        {/* Notifications bell */}
        <button
          className="btn-ghost p-2 relative"
          aria-label="Notificaciones"
        >
          <Bell size={16} />
          {activeThreats > 0 && (
            <span className="absolute top-1 right-1 h-2 w-2 bg-threat-critical rounded-full" />
          )}
        </button>

        {/* Refresh button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className={clsx(
              "btn-ghost p-2",
              isRefreshing && "opacity-70 cursor-not-allowed"
            )}
            aria-label="Actualizar datos"
          >
            <RefreshCw
              size={16}
              className={clsx(isRefreshing && "animate-spin")}
            />
          </button>
        )}
      </div>
    </header>
  );
}
