import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Shield,
  ScanLine,
  AlertTriangle,
  Lock,
  Cpu,
  Network,
  Globe,
  FileText,
  Settings,
} from "lucide-react";
import { clsx } from "clsx";
import { useAgentStore } from "@/store/useAgentStore";
import { StatusIndicator } from "@/components/ui/StatusIndicator";

interface NavItem {
  to: string;
  icon: React.ReactNode;
  label: string;
  badge?: number;
}

function NavItemLink({ item }: { item: NavItem }) {
  const location = useLocation();
  const isActive = location.pathname === item.to;

  return (
    <NavLink
      to={item.to}
      className={clsx(
        "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 relative",
        isActive
          ? "bg-shield-600/20 text-shield-400 border border-shield-600/30"
          : "text-gray-400 hover:text-gray-200 hover:bg-surface-700"
      )}
    >
      <span className={clsx("flex-shrink-0", isActive && "text-shield-400")}>
        {item.icon}
      </span>
      <span className="truncate">{item.label}</span>
      {item.badge !== undefined && item.badge > 0 && (
        <span className="ml-auto bg-threat-critical text-white text-xs font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
          {item.badge > 99 ? "99+" : item.badge}
        </span>
      )}
    </NavLink>
  );
}

export function Sidebar() {
  const { isConnected, isProtectionPaused, stats } = useAgentStore();

  const activeThreats = stats?.threats ?? 0;

  const navItems: NavItem[] = [
    {
      to: "/",
      icon: <LayoutDashboard size={18} />,
      label: "Dashboard",
    },
    {
      to: "/scan",
      icon: <ScanLine size={18} />,
      label: "Escaneo",
    },
    {
      to: "/threats",
      icon: <AlertTriangle size={18} />,
      label: "Amenazas",
      badge: activeThreats,
    },
    {
      to: "/quarantine",
      icon: <Lock size={18} />,
      label: "Cuarentena",
    },
    {
      to: "/processes",
      icon: <Cpu size={18} />,
      label: "Procesos",
    },
    {
      to: "/connections",
      icon: <Network size={18} />,
      label: "Conexiones",
    },
    {
      to: "/intel",
      icon: <Globe size={18} />,
      label: "Inteligencia",
    },
    {
      to: "/logs",
      icon: <FileText size={18} />,
      label: "Logs",
    },
  ];

  const agentIndicatorStatus = isConnected
    ? isProtectionPaused
      ? "warning"
      : "online"
    : "offline";

  return (
    <aside className="w-60 flex-shrink-0 flex flex-col bg-surface-800 border-r border-surface-600 h-screen">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-surface-600">
        <div className="flex items-center gap-3">
          <div className="p-1.5 bg-shield-600/20 rounded-lg border border-shield-600/30">
            <Shield size={22} className="text-shield-400" />
          </div>
          <div>
            <h1 className="font-bold text-gray-100 text-sm leading-tight">
              HispanShield
            </h1>
            <p className="text-xs text-gray-500">Antivirus OS</p>
          </div>
        </div>
      </div>

      {/* Protection Status */}
      <div className="px-4 py-3 border-b border-surface-600">
        <div className="bg-surface-700/50 rounded-lg px-3 py-2.5">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-gray-500 uppercase tracking-wide font-medium">
              Estado
            </span>
          </div>
          <StatusIndicator
            status={agentIndicatorStatus}
            label={
              !isConnected
                ? "Agente desconectado"
                : isProtectionPaused
                ? "Proteccion pausada"
                : "Protegido"
            }
            size="sm"
          />
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavItemLink key={item.to} item={item} />
        ))}
      </nav>

      {/* Footer nav */}
      <div className="px-3 py-3 border-t border-surface-600">
        <NavItemLink
          item={{
            to: "/settings",
            icon: <Settings size={18} />,
            label: "Configuracion",
          }}
        />
      </div>
    </aside>
  );
}
