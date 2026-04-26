import { create } from "zustand";
import { api } from "@/lib/ipc";
import type {
  AgentStatus,
  Stats,
  Threat,
  Event,
  QuarantineEntry,
  ProcessInfo,
  ConnectionInfo,
  FeedStatus,
} from "@/types";

interface AgentStore {
  // State
  status: AgentStatus | null;
  stats: Stats | null;
  threats: Threat[];
  events: Event[];
  quarantine: QuarantineEntry[];
  processes: ProcessInfo[];
  connections: ConnectionInfo[];
  feedStatus: FeedStatus[];
  isConnected: boolean;
  isProtectionPaused: boolean;
  lastRefresh: Date | null;
  error: string | null;

  // Actions
  fetchAll: () => Promise<void>;
  fetchStatus: () => Promise<void>;
  fetchThreats: () => Promise<void>;
  fetchEvents: () => Promise<void>;
  fetchQuarantine: () => Promise<void>;
  fetchProcesses: () => Promise<void>;
  fetchConnections: () => Promise<void>;
  fetchFeeds: () => Promise<void>;
  pauseProtection: () => Promise<void>;
  resumeProtection: () => Promise<void>;
  killProcess: (pid: number) => Promise<void>;
  quarantineFile: (path: string) => Promise<void>;
  restoreQuarantine: (id: string) => Promise<void>;
  deleteQuarantine: (id: string) => Promise<void>;
  updateFeeds: () => Promise<void>;
  clearError: () => void;
}

export const useAgentStore = create<AgentStore>((set, get) => ({
  status: null,
  stats: null,
  threats: [],
  events: [],
  quarantine: [],
  processes: [],
  connections: [],
  feedStatus: [],
  isConnected: false,
  isProtectionPaused: false,
  lastRefresh: null,
  error: null,

  clearError: () => set({ error: null }),

  fetchStatus: async () => {
    try {
      const [status, stats] = await Promise.all([
        api.getStatus(),
        api.getStats(),
      ]);
      set({
        status,
        stats,
        isConnected: true,
        isProtectionPaused: !status.protection_enabled,
        error: null,
      });
    } catch (err) {
      set({
        isConnected: false,
        error: err instanceof Error ? err.message : "Error de conexion con el agente",
      });
    }
  },

  fetchAll: async () => {
    try {
      const [status, stats, threats, events] = await Promise.all([
        api.getStatus(),
        api.getStats(),
        api.getThreats(100, 0),
        api.getEvents(200, 0),
      ]);
      set({
        status,
        stats,
        threats,
        events,
        isConnected: true,
        isProtectionPaused: !status.protection_enabled,
        lastRefresh: new Date(),
        error: null,
      });
    } catch (err) {
      set({
        isConnected: false,
        error: err instanceof Error ? err.message : "Error de conexion con el agente",
      });
    }
  },

  fetchThreats: async () => {
    try {
      const threats = await api.getThreats(100, 0);
      set({ threats });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Error cargando amenazas" });
    }
  },

  fetchEvents: async () => {
    try {
      const events = await api.getEvents(200, 0);
      set({ events });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Error cargando eventos" });
    }
  },

  fetchQuarantine: async () => {
    try {
      const quarantine = await api.getQuarantine();
      set({ quarantine });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Error cargando cuarentena" });
    }
  },

  fetchProcesses: async () => {
    try {
      const processes = await api.getProcesses();
      set({ processes });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Error cargando procesos" });
    }
  },

  fetchConnections: async () => {
    try {
      const connections = await api.getConnections();
      set({ connections });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Error cargando conexiones" });
    }
  },

  fetchFeeds: async () => {
    try {
      const feedStatus = await api.getFeedStatus();
      set({ feedStatus });
    } catch (err) {
      set({ error: err instanceof Error ? err.message : "Error cargando feeds" });
    }
  },

  pauseProtection: async () => {
    await api.pauseProtection();
    set({ isProtectionPaused: true });
    await get().fetchStatus();
  },

  resumeProtection: async () => {
    await api.resumeProtection();
    set({ isProtectionPaused: false });
    await get().fetchStatus();
  },

  killProcess: async (pid: number) => {
    await api.killProcess(pid);
    await get().fetchProcesses();
  },

  quarantineFile: async (path: string) => {
    await api.quarantineFile(path);
    await Promise.all([get().fetchThreats(), get().fetchQuarantine()]);
  },

  restoreQuarantine: async (id: string) => {
    await api.restoreQuarantine(id);
    await get().fetchQuarantine();
  },

  deleteQuarantine: async (id: string) => {
    await api.deleteQuarantine(id);
    await get().fetchQuarantine();
  },

  updateFeeds: async () => {
    await api.updateFeeds();
    await get().fetchFeeds();
  },
}));
