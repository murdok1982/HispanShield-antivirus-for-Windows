import { invoke } from "@tauri-apps/api/core";
import type {
  AgentStatus,
  Stats,
  Threat,
  Event,
  QuarantineEntry,
  ProcessInfo,
  ConnectionInfo,
  FeedStatus,
  ScanResult,
} from "@/types";

async function call<T>(method: string, params?: unknown): Promise<T> {
  return invoke<T>("ipc_call", { method, params: params ?? null });
}

export const api = {
  getStatus: () => call<AgentStatus>("get_status"),
  getStats: () => call<Stats>("get_stats"),
  getThreats: (limit = 100, offset = 0) =>
    call<Threat[]>("get_threats", { limit, offset }),
  getEvents: (limit = 200, offset = 0) =>
    call<Event[]>("get_events", { limit, offset }),
  getQuarantine: () => call<QuarantineEntry[]>("get_quarantine"),
  getProcesses: () => call<ProcessInfo[]>("get_processes"),
  getConnections: () => call<ConnectionInfo[]>("get_connections"),
  getFeedStatus: () => call<FeedStatus[]>("get_feed_status"),
  scanFile: (path: string) => call<ScanResult>("scan_file", { path }),
  scanPath: (path: string) => call<ScanResult>("scan_path", { path }),
  quarantineFile: (path: string) =>
    call<void>("quarantine_file", { path }),
  restoreQuarantine: (id: string) =>
    call<void>("restore_quarantine", { id }),
  deleteQuarantine: (id: string) =>
    call<void>("delete_quarantine", { id }),
  killProcess: (pid: number) => call<void>("kill_process", { pid }),
  updateFeeds: () => call<void>("update_feeds"),
  pauseProtection: () => call<void>("pause_protection"),
  resumeProtection: () => call<void>("resume_protection"),
  getConfig: () => call<unknown>("get_config"),
  setConfig: (config: unknown) => call<void>("set_config", { config }),
  addException: (path: string) => call<void>("add_exception", { path }),
  blockIoc: (ioc_type: string, value: string) =>
    call<void>("block_ioc", { ioc_type, value }),
  call: <T>(method: string, params?: unknown) => call<T>(method, params),
  openFolderDialog: () => invoke<string | null>("open_folder_dialog"),
  openFileDialog: () => invoke<string | null>("open_file_dialog"),
};

export async function openFolderDialog(): Promise<string | null> {
  return invoke<string | null>("open_folder_dialog");
}

export async function openFileDialog(): Promise<string | null> {
  return invoke<string | null>("open_file_dialog");
}
