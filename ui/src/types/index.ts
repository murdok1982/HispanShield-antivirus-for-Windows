export interface AgentStatus {
  running: boolean;
  protection_enabled: boolean;
  last_update: string;
  version: string;
  uptime_seconds: number;
}

export interface Stats {
  threats: number;
  quarantined: number;
  ioc_count: number;
  events_today: number;
  processes_monitored: number;
  connections_active: number;
}

export interface Threat {
  id: number;
  detected_at: string;
  threat_type:
    | "Malware"
    | "Ransomware"
    | "PUA"
    | "Suspicious"
    | "Network"
    | "LOLBin";
  name?: string;
  path?: string;
  pid?: number;
  process_name?: string;
  hash_sha256?: string;
  score: number;
  detection_method: "Hash" | "YARA" | "Heuristic" | "Network" | "Behavior";
  ioc_source?: string;
  status: "Active" | "Quarantined" | "Whitelisted" | "Resolved";
  action_taken?: string;
  details?: string;
}

export interface QuarantineEntry {
  id: string;
  quarantined_at: string;
  original_path: string;
  original_name: string;
  quarantine_path: string;
  hash_sha256?: string;
  file_size?: number;
  threat_name?: string;
  score?: number;
  detection_method?: string;
  status: "Quarantined" | "Restored" | "Deleted";
  details?: string;
}

export interface ProcessInfo {
  pid: number;
  ppid?: number;
  name: string;
  path?: string;
  cmdline?: string;
  hash_sha256?: string;
  signed: boolean;
  signer?: string;
  score: number;
  connections: number;
  status: string;
  flags?: string[];
}

export interface ConnectionInfo {
  id: number;
  pid: number;
  process_name: string;
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  protocol: "TCP" | "UDP";
  state: string;
  score: number;
  ioc_match?: string;
  country?: string;
}

export interface FeedStatus {
  name: string;
  last_updated?: string;
  next_update?: string;
  ioc_count: number;
  status: "Pending" | "OK" | "Error" | "Updating";
  error_msg?: string;
}

export interface Event {
  id: number;
  timestamp: string;
  event_type: string;
  severity: "Info" | "Low" | "Medium" | "High" | "Critical";
  source?: string;
  path?: string;
  pid?: number;
  process_name?: string;
  score?: number;
  details?: string;
  resolved: boolean;
}

export interface ScanResult {
  scanned: number;
  threats_found: number;
  duration_ms: number;
  threats: Threat[];
}

export interface ChartDataPoint {
  time: string;
  events: number;
  threats: number;
}

export type RiskLevel = "clean" | "low" | "medium" | "high" | "critical";

export function scoreToRisk(score: number): RiskLevel {
  if (score < 30) return "clean";
  if (score < 45) return "low";
  if (score < 60) return "medium";
  if (score < 80) return "high";
  return "critical";
}

export function riskLabel(level: RiskLevel): string {
  const labels: Record<RiskLevel, string> = {
    clean: "Limpio",
    low: "Bajo",
    medium: "Medio",
    high: "Alto",
    critical: "Critico",
  };
  return labels[level];
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}
