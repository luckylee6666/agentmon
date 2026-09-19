import { invoke } from "@tauri-apps/api/core";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Evidence {
  ts: number;
  kind: string;
  summary: string;
  detail?: string | null;
}

export interface Finding {
  id?: number | null;
  ts: number;
  rule_id: string;
  severity: Severity;
  title: string;
  detail: string;
  agent_id?: string | null;
  pid?: number | null;
  evidence: Evidence[];
  status: "open" | "ignored";
  dedupe_key?: string | null;
}

export interface AgentDto {
  id: string;
  name: string;
  vendor: string;
  last_seen: number;
  bytes_out_24h: number;
  open_findings: number;
  worst_severity?: Severity | null;
  installed: boolean;
  data_dir_bytes: number;
}

export interface VolumePoint {
  bucket: number;
  bytes_out: number;
  bytes_in: number;
}

export interface Destination {
  agent_id?: string | null;
  host: string;
  connections: number;
  first_seen: number;
  last_seen: number;
  allowed: boolean;
}

export interface ArtifactRow {
  ts: number;
  agent_id: string;
  path: string;
  size: number;
  entropy: number;
  kind: string;
  detail: string;
}

export interface FileEventRow {
  ts: number;
  pid: number;
  agent_id?: string | null;
  path: string;
  op: string;
}

export interface HttpRow {
  ts: number;
  agent_id?: string | null;
  host: string;
  method: string;
  path: string;
  bytes_out: number;
  class: string;
  sample?: string | null;
}

export interface DbInfo {
  path: string;
  exists: boolean;
  system: boolean;
  daemon_active: boolean;
  file_audit: boolean;
  proxy_addr?: string | null;
  db_size: number;
  version: string;
}

export interface Stats {
  agents_seen: number;
  connections_24h: number;
  file_events_24h: number;
  http_requests_24h: number;
  volume_samples_24h: number;
  bytes_out_24h: number;
}

export interface Overview {
  info: DbInfo;
  stats: Stats;
  agents: AgentDto[];
  findings: Finding[];
  volume: VolumePoint[];
  destinations: Destination[];
  artifacts: ArtifactRow[];
}

export interface ProfileDto {
  id: string;
  name: string;
  vendor: string;
  installed: boolean;
  data_dirs: string[];
  allowed_domains: string[];
  telemetry_domains: string[];
  notes?: string | null;
}

export const api = {
  overview: (sinceMs?: number) => invoke<Overview>("get_overview", { sinceMs }),
  findings: (opts: { limit?: number; severity?: string; agentId?: string; includeIgnored?: boolean }) =>
    invoke<Finding[]>("list_findings", opts),
  setIgnored: (id: number, ignored: boolean) => invoke<void>("set_finding_ignored", { id, ignored }),
  fileEvents: (agentId?: string, sinceMs?: number, limit?: number) =>
    invoke<FileEventRow[]>("list_file_events", { agentId, sinceMs, limit }),
  httpRequests: (sinceMs?: number, limit?: number) =>
    invoke<HttpRow[]>("list_http_requests", { sinceMs, limit }),
  artifacts: (limit?: number) => invoke<ArtifactRow[]>("list_artifacts", { limit }),
  egress: (sinceMs?: number, bucketMs?: number, agentId?: string) =>
    invoke<VolumePoint[]>("egress", { sinceMs, bucketMs, agentId }),
  destinations: (sinceMs?: number, limit?: number) =>
    invoke<Destination[]>("destinations", { sinceMs, limit }),
  runScan: (deep?: boolean) => invoke<Finding[]>("run_scan", { deep }),
  profiles: () => invoke<ProfileDto[]>("list_agent_profiles"),
  paths: () => invoke<Record<string, string>>("paths_info"),
  config: () => invoke<Record<string, unknown>>("get_config"),
};
