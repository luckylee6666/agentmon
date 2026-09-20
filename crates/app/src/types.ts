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
  id: number;
  ts: number;
  agent_id?: string | null;
  host: string;
  method: string;
  path: string;
  bytes_out: number;
  class: string;
  sample?: string | null;
  has_body: boolean;
}

export interface DbInfo {
  path: string;
  exists: boolean;
  system: boolean;
  daemon_active: boolean;
  file_audit: boolean;
  db_readable: boolean;
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

export interface ServiceStatus {
  installed: boolean;
  running: boolean;
  binary_present: boolean;
  unit_path: string;
  managed_binary: string;
  detail: string;
  root: boolean;
}
