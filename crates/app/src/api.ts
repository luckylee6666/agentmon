import { invoke } from "@tauri-apps/api/core";
import * as mock from "./mock";
import type {
  ArtifactRow,
  Destination,
  FileEventRow,
  Finding,
  HttpRow,
  Overview,
  ProfileDto,
  ServiceStatus,
  VolumePoint,
} from "./types";

export * from "./types";

/** True when running inside the Tauri webview rather than a plain browser. */
export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** In a plain browser (`pnpm dev` without Tauri) the UI renders sample data. */
function fallback<T>(value: T): Promise<T> {
  return Promise.resolve(value);
}

const call = <T>(command: string, args?: Record<string, unknown>, sample?: T): Promise<T> => {
  if (!isTauri) {
    if (sample === undefined) {
      return Promise.reject(new Error("not running inside Tauri"));
    }
    return fallback(sample);
  }
  return invoke<T>(command, args);
};

export const api = {
  overview: (sinceMs?: number) => call<Overview>("get_overview", { sinceMs }, mock.mockOverview),
  findings: (opts: { limit?: number; severity?: string; agentId?: string; includeIgnored?: boolean }) =>
    call<Finding[]>(
      "list_findings",
      opts,
      opts.includeIgnored ? mock.mockFindings.map((f) => ({ ...f, status: "ignored" as const })) : mock.mockFindings,
    ),
  setIgnored: (id: number, ignored: boolean) => call<void>("set_finding_ignored", { id, ignored }, undefined),
  fileEvents: (agentId?: string, sinceMs?: number, limit?: number) =>
    call<FileEventRow[]>("list_file_events", { agentId, sinceMs, limit }, mock.mockFileEvents),
  httpBody: (id: number) => call<string | null>("http_body", { id }, `pub struct Ledger {\n    pub entries: HashMap<String, i64>,\n}\n\nimpl Ledger {\n    pub fn balance(&self, account: &str) -> i64 {\n        self.entries.get(account).copied().unwrap_or(0)\n    }\n}`),
  httpRequests: (sinceMs?: number, limit?: number) =>
    call<HttpRow[]>("list_http_requests", { sinceMs, limit }, mock.mockHttp),
  artifacts: (limit?: number) => call<ArtifactRow[]>("list_artifacts", { limit }, mock.mockArtifacts),
  egress: (sinceMs?: number, bucketMs?: number, agentId?: string) =>
    call<VolumePoint[]>("egress", { sinceMs, bucketMs, agentId }, mock.mockVolume),
  destinations: (sinceMs?: number, limit?: number) =>
    call<Destination[]>("destinations", { sinceMs, limit }, mock.mockDestinations),
  daemonStatus: () =>
    call<ServiceStatus>("daemon_status", {}, {
      installed: false,
      running: false,
      binary_present: false,
      unit_path: "/Library/LaunchDaemons/ai.agentmon.agentmond.plist",
      managed_binary: "/usr/local/lib/agentmon/agentmond",
      detail: "未加载",
      root: false,
    }),
  daemonPlan: (action: string) => call<string[]>("daemon_plan", { action }, 
    action === "uninstall" ? ["停用并移除服务", "保留数据库"] : ["复制二进制到 /usr/local/lib/agentmon", "创建 agentmon 组", "写入 LaunchDaemon 并加载"]),
  daemonRun: (action: string) => call<string>("daemon_run", { action }, ""),
  runScan: (deep?: boolean) => call<Finding[]>("run_scan", { deep }, mock.mockFindings.slice(0, 3)),
  profiles: () => call<ProfileDto[]>("list_agent_profiles", {}, mock.mockProfiles),
  paths: () =>
    call<Record<string, string>>("paths_info", {}, {
      config: "/Users/dev/.config/agentmon/config.yaml",
      profiles_dir: "/Users/dev/.config/agentmon/profiles.d",
      db_user: "/Users/dev/Library/Application Support/agentmon/agentmon.db",
      db_system: "/Library/Application Support/agentmon/agentmon.db",
      data_dir_user: "/Users/dev/Library/Application Support/agentmon",
      data_dir_system: "/Library/Application Support/agentmon",
    }),
  config: () => call<Record<string, unknown>>("get_config", {}, {}),
};
