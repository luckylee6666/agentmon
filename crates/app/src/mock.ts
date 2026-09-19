import type {
  AgentDto,
  ArtifactRow,
  DbInfo,
  Destination,
  FileEventRow,
  Finding,
  HttpRow,
  Overview,
  ProfileDto,
  Stats,
  VolumePoint,
} from "./types";

// Sample data so the UI can be developed and reviewed in a plain browser
// (`pnpm dev` without Tauri). Never used inside the app: the api layer only
// falls back to it when the Tauri bridge is absent.

const now = Date.now();
const minute = 60_000;

export const mockDbInfo: DbInfo = {
  path: "/Users/dev/Library/Application Support/agentmon/agentmon.db",
  exists: true,
  system: false,
  daemon_active: true,
  file_audit: true,
  proxy_addr: "127.0.0.1:8899",
  db_size: 4_812_344,
  version: "0.1.0",
};

export const mockStats: Stats = {
  agents_seen: 4,
  connections_24h: 1284,
  file_events_24h: 21_640,
  http_requests_24h: 312,
  volume_samples_24h: 8_640,
  bytes_out_24h: 74_231_808,
};

export const mockAgents: AgentDto[] = [
  {
    id: "zcode",
    name: "ZCode",
    vendor: "智谱 AI",
    last_seen: now - 2 * minute,
    bytes_out_24h: 68_157_440,
    open_findings: 3,
    worst_severity: "critical",
    installed: true,
    data_dir_bytes: 634_388_480,
  },
  {
    id: "claude-code",
    name: "Claude Code",
    vendor: "Anthropic",
    last_seen: now - 4 * minute,
    bytes_out_24h: 4_194_304,
    open_findings: 1,
    worst_severity: "high",
    installed: true,
    data_dir_bytes: 661_651_456,
  },
  {
    id: "codex-cli",
    name: "Codex CLI",
    vendor: "OpenAI",
    last_seen: now - 9 * minute,
    bytes_out_24h: 1_572_864,
    open_findings: 1,
    worst_severity: "low",
    installed: true,
    data_dir_bytes: 14_495_514_624,
  },
  {
    id: "cursor-agent",
    name: "Cursor Agent CLI",
    vendor: "Anysphere",
    last_seen: now - 41 * minute,
    bytes_out_24h: 307_200,
    open_findings: 0,
    worst_severity: null,
    installed: true,
    data_dir_bytes: 2_147_483_648,
  },
];

export const mockFindings: Finding[] = [
  {
    id: 41,
    ts: now - 90_000,
    rule_id: "exfil.chain",
    severity: "critical",
    title: "zcode 疑似外传：先批量读取，随后立即上传",
    detail:
      "47 秒内先出现敏感/批量读取，紧接着出站 36.2MB。这与「本地打包后上传」的行为特征一致。",
    agent_id: "zcode",
    pid: 84212,
    status: "open",
    evidence: [
      {
        ts: now - 137_000,
        kind: "bulk-read",
        summary: "60 秒内读取 412 个不同文件（仓库 /Users/dev/project/payments）",
        detail:
          "/Users/dev/project/payments/.git/objects/3f/8a1c2\n/Users/dev/project/payments/src/api/client.ts\n/Users/dev/project/payments/src/db/migrations/0042_add_ledger.sql",
      },
      {
        ts: now - 96_000,
        kind: "git-read",
        summary: "60 秒内读取 68 个 .git 文件",
      },
      {
        ts: now - 90_000,
        kind: "http-upload",
        summary: "读取后 47 秒内出站 36.2MB",
        detail: "POST api.z.ai/v1/repo/index",
      },
    ],
  },
  {
    id: 40,
    ts: now - 6 * minute,
    rule_id: "egress.sensitive_payload",
    severity: "high",
    title: "claude-code 向 sync.unknown-vendor.example 发送了疑似源码内容",
    detail:
      "POST sync.unknown-vendor.example → /v1/ingest，请求体被判定为 source_code（1.2MB）。该域名不在允许列表中。",
    agent_id: "claude-code",
    pid: 77120,
    status: "open",
    evidence: [
      {
        ts: now - 6 * minute,
        kind: "http",
        summary: "POST sync.unknown-vendor.example/v1/ingest",
        detail: "疑似源码（3,214 行，含 .ts .tsx .sql 等文件引用）",
      },
    ],
  },
  {
    id: 39,
    ts: now - 18 * minute,
    rule_id: "fs.sensitive_read",
    severity: "medium",
    title: "codex-cli 读取敏感文件",
    detail: "codex-cli 读取了 /Users/dev/project/payments/.env.production",
    agent_id: "codex-cli",
    pid: 71004,
    status: "open",
    evidence: [
      {
        ts: now - 18 * minute,
        kind: "file-read",
        summary: "读取 /Users/dev/project/payments/.env.production",
      },
    ],
  },
  {
    id: 38,
    ts: now - 52 * minute,
    rule_id: "artifact.hidden_blob",
    severity: "medium",
    title: "zcode 数据目录出现高熵大文件",
    detail: "312MB 高熵文件（entropy 7.98），疑似本地打包/加密的数据块",
    agent_id: "zcode",
    pid: null,
    status: "open",
    evidence: [
      {
        ts: now - 52 * minute,
        kind: "artifact",
        summary: "/Users/dev/Library/Application Support/ZCode/index/9f2c1a.blob (312MB)",
        detail: "entropy 7.98",
      },
    ],
  },
  {
    id: 37,
    ts: now - 3 * 60 * minute,
    rule_id: "egress.unknown_domain",
    severity: "low",
    title: "codex-cli 连接到白名单外的地址 198.18.0.85:443",
    detail:
      "目标 198.18.0.85:443 不在 Codex CLI 的允许域名或全局白名单内，也不匹配已解析的厂商 IP。",
    agent_id: "codex-cli",
    pid: 2536,
    status: "open",
    evidence: [{ ts: now - 3 * 60 * minute, kind: "connection", summary: "连接到 198.18.0.85:443" }],
  },
];

export const mockVolume: VolumePoint[] = Array.from({ length: 32 }, (_, index) => {
  const spike = index === 22 ? 46_137_344 : index === 23 ? 12_582_912 : 0;
  return {
    bucket: now - (31 - index) * 15 * minute,
    bytes_out: spike || Math.round(120_000 + Math.random() * 900_000),
    bytes_in: Math.round(300_000 + Math.random() * 2_400_000),
  };
});

export const mockDestinations: Destination[] = [
  { agent_id: "zcode", host: "api.z.ai", connections: 412, first_seen: now - 6 * 3600_000, last_seen: now - minute, allowed: true },
  { agent_id: "zcode", host: "198.18.0.85", connections: 96, first_seen: now - 5 * 3600_000, last_seen: now - 2 * minute, allowed: false },
  { agent_id: "claude-code", host: "api.anthropic.com", connections: 288, first_seen: now - 8 * 3600_000, last_seen: now - 4 * minute, allowed: true },
  { agent_id: "claude-code", host: "sync.unknown-vendor.example", connections: 3, first_seen: now - 7 * 60 * minute, last_seen: now - 6 * minute, allowed: false },
  { agent_id: "codex-cli", host: "chatgpt.com", connections: 174, first_seen: now - 9 * 3600_000, last_seen: now - 9 * minute, allowed: true },
  { agent_id: "codex-cli", host: "198.18.0.88", connections: 41, first_seen: now - 3 * 3600_000, last_seen: now - 12 * minute, allowed: false },
  { agent_id: "cursor-agent", host: "api2.cursor.sh", connections: 63, first_seen: now - 4 * 3600_000, last_seen: now - 41 * minute, allowed: true },
];

export const mockArtifacts: ArtifactRow[] = [
  {
    ts: now - 52 * minute,
    agent_id: "zcode",
    path: "/Users/dev/Library/Application Support/ZCode/index/9f2c1a.blob",
    size: 327_155_712,
    entropy: 7.98,
    kind: "hidden_blob",
    detail: "312MB 高熵文件，疑似本地打包/加密的数据块",
  },
  {
    ts: now - 2 * 3600_000,
    agent_id: "codex-cli",
    path: "/Users/dev/.codex/.tmp/rollout-2026-09-19.bin",
    size: 88_080_384,
    entropy: 7.81,
    kind: "hidden_blob",
    detail: "84MB 高熵文件，疑似本地打包/加密的数据块",
  },
  {
    ts: now - 4 * 3600_000,
    agent_id: "claude-code",
    path: "/Users/dev/.claude/settings.json",
    size: 0,
    entropy: 0,
    kind: "unexpected_endpoint",
    detail: "配置项 anthropic_base_url 指向白名单外地址 token-plan.cn-beijing.maas.aliyuncs.com",
  },
];

export const mockFileEvents: FileEventRow[] = [
  { ts: now - 137_000, pid: 84212, agent_id: "zcode", path: "/Users/dev/project/payments/.git/objects/3f/8a1c2", op: "open" },
  { ts: now - 136_500, pid: 84212, agent_id: "zcode", path: "/Users/dev/project/payments/.git/config", op: "open" },
  { ts: now - 136_000, pid: 84212, agent_id: "zcode", path: "/Users/dev/project/payments/src/api/client.ts", op: "open" },
  { ts: now - 18 * minute, pid: 71004, agent_id: "codex-cli", path: "/Users/dev/project/payments/.env.production", op: "open" },
  { ts: now - 18 * minute + 400, pid: 71004, agent_id: "codex-cli", path: "/Users/dev/.ssh/id_ed25519", op: "open" },
  { ts: now - 44 * minute, pid: 77120, agent_id: "claude-code", path: "/Users/dev/project/payments/.git/FETCH_HEAD", op: "open" },
];

export const mockHttp: HttpRow[] = [
  {
    id: 701,
    ts: now - 90_000,
    agent_id: "zcode",
    host: "api.z.ai",
    method: "POST",
    path: "/v1/repo/index",
    bytes_out: 37_957_632,
    class: "source_code",
    sample: "疑似源码（12,884 行，含 .ts .sql .rs 等文件引用）",
    has_body: true,
  },
  {
    id: 702,
    ts: now - 6 * minute,
    agent_id: "claude-code",
    host: "sync.unknown-vendor.example",
    method: "POST",
    path: "/v1/ingest",
    bytes_out: 1_258_291,
    class: "source_code",
    sample: "疑似源码（3,214 行，含 .ts .tsx .sql 等文件引用）",
    has_body: true,
  },
  {
    id: 703,
    ts: now - 11 * minute,
    agent_id: "claude-code",
    host: "api.anthropic.com",
    method: "POST",
    path: "/v1/messages",
    bytes_out: 18_432,
    class: "text",
    sample: null,
    has_body: true,
  },
  {
    id: 704,
    ts: now - 27 * minute,
    agent_id: "codex-cli",
    host: "chatgpt.com",
    method: "POST",
    path: "/backend-api/codex/responses",
    bytes_out: 2_097_152,
    class: "archive",
    sample: "gzip 解压后：压缩包/归档格式（72192 字节）",
    has_body: true,
  },
  {
    id: 705,
    ts: now - 63 * minute,
    agent_id: "zcode",
    host: "198.18.0.85",
    method: "POST",
    path: "/collect",
    bytes_out: 4_194_304,
    class: "binary",
    sample: "二进制数据（194304 字节）",
    has_body: true,
  },
];

export const mockProfiles: ProfileDto[] = [
  {
    id: "zcode",
    name: "ZCode",
    vendor: "智谱 AI",
    installed: true,
    data_dirs: ["~/Library/Application Support/ZCode", "~/.zcode"],
    allowed_domains: ["*.z.ai", "open.bigmodel.cn"],
    telemetry_domains: [],
    notes: "2026-09 事件：仓库索引功能默认开启，静默打包上传整个仓库（含 .git）",
  },
  {
    id: "claude-code",
    name: "Claude Code",
    vendor: "Anthropic",
    installed: true,
    data_dirs: ["~/.claude"],
    allowed_domains: ["*.anthropic.com", "claude.ai"],
    telemetry_domains: ["*.sentry.io", "*.statsig.com"],
    notes: null,
  },
  {
    id: "codex-cli",
    name: "Codex CLI",
    vendor: "OpenAI",
    installed: true,
    data_dirs: ["~/.codex"],
    allowed_domains: ["*.openai.com", "chatgpt.com"],
    telemetry_domains: ["*.sentry.io"],
    notes: null,
  },
  {
    id: "cursor-agent",
    name: "Cursor Agent CLI",
    vendor: "Anysphere",
    installed: true,
    data_dirs: ["~/.cursor"],
    allowed_domains: ["*.cursor.sh", "*.cursor.com"],
    telemetry_domains: ["*.sentry.io"],
    notes: null,
  },
];

export const mockOverview: Overview = {
  info: mockDbInfo,
  stats: mockStats,
  agents: mockAgents,
  findings: mockFindings,
  volume: mockVolume,
  destinations: mockDestinations,
  artifacts: mockArtifacts,
};
