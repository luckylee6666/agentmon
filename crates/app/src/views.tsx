import { useState } from "react";
import { api, type AgentDto, type ArtifactRow, type Destination, type FileEventRow, type Finding, type HttpRow, type ProfileDto } from "./api";
import { formatAgo, formatBytes, formatTime, ruleLabels } from "./format";

export function FindingCard({ finding, onIgnore, onRestore }: {
  finding: Finding;
  onIgnore?: (id: number) => void;
  onRestore?: (id: number) => void;
}) {
  const [open, setOpen] = useState(finding.severity === "critical" || finding.severity === "high");
  const label = ruleLabels[finding.rule_id] ?? finding.rule_id;
  return (
    <div className={`finding ${finding.severity}`}>
      <div className="title">
        <span className={`sev ${finding.severity}`}>{finding.severity}</span>
        <span>{finding.title}</span>
        <span className="muted mono">{label}</span>
        <span className="muted">· {formatAgo(finding.ts)}</span>
        <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          <button onClick={() => setOpen(!open)}>{open ? "收起" : "证据链"}</button>
          {finding.id != null && !onRestore && <button onClick={() => onIgnore?.(finding.id!)}>忽略</button>}
          {finding.id != null && onRestore && <button onClick={() => onRestore(finding.id!)}>恢复</button>}
        </span>
      </div>
      <div className="detail">{finding.detail}</div>
      {open && finding.evidence.length > 0 && (
        <ul className="evidence">
          {finding.evidence.map((item, index) => (
            <li key={index}>
              <span className="muted mono">{formatTime(item.ts)}</span> {item.summary}
              {item.detail && <div className="muted mono">{item.detail}</div>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function FindingsView({ findings, ignored, onIgnore, onRestore, onRefresh }: {
  findings: Finding[];
  ignored: Finding[];
  onIgnore: (id: number) => void;
  onRestore: (id: number) => void;
  onRefresh: () => void;
}) {
  const [showIgnored, setShowIgnored] = useState(false);
  const list = showIgnored ? ignored : findings;
  const [severity, setSeverity] = useState("all");
  const filtered = severity === "all" ? list : list.filter((f) => f.severity === severity);

  return (
    <div className="panel">
      <h3>
        安全发现
        <span style={{ float: "right", display: "flex", gap: 8 }}>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">全部级别</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <button onClick={() => setShowIgnored(!showIgnored)}>
            {showIgnored ? `显示待处理 (${findings.length})` : `显示已忽略 (${ignored.length})`}
          </button>
          <button onClick={onRefresh}>刷新</button>
        </span>
      </h3>
      {filtered.length === 0 ? (
        <div className="empty">没有符合条件的事件</div>
      ) : (
        filtered.map((finding) => (
          <FindingCard
            key={finding.id ?? `${finding.ts}-${finding.rule_id}`}
            finding={finding}
            onIgnore={onIgnore}
            onRestore={showIgnored ? onRestore : undefined}
          />
        ))
      )}
    </div>
  );
}

export function EgressView({ destinations, agents }: { destinations: Destination[]; agents: AgentDto[] }) {
  const [filter, setFilter] = useState("all");
  const filtered = filter === "all" ? destinations : destinations.filter((d) => d.agent_id === filter);
  const byHost = new Map<string, { connections: number; agents: Set<string>; last: number }>();
  for (const destination of filtered) {
    const entry = byHost.get(destination.host) ?? { connections: 0, agents: new Set<string>(), last: 0 };
    entry.connections += destination.connections;
    entry.agents.add(destination.agent_id ?? "-");
    entry.last = Math.max(entry.last, destination.last_seen);
    byHost.set(destination.host, entry);
  }
  const rows = [...byHost.entries()].sort((a, b) => b[1].connections - a[1].connections);

  return (
    <div className="panel">
      <h3>
        出站目标
        <span style={{ float: "right" }}>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">全部 agent</option>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>{agent.name}</option>
            ))}
          </select>
        </span>
      </h3>
      {rows.length === 0 ? (
        <div className="empty">近 24 小时没有记录到出站连接</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>目标主机 / IP</th>
              <th>agent</th>
              <th>连接次数</th>
              <th>最近一次</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 100).map(([host, info]) => (
              <tr key={host}>
                <td className="mono">{host}</td>
                <td>{[...info.agents].join(", ")}</td>
                <td>{info.connections}</td>
                <td className="muted">{formatAgo(info.last)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint" style={{ marginTop: 12 }}>
        提示：本机若使用 fake-ip 代理（198.18.0.0/15 等保留网段），这里只能看到代理地址，
        真实域名需要 `agentmon wrap` 启动 agent 后才能拿到。
      </p>
    </div>
  );
}

export function FileAuditView({ events, fileAuditAvailable }: { events: FileEventRow[]; fileAuditAvailable: boolean }) {
  return (
    <div className="panel">
      <h3>文件读取审计</h3>
      {!fileAuditAvailable && (
        <p className="hint">
          当前没有以 root 运行 agentmond，因此看不到文件读取事件。启用方式：
          <span className="mono"> sudo agentmond</span>（或安装为 LaunchDaemon）。
        </p>
      )}
      {events.length === 0 ? (
        <div className="empty">暂无文件读取事件</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>agent</th>
              <th>pid</th>
              <th>操作</th>
              <th>路径</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, index) => (
              <tr key={index}>
                <td className="muted mono">{formatTime(event.ts)}</td>
                <td>{event.agent_id ?? "-"}</td>
                <td className="muted">{event.pid}</td>
                <td className="mono">{event.op}</td>
                <td className="mono">{event.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function ContentView({ requests, proxyAddr }: { requests: HttpRow[]; proxyAddr: string | null }) {
  return (
    <div className="panel">
      <h3>内容审计（代理抓包）</h3>
      <p className="hint">
        {proxyAddr
          ? `代理运行中：${proxyAddr}`
          : "代理未运行（在 config.yaml 里开启 proxy.enabled）"}
        <br />
        用 <span className="mono">agentmon wrap -- &lt;agent 命令&gt;</span> 启动 agent 后，
        这里会显示实际发出的请求体分类结果（源码 / 密钥 / 压缩包）。数据只在本地判定，不上传。
      </p>
      {requests.length === 0 ? (
        <div className="empty">暂无抓包数据</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>agent</th>
              <th>方法</th>
              <th>主机</th>
              <th>路径</th>
              <th>请求体</th>
              <th>判定</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((request, index) => (
              <tr key={index}>
                <td className="muted mono">{formatTime(request.ts)}</td>
                <td>{request.agent_id ?? "-"}</td>
                <td className="mono">{request.method}</td>
                <td className="mono">{request.host}</td>
                <td className="mono">{request.path}</td>
                <td>{formatBytes(request.bytes_out)}</td>
                <td>
                  <span className={`sev ${request.class === "secret" ? "critical" : request.class === "source_code" ? "high" : "info"}`}>
                    {request.class}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function ArtifactsView({ artifacts }: { artifacts: ArtifactRow[] }) {
  return (
    <div className="panel">
      <h3>本地痕迹（高熵打包块 / 配置端点）</h3>
      {artifacts.length === 0 ? (
        <div className="empty">未发现可疑的本地数据块</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>agent</th>
              <th>类型</th>
              <th>体积</th>
              <th>熵</th>
              <th>路径</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.map((artifact, index) => (
              <tr key={index}>
                <td>{artifact.agent_id}</td>
                <td className="mono">{artifact.kind}</td>
                <td>{artifact.size > 0 ? formatBytes(artifact.size) : "-"}</td>
                <td>{artifact.entropy > 0 ? artifact.entropy.toFixed(2) : "-"}</td>
                <td className="mono">{artifact.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function AgentsView({ agents, profiles }: { agents: AgentDto[]; profiles: ProfileDto[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const profile = profiles.find((p) => p.id === selected);
  return (
    <div className="panel">
      <h3>Agent 画像</h3>
      <table>
        <thead>
          <tr>
            <th>agent</th>
            <th>厂商</th>
            <th>已安装</th>
            <th>允许域名</th>
            <th>数据目录</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {profiles.map((item) => {
            const summary = agents.find((a) => a.id === item.id);
            return (
              <tr key={item.id}>
                <td>{item.name}</td>
                <td className="muted">{item.vendor}</td>
                <td>{item.installed ? "是" : "-"}</td>
                <td className="muted">{item.allowed_domains.length}</td>
                <td className="mono muted">{item.data_dirs[0] ?? "-"}</td>
                <td>
                  <button onClick={() => setSelected(selected === item.id ? null : item.id)}>
                    {summary ? `24h 出站 ${formatBytes(summary.bytes_out_24h)}` : "详情"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {profile && (
        <div className="panel" style={{ marginTop: 14 }}>
          <h3>{profile.name} 详情</h3>
          <p className="hint">
            允许域名：<span className="mono">{profile.allowed_domains.join(", ") || "-"}</span>
            <br />
            遥测域名：<span className="mono">{profile.telemetry_domains.join(", ") || "-"}</span>
            <br />
            数据目录：<span className="mono">{profile.data_dirs.join(", ")}</span>
            {profile.notes && (
              <>
                <br />
                备注：{profile.notes}
              </>
            )}
          </p>
        </div>
      )}
    </div>
  );
}

export function SettingsView({ onScan }: { onScan: () => Promise<Finding[]> }) {
  const [paths, setPaths] = useState<Record<string, string> | null>(null);
  const [scanResult, setScanResult] = useState<Finding[] | null>(null);
  const [busy, setBusy] = useState(false);

  if (!paths) {
    api.paths().then(setPaths).catch(() => setPaths({}));
  }

  return (
    <div className="panel">
      <h3>设置与路径</h3>
      <p className="hint">
        配置文件：<span className="mono">{paths?.config ?? "加载中…"}</span>
        <br />
        自定义画像目录：<span className="mono">{paths?.profiles_dir ?? "…"}</span>
        <br />
        用户数据库：<span className="mono">{paths?.db_user ?? "…"}</span>
        <br />
        root 守护进程数据库：<span className="mono">{paths?.db_system ?? "…"}</span>
      </p>
      <p>
        <button
          className="primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              setScanResult(await onScan());
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "扫描中…" : "立即执行静态扫描"}
        </button>
      </p>
      {scanResult && (
        <div>
          <p className="hint">扫描完成，产生 {scanResult.length} 条结果：</p>
          {scanResult.map((finding, index) => (
            <FindingCard key={index} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}
