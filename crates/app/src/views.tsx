import { Fragment, useEffect, useMemo, useState } from "react";
import { api, type AgentDto, type ArtifactRow, type Destination, type FileEventRow, type Finding, type HttpRow, type ProfileDto } from "./api";
import { formatAgo, formatBytes, formatCount, formatTime, elidePath, evidenceLabels, ruleLabels } from "./format";

function classColor(value: string): string {
  if (value === "secret") return "critical";
  if (value === "source_code") return "high";
  if (value === "archive") return "medium";
  if (value === "binary") return "low";
  return "info";
}

export function FindingCard({
  finding,
  onIgnore,
  onRestore,
}: {
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
        <span className="spacer" />
        <div className="btn-row">
          {finding.evidence.length > 0 && (
            <button onClick={() => setOpen(!open)}>{open ? "收起证据" : "看证据链"}</button>
          )}
          {finding.id != null && !onRestore && <button onClick={() => onIgnore?.(finding.id!)}>忽略</button>}
          {finding.id != null && onRestore && <button onClick={() => onRestore(finding.id!)}>恢复</button>}
        </div>
      </div>
      <div className="meta">
        <span>{label}</span>
        <span>·</span>
        <span>{formatAgo(finding.ts)}</span>
        {finding.agent_id && (
          <>
            <span>·</span>
            <span>{finding.agent_id}</span>
          </>
        )}
        {finding.pid != null && (
          <>
            <span>·</span>
            <span className="mono">pid {finding.pid}</span>
          </>
        )}
      </div>
      <div className="detail">{finding.detail}</div>
      {open && finding.evidence.length > 0 && (
        <ul className="evidence">
          {finding.evidence.map((item, index) => (
            <li key={index}>
              <time>{formatTime(item.ts)}</time>
              <span className="kind">{evidenceLabels[item.kind] ?? item.kind}</span>
              <div>
                {item.summary}
                {item.detail && <div className="samples">{item.detail}</div>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function FindingsView({
  findings,
  ignored,
  onIgnore,
  onRestore,
  onRefresh,
}: {
  findings: Finding[];
  ignored: Finding[];
  onIgnore: (id: number) => void;
  onRestore: (id: number) => void;
  onRefresh: () => void;
}) {
  const [showIgnored, setShowIgnored] = useState(false);
  const [severity, setSeverity] = useState("all");
  const list = showIgnored ? ignored : findings;
  const filtered = severity === "all" ? list : list.filter((f) => f.severity === severity);

  return (
    <div className="panel">
      <div className="panel-head">
        <h3>安全发现</h3>
        <div className="tools">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">全部级别</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <button onClick={() => setShowIgnored(!showIgnored)}>
            {showIgnored ? `待处理（${findings.length}）` : `已忽略（${ignored.length}）`}
          </button>
          <button onClick={onRefresh}>刷新</button>
        </div>
      </div>
      {filtered.length === 0 ? (
        <div className="empty">没有符合条件的条目</div>
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

export function DestinationsPanel({
  destinations,
  agents = [],
  limit = 10,
  withFilter = false,
}: {
  destinations: Destination[];
  agents?: AgentDto[];
  limit?: number;
  withFilter?: boolean;
}) {
  const [filter, setFilter] = useState("all");
  const scoped = filter === "all" ? destinations : destinations.filter((d) => d.agent_id === filter);

  const rows = useMemo(() => {
    const byHost = new Map<string, { connections: number; agents: Set<string>; last: number; disallowed: boolean }>();
    for (const destination of scoped) {
      const entry =
        byHost.get(destination.host) ?? { connections: 0, agents: new Set<string>(), last: 0, disallowed: false };
      entry.connections += destination.connections;
      entry.agents.add(destination.agent_id ?? "未知");
      entry.last = Math.max(entry.last, destination.last_seen);
      entry.disallowed = entry.disallowed || !destination.allowed;
      byHost.set(destination.host, entry);
    }
    return [...byHost.entries()].sort((a, b) => b[1].connections - a[1].connections);
  }, [scoped]);

  return (
    <div className="panel">
      <div className="panel-head">
        <h3>出站目标</h3>
        {withFilter && (
          <div className="tools">
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="all">全部 agent</option>
              {agents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>
      {rows.length === 0 ? (
        <div className="empty">近 24 小时没有记录到出站连接</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>目标主机 / IP</th>
              <th>agent</th>
              <th className="num">连接次数</th>
              <th>最近一次</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, limit).map(([host, entry]) => (
              <tr key={host}>
                <td className="mono">
                  {host}
                  {entry.disallowed && (
                    <span className="sev medium" style={{ marginLeft: 8 }}>
                      白名单外
                    </span>
                  )}
                </td>
                <td className="muted">{[...entry.agents].join(", ")}</td>
                <td className="num">{formatCount(entry.connections)}</td>
                <td className="muted">{formatAgo(entry.last)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {withFilter && rows.length > 0 && (
        <div className="panel-body hint" style={{ borderTop: "1px solid var(--border-soft)" }}>
          本机若使用 fake-ip 代理（198.18.0.0/15 等保留网段），这里只能看到代理地址；
          真实域名需要 <span className="mono">agentmon wrap</span> 启动 agent 后才能拿到。
        </div>
      )}
    </div>
  );
}

export function FileAuditView({
  events,
  fileAuditAvailable,
}: {
  events: FileEventRow[];
  fileAuditAvailable: boolean;
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>文件读取审计</h3>
        <span className={`pill ${fileAuditAvailable ? "on" : ""}`}>
          {fileAuditAvailable ? "采集中" : "未启用"}
        </span>
      </div>
      {!fileAuditAvailable && (
        <div className="panel-body hint">
          当前守护进程不是以 root 运行，因此看不到文件读取事件。启用方式：
          <span className="mono"> sudo agentmon install</span> 安装为服务，或临时用
          <span className="mono"> sudo agentmond</span>。
        </div>
      )}
      {events.length === 0 ? (
        <div className="empty">暂无文件读取事件</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>agent</th>
              <th className="num">pid</th>
              <th>操作</th>
              <th>路径</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, index) => (
              <tr key={index}>
                <td className="muted mono" style={{ whiteSpace: "nowrap" }}>
                  {formatTime(event.ts)}
                </td>
                <td>{event.agent_id ?? "-"}</td>
                <td className="num muted">{event.pid}</td>
                <td className="mono muted">{event.op}</td>
                <td className="mono pre">{event.path}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function ContentView({ requests, proxyAddr }: { requests: HttpRow[]; proxyAddr: string | null }) {
  type BodyState = "idle" | "loading" | "error" | { text: string | null };
  const [openId, setOpenId] = useState<number | null>(null);
  const [bodyState, setBodyState] = useState<BodyState>("idle");
  const [bodyError, setBodyError] = useState("");

  useEffect(() => {
    if (openId === null) {
      setBodyState("idle");
      return;
    }
    // Guards against a fast second click resolving after the first.
    let cancelled = false;
    setBodyState("loading");
    api
      .httpBody(openId)
      .then((text) => {
        if (!cancelled) setBodyState({ text });
      })
      .catch((err) => {
        if (!cancelled) {
          setBodyError(String(err));
          setBodyState("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [openId]);

  const toggleBody = (id: number) => {
    setOpenId(openId === id ? null : id);
  };

  const stored = requests.filter((request) => request.has_body).length;

  return (
    <div className="panel">
      <div className="panel-head">
        <h3>内容审计（代理抓包）</h3>
        <span className={`pill ${proxyAddr ? "on" : ""}`}>
          {proxyAddr ? `代理 ${proxyAddr}` : "代理未运行"}
        </span>
      </div>
      <div className="panel-body hint">
        用 <span className="mono">agentmon wrap -- &lt;agent 命令&gt;</span> 启动 agent 后，
        这里显示请求体的判定结果。判定在本地完成：先解开 gzip / base64 / 归档，再识别源码与密钥特征；
        命中密钥时只记录类型，不保存密钥原文。
        {requests.length > 0 && stored === 0 && (
          <div style={{ marginTop: 6 }}>
            原文本地未保存（默认如此，它会原样留住你的 prompt 和源码）。要能点开查看，
            在配置里打开 <span className="mono">capture.capture_bodies</span> 后重启守护进程。
          </div>
        )}
      </div>
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
              <th className="num">请求体</th>
              <th>判定</th>
              <th>原文</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((request, index) => (
              <Fragment key={request.id ?? index}>
                <tr
                  className={request.has_body ? "row-clickable" : undefined}
                  onClick={request.has_body ? () => toggleBody(request.id) : undefined}
                >
                  <td className="muted mono" style={{ whiteSpace: "nowrap" }}>
                    {formatTime(request.ts)}
                  </td>
                  <td>{request.agent_id ?? "-"}</td>
                  <td className="mono muted">{request.method}</td>
                  <td className="mono">{request.host}</td>
                  <td className="mono pre">{request.path}</td>
                  <td className="num">{formatBytes(request.bytes_out)}</td>
                  <td>
                    <span className={`sev ${classColor(request.class)}`}>{request.class}</span>
                    {request.sample && (
                      <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>
                        {request.sample}
                      </div>
                    )}
                  </td>
                  <td className="muted" style={{ whiteSpace: "nowrap" }}>
                    {request.has_body ? (openId === request.id ? "收起" : "查看") : "-"}
                  </td>
                </tr>
                {openId === request.id && (
                  <tr className="body-row">
                    <td colSpan={8}>
                      {bodyState === "loading" && <div className="muted">读取中…</div>}
                      {bodyState === "error" && (
                        <div className="muted">读取失败：{bodyError}</div>
                      )}
                      {typeof bodyState === "object" && bodyState !== null && (
                        <pre className="payload">{bodyState.text ?? "（空）"}</pre>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function ArtifactsView({ artifacts, limit = 200 }: { artifacts: ArtifactRow[]; limit?: number }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>本地痕迹</h3>
        <span className="muted" style={{ fontSize: 11 }}>
          高熵打包块 / 配置端点
        </span>
      </div>
      {artifacts.length === 0 ? (
        <div className="empty">未发现可疑的本地数据块</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>agent</th>
              <th>类型</th>
              <th className="num">体积</th>
              <th>路径</th>
            </tr>
          </thead>
          <tbody>
            {artifacts.slice(0, limit).map((artifact, index) => (
              <tr key={index}>
                <td style={{ whiteSpace: "nowrap" }}>{artifact.agent_id}</td>
                <td>
                  <span className={`sev ${artifact.kind === "hidden_blob" ? "medium" : "low"}`}>
                    {artifact.kind === "hidden_blob" ? "blob" : "endpoint"}
                  </span>
                </td>
                <td className="num" style={{ whiteSpace: "nowrap" }}>
                  {artifact.size > 0 ? formatBytes(artifact.size) : "-"}
                  {artifact.entropy > 0 && (
                    <div className="muted" style={{ fontSize: 10.5 }}>
                      ent {artifact.entropy.toFixed(2)}
                    </div>
                  )}
                </td>
                <td className="mono muted" title={artifact.path}>
                  {elidePath(artifact.path, 46)}
                </td>
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
      <div className="panel-head">
        <h3>Agent 画像</h3>
        <span className="muted" style={{ fontSize: 11 }}>
          {profiles.length} 个内置画像
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>agent</th>
            <th>厂商</th>
            <th>已安装</th>
            <th className="num">允许域名</th>
            <th className="num">24h 出站</th>
            <th className="num">未处理</th>
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
                <td>{item.installed ? <span className="pill on">已安装</span> : <span className="muted">-</span>}</td>
                <td className="num muted">{item.allowed_domains.length}</td>
                <td className="num">{formatBytes(summary?.bytes_out_24h ?? 0)}</td>
                <td className="num">
                  {summary && summary.open_findings > 0 ? (
                    <span className={`sev ${summary.worst_severity ?? "low"}`}>{summary.open_findings}</span>
                  ) : (
                    <span className="muted">0</span>
                  )}
                </td>
                <td>
                  <button onClick={() => setSelected(selected === item.id ? null : item.id)}>
                    {selected === item.id ? "收起" : "详情"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {profile && (
        <div className="panel-body" style={{ borderTop: "1px solid var(--border-soft)" }}>
          <h3 style={{ margin: "0 0 10px", fontSize: 13 }}>{profile.name}</h3>
          <dl className="kv">
            <dt>允许域名</dt>
            <dd>{profile.allowed_domains.join("  ") || "-"}</dd>
            <dt>遥测域名</dt>
            <dd>{profile.telemetry_domains.join("  ") || "-"}</dd>
            <dt>数据目录</dt>
            <dd>{profile.data_dirs.join("  ")}</dd>
            {profile.notes && (
              <>
                <dt>备注</dt>
                <dd style={{ fontFamily: "inherit" }}>{profile.notes}</dd>
              </>
            )}
          </dl>
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
    <>
      <div className="panel">
        <div className="panel-head">
          <h3>路径</h3>
        </div>
        <div className="panel-body">
          <dl className="kv">
            <dt>配置文件</dt>
            <dd>{paths?.config ?? "加载中…"}</dd>
            <dt>自定义画像</dt>
            <dd>{paths?.profiles_dir ?? "…"}</dd>
            <dt>用户数据库</dt>
            <dd>{paths?.db_user ?? "…"}</dd>
            <dt>系统数据库</dt>
            <dd>{paths?.db_system ?? "…"}</dd>
          </dl>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <h3>静态扫描</h3>
          <div className="tools">
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
              {busy ? "扫描中…" : "立即扫描"}
            </button>
          </div>
        </div>
        <div className="panel-body hint">
          扫描各 agent 数据目录中的高熵大文件与配置里的白名单外端点。扫描在本机完成，不产生任何网络请求。
        </div>
        {scanResult && (
          <div>
            <div className="panel-body hint" style={{ borderTop: "1px solid var(--border-soft)" }}>
              扫描完成，产生 {scanResult.length} 条结果
            </div>
            {scanResult.map((finding, index) => (
              <FindingCard key={index} finding={finding} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}
