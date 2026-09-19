import { useCallback, useEffect, useMemo, useState } from "react";
import type { EChartsOption } from "echarts";
import { Chart } from "./Chart";
import { api, type FileEventRow, type Finding, type HttpRow, type Overview, type ProfileDto } from "./api";
import { formatBytes, formatClock } from "./format";
import { AgentsView, ArtifactsView, ContentView, EgressView, FileAuditView, FindingsView, SettingsView, FindingCard } from "./views";
import "./App.css";

type Tab = "overview" | "egress" | "files" | "content" | "findings" | "agents" | "settings";

const tabs: { id: Tab; label: string }[] = [
  { id: "overview", label: "总览" },
  { id: "egress", label: "出站流量" },
  { id: "files", label: "文件审计" },
  { id: "content", label: "内容审计" },
  { id: "findings", label: "安全发现" },
  { id: "agents", label: "Agent 画像" },
  { id: "settings", label: "设置" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [ignored, setIgnored] = useState<Finding[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEventRow[]>([]);
  const [httpRequests, setHttpRequests] = useState<HttpRow[]>([]);
  const [profiles, setProfiles] = useState<ProfileDto[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.overview();
      setOverview(data);
      setError(null);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    refresh();
    api.profiles().then(setProfiles).catch(() => setProfiles([]));
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    if (tab !== "files") return;
    const load = () => api.fileEvents(undefined, Date.now() - 24 * 3600 * 1000, 300).then(setFileEvents).catch(() => setFileEvents([]));
    load();
    const timer = setInterval(load, 8000);
    return () => clearInterval(timer);
  }, [tab]);

  useEffect(() => {
    if (tab !== "content") return;
    const load = () =>
      api.httpRequests(Date.now() - 24 * 3600 * 1000, 300).then(setHttpRequests).catch(() => setHttpRequests([]));
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [tab]);

  const loadIgnored = useCallback(() => {
    api.findings({ includeIgnored: true, limit: 200 })
      .then((all) => setIgnored(all.filter((f) => f.status === "ignored")))
      .catch(() => setIgnored([]));
  }, []);

  useEffect(() => {
    if (tab === "findings") loadIgnored();
  }, [tab, loadIgnored]);

  const volumeOption = useMemo<EChartsOption>(() => {
    const points = overview?.volume ?? [];
    return {
      backgroundColor: "transparent",
      grid: { left: 60, right: 20, top: 24, bottom: 28 },
      tooltip: {
        trigger: "axis" as const,
        valueFormatter: (value) => formatBytes(Number(value)),
      },
      xAxis: {
        type: "category" as const,
        data: points.map((p) => formatClock(p.bucket)),
        axisLabel: { color: "#8b949e", fontSize: 10 },
      },
      yAxis: {
        type: "value" as const,
        axisLabel: {
          color: "#8b949e",
          fontSize: 10,
          formatter: (value: number) => formatBytes(value),
        },
        splitLine: { lineStyle: { color: "#262d3a" } },
      },
      series: [
        {
          name: "上传",
          type: "bar",
          data: points.map((p) => p.bytes_out),
          itemStyle: { color: "#ff7a45" },
        },
        {
          name: "下载",
          type: "line",
          smooth: true,
          showSymbol: false,
          data: points.map((p) => p.bytes_in),
          itemStyle: { color: "#40a9ff" },
          lineStyle: { width: 1.5 },
        },
      ],
      legend: { textStyle: { color: "#8b949e" }, top: 0 },
    };
  }, [overview?.volume]);

  const agentsOption = useMemo<EChartsOption>(() => {
    const agents = (overview?.agents ?? []).filter((a) => a.bytes_out_24h > 0);
    return {
      backgroundColor: "transparent",
      grid: { left: 130, right: 30, top: 10, bottom: 24 },
      tooltip: { trigger: "axis" as const, valueFormatter: (value) => formatBytes(Number(value)) },
      xAxis: {
        type: "value" as const,
        axisLabel: { color: "#8b949e", fontSize: 10, formatter: (value: number) => formatBytes(value) },
        splitLine: { lineStyle: { color: "#262d3a" } },
      },
      yAxis: {
        type: "category" as const,
        data: agents.map((a) => a.name).reverse(),
        axisLabel: { color: "#8b949e", fontSize: 10 },
      },
      series: [
        {
          name: "24h 出站",
          type: "bar",
          data: agents.map((a) => a.bytes_out_24h).reverse(),
          itemStyle: { color: "#1f6feb" },
        },
      ],
    };
  }, [overview?.agents]);

  const info = overview?.info;
  const openFindings = overview?.findings ?? [];
  const criticalCount = openFindings.filter((f) => f.severity === "critical" || f.severity === "high").length;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          agentmon
          <small>AI Agent 上传审计 v{info?.version ?? "0.1.0"}</small>
        </div>
        {tabs.map((item) => (
          <div
            key={item.id}
            className={`nav-item ${tab === item.id ? "active" : ""}`}
            onClick={() => setTab(item.id)}
          >
            <span>{item.label}</span>
            {item.id === "findings" && criticalCount > 0 && (
              <span className="badge-count">{criticalCount}</span>
            )}
          </div>
        ))}
        <div style={{ marginTop: "auto", padding: "0 10px" }}>
          <div className="hint mono" style={{ fontSize: 10 }}>
            {info?.path ?? "…"}
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <h2>{tabs.find((t) => t.id === tab)?.label}</h2>
          <span className={`chip ${info?.daemon_active ? "ok" : "warn"}`}>
            {info?.daemon_active ? "守护进程运行中" : "守护进程未运行"}
          </span>
          <span className={`chip ${info?.file_audit ? "ok" : ""}`}>
            {info?.file_audit ? "文件审计已启用" : "无文件审计（需 root 守护进程）"}
          </span>
          <span className={`chip ${info?.proxy_addr ? "ok" : ""}`}>
            {info?.proxy_addr ? `内容代理 ${info.proxy_addr}` : "内容代理未运行"}
          </span>
          <span className="chip">{info?.system ? "系统库" : "用户库"}</span>
          <span className="chip">数据库 {formatBytes(info?.db_size ?? 0)}</span>
          <span style={{ marginLeft: "auto" }}>
            <button onClick={refresh}>刷新</button>
          </span>
        </div>

        {error && <div className="panel hint">读取数据库失败：{error}（先运行 `agentmond` 或 `agentmon watch` 生成数据）</div>}

        {tab === "overview" && (
          <>
            <div className="cards">
              <div className="card">
                <div className="label">检测到的 agent</div>
                <div className="value">{overview?.stats.agents_seen ?? 0}</div>
              </div>
              <div className="card">
                <div className="label">24h 出站流量</div>
                <div className="value">{formatBytes(overview?.stats.bytes_out_24h ?? 0)}</div>
              </div>
              <div className="card">
                <div className="label">24h 出站连接</div>
                <div className="value">{overview?.stats.connections_24h ?? 0}</div>
              </div>
              <div className="card">
                <div className="label">文件读取事件</div>
                <div className="value">{overview?.stats.file_events_24h ?? 0}</div>
              </div>
              <div className="card">
                <div className="label">未处理发现</div>
                <div className="value" style={{ color: criticalCount > 0 ? "var(--critical)" : undefined }}>
                  {openFindings.length}
                </div>
              </div>
            </div>

            <div className="panel">
              <h3>出站流量趋势（15 分钟粒度）</h3>
              <Chart option={volumeOption} height={240} />
            </div>

            <div className="panel">
              <h3>各 agent 24h 出站量</h3>
              <Chart option={agentsOption} height={Math.max(120, (overview?.agents.length ?? 1) * 26)} />
            </div>

            <div className="panel">
              <h3>最新安全发现</h3>
              {openFindings.length === 0 ? (
                <div className="empty">暂无发现</div>
              ) : (
                openFindings.slice(0, 6).map((finding) => (
                  <FindingCard
                    key={finding.id ?? finding.ts}
                    finding={finding}
                    onIgnore={async (id) => {
                      await api.setIgnored(id, true);
                      refresh();
                    }}
                  />
                ))
              )}
            </div>

            <ArtifactsView artifacts={overview?.artifacts ?? []} />
          </>
        )}

        {tab === "egress" && (
          <EgressView destinations={overview?.destinations ?? []} agents={overview?.agents ?? []} />
        )}

        {tab === "files" && (
          <FileAuditView events={fileEvents} fileAuditAvailable={info?.file_audit ?? false} />
        )}

        {tab === "content" && (
          <ContentView requests={httpRequests} proxyAddr={info?.proxy_addr ?? null} />
        )}

        {tab === "findings" && (
          <FindingsView
            findings={openFindings}
            ignored={ignored}
            onIgnore={async (id) => {
              await api.setIgnored(id, true);
              refresh();
              loadIgnored();
            }}
            onRestore={async (id) => {
              await api.setIgnored(id, false);
              refresh();
              loadIgnored();
            }}
            onRefresh={refresh}
          />
        )}

        {tab === "agents" && <AgentsView agents={overview?.agents ?? []} profiles={profiles} />}

        {tab === "settings" && (
          <SettingsView
            onScan={async () => {
              const result = await api.runScan(true);
              refresh();
              return result;
            }}
          />
        )}
      </main>
    </div>
  );
}
