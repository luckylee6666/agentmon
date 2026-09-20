import { useCallback, useEffect, useMemo, useState } from "react";
import type { EChartsOption } from "echarts";
import { Chart } from "./Chart";
import { api, type FileEventRow, type Finding, type HttpRow, type Overview, type ProfileDto } from "./api";
import { formatBytes, formatClock, formatCount, elidePath } from "./format";
import {
  AgentsView,
  ArtifactsView,
  ContentView,
  DestinationsPanel,
  FileAuditView,
  FindingCard,
  FindingsView,
  SettingsView,
} from "./views";
import "./App.css";

type Tab = "overview" | "egress" | "files" | "content" | "findings" | "agents" | "settings";

const tabs: { id: Tab; label: string; group: string }[] = [
  { id: "overview", label: "总览", group: "监控" },
  { id: "egress", label: "出站流量", group: "监控" },
  { id: "files", label: "文件审计", group: "监控" },
  { id: "content", label: "内容审计", group: "监控" },
  { id: "findings", label: "安全发现", group: "审计" },
  { id: "agents", label: "Agent 画像", group: "审计" },
  { id: "settings", label: "设置", group: "系统" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>(() => {
    const hash = window.location.hash.replace("#", "") as Tab;
    return tabs.some((item) => item.id === hash) ? hash : "overview";
  });
  const [overview, setOverview] = useState<Overview | null>(null);
  const [ignored, setIgnored] = useState<Finding[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEventRow[]>([]);
  const [httpRequests, setHttpRequests] = useState<HttpRow[]>([]);
  const [profiles, setProfiles] = useState<ProfileDto[]>([]);
  const [error, setError] = useState<string | null>(null);

  const openTab = useCallback((next: Tab) => {
    setTab(next);
    window.location.hash = next;
  }, []);

  const refresh = useCallback(async () => {
    try {
      setOverview(await api.overview());
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
    const load = () =>
      api
        .fileEvents(undefined, Date.now() - 24 * 3600 * 1000, 300)
        .then(setFileEvents)
        .catch(() => setFileEvents([]));
    load();
    const timer = setInterval(load, 8000);
    return () => clearInterval(timer);
  }, [tab]);

  useEffect(() => {
    if (tab !== "content") return;
    const load = () =>
      api
        .httpRequests(Date.now() - 24 * 3600 * 1000, 300)
        .then(setHttpRequests)
        .catch(() => setHttpRequests([]));
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [tab]);

  const loadIgnored = useCallback(() => {
    api
      .findings({ includeIgnored: true, limit: 200 })
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
      grid: { left: 62, right: 18, top: 30, bottom: 26 },
      tooltip: {
        trigger: "axis" as const,
        valueFormatter: (value) => formatBytes(Number(value)),
      },
      legend: {
        top: 0,
        right: 0,
        itemWidth: 10,
        itemHeight: 10,
        textStyle: { color: "#9aa7b8", fontSize: 11 },
      },
      xAxis: {
        type: "category" as const,
        data: points.map((p) => formatClock(p.bucket)),
        axisLabel: { color: "#6b7789", fontSize: 10.5, interval: Math.ceil(points.length / 8) },
        axisLine: { lineStyle: { color: "#232a36" } },
      },
      yAxis: {
        type: "value" as const,
        axisLabel: {
          color: "#6b7789",
          fontSize: 10.5,
          formatter: (value: number) => formatBytes(value),
        },
        splitLine: { lineStyle: { color: "#1c232e" } },
      },
      series: [
        {
          name: "上传",
          type: "bar",
          data: points.map((p) => p.bytes_out),
          itemStyle: { color: "#ff8a3d", borderRadius: [2, 2, 0, 0] },
          barMaxWidth: 14,
        },
        {
          name: "下载",
          type: "line",
          smooth: true,
          showSymbol: false,
          data: points.map((p) => p.bytes_in),
          itemStyle: { color: "#4aa3ff" },
          lineStyle: { width: 1.5 },
        },
      ],
    };
  }, [overview?.volume]);

  const agentBars = (overview?.agents ?? []).filter((a) => a.bytes_out_24h > 0).length;
  // A fixed height leaves a handful of bars stretched across the panel; follow
  // the bar count instead, with a floor so a single bar still looks deliberate.
  const agentsChartHeight = Math.min(320, Math.max(150, agentBars * 34 + 56));

  const agentsOption = useMemo<EChartsOption>(() => {
    const agents = [...(overview?.agents ?? [])].filter((a) => a.bytes_out_24h > 0).reverse();
    return {
      backgroundColor: "transparent",
      grid: { left: 96, right: 24, top: 8, bottom: 24 },
      tooltip: {
        trigger: "axis" as const,
        valueFormatter: (value) => formatBytes(Number(value)),
      },
      xAxis: {
        type: "value" as const,
        axisLabel: {
          color: "#6b7789",
          fontSize: 10.5,
          formatter: (value: number) => formatBytes(value),
        },
        splitLine: { lineStyle: { color: "#1c232e" } },
      },
      yAxis: {
        type: "category" as const,
        data: agents.map((a) => a.name),
        axisLabel: { color: "#9aa7b8", fontSize: 11 },
        axisLine: { lineStyle: { color: "#232a36" } },
      },
      series: [
        {
          name: "24h 出站",
          type: "bar",
          data: agents.map((a) => a.bytes_out_24h),
          itemStyle: { color: "#3d7dff", borderRadius: [0, 3, 3, 0] },
          barWidth: 16,
        },
      ],
    };
  }, [overview?.agents]);

  const info = overview?.info;
  const stats = overview?.stats;
  const openFindings = overview?.findings ?? [];
  const urgent = openFindings.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const installed = (overview?.agents ?? []).filter((a) => a.installed).length;

  let lastGroup = "";

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="dot" />
          <div>
            agentmon
            <small>AI Agent 上传审计 v{info?.version ?? "0.1.0"}</small>
          </div>
        </div>
        {tabs.map((item) => {
          const groupLabel = item.group !== lastGroup ? item.group : null;
          lastGroup = item.group;
          return (
            <div key={item.id}>
              {groupLabel && <div className="nav-label">{groupLabel}</div>}
              <div
                className={`nav-item ${tab === item.id ? "active" : ""}`}
                onClick={() => openTab(item.id)}
              >
                <span>{item.label}</span>
                {item.id === "findings" && urgent > 0 && <span className="badge-count">{urgent}</span>}
              </div>
            </div>
          );
        })}
        <div className="sidebar-foot" title={info?.path ?? ""}>
          {info?.path ? elidePath(info.path, 30) : "…"}
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <h2>{tabs.find((t) => t.id === tab)?.label}</h2>
          <span className={`chip ${info?.daemon_active ? "ok" : "warn"}`}>
            {info?.daemon_active ? "● 守护进程运行中" : "○ 守护进程未运行"}
          </span>
          <span className={`chip ${info?.file_audit ? "ok" : ""}`}>
            {info?.file_audit ? "文件层已启用" : "文件层未启用（需 root）"}
          </span>
          <span className={`chip ${info?.proxy_addr ? "ok" : ""}`}>
            {info?.proxy_addr ? `内容代理 ${info.proxy_addr}` : "内容代理未运行"}
          </span>
          <span className="chip">{formatBytes(info?.db_size ?? 0)} 本地库</span>
          <span style={{ marginLeft: "auto" }}>
            <button onClick={refresh}>刷新</button>
          </span>
        </div>

        {error && (
          <div className="panel">
            <div className="panel-body hint">
              读取数据库失败：{error}
              <br />
              先运行 <span className="mono">agentmond</span> 或 <span className="mono">agentmon watch</span> 生成数据。
            </div>
          </div>
        )}

        {tab === "overview" && (
          <>
            <div className="cards">
              <div className="card">
                <div className="label">检测到的 agent</div>
                <div className="value">{formatCount(stats?.agents_seen ?? 0)}</div>
                <div className="sub">其中 {installed} 个在本机已安装</div>
              </div>
              <div className="card">
                <div className="label">24h 出站总量</div>
                <div className="value">{formatBytes(stats?.bytes_out_24h ?? 0)}</div>
                <div className="sub">按进程字节累计</div>
              </div>
              <div className="card">
                <div className="label">24h 出站连接</div>
                <div className="value">{formatCount(stats?.connections_24h ?? 0)}</div>
                <div className="sub">归属到 agent 的连接</div>
              </div>
              <div className="card">
                <div className="label">文件读取事件</div>
                <div className="value">{formatCount(stats?.file_events_24h ?? 0)}</div>
                <div className="sub">{info?.file_audit ? "文件层采集中" : "需 root 守护进程"}</div>
              </div>
              <div className="card">
                <div className="label">代理抓包</div>
                <div className="value">{formatCount(stats?.http_requests_24h ?? 0)}</div>
                <div className="sub">{info?.proxy_addr ? "内容层采集中" : "内容层未运行"}</div>
              </div>
              <div className={`card ${urgent > 0 ? "accent" : ""}`}>
                <div className="label">未处理发现</div>
                <div className="value" style={{ color: urgent > 0 ? "var(--critical)" : undefined }}>
                  {formatCount(openFindings.length)}
                </div>
                <div className="sub">{urgent > 0 ? `${urgent} 条需要立即查看` : "暂无高危"}</div>
              </div>
            </div>

            <div className="grid cols-2">
              <div className="panel">
                <div className="panel-head">
                  <h3>出站流量趋势</h3>
                  <span className="muted" style={{ fontSize: 11 }}>
                    15 分钟粒度
                  </span>
                </div>
                <div className="panel-body">
                  <Chart option={volumeOption} height={228} />
                </div>
              </div>

              <div className="panel">
                <div className="panel-head">
                  <h3>各 agent 24h 出站</h3>
                </div>
                <div className="panel-body">
                  <Chart option={agentsOption} height={agentsChartHeight} />
                </div>
              </div>
            </div>

            <div className="grid cols-2">
              <DestinationsPanel destinations={overview?.destinations ?? []} limit={8} />
              <ArtifactsView artifacts={overview?.artifacts ?? []} limit={6} />
            </div>

            <div className="panel">
              <div className="panel-head">
                <h3>最新安全发现</h3>
                <div className="tools">
                  <button onClick={() => openTab("findings")}>查看全部</button>
                </div>
              </div>
              {openFindings.length === 0 ? (
                <div className="empty">暂无发现</div>
              ) : (
                openFindings
                  .slice(0, 5)
                  .map((finding) => (
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
          </>
        )}

        {tab === "egress" && (
          <DestinationsPanel
            destinations={overview?.destinations ?? []}
            agents={overview?.agents ?? []}
            limit={100}
            withFilter
          />
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
