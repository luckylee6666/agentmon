# 架构

## 目标与威胁模型

检测 AI 编程 agent 在用户不知情时**读取本地代码/密钥并外传**的行为链：

```
读取敏感文件  →  本地打包（高熵大文件）  →  出站上传
     ↑ file audit        ↑ 静态扫描             ↑ 连接/字节/代理
                    └────── exfil.chain 关联判定 ──────┘
```

非目标：不统计、不解析用户与 AI 的正常对话内容；agentmon 自身零遥测。

## 组件

| 组件 | 角色 | 权限 |
|---|---|---|
| `agentmon-core` | 共享库：模型、存储、画像、规则引擎、采集器、DNS | — |
| `agentmond` | 采集 + 检测 + 落库 + 告警；**唯一写库者** | root（完整）/ 用户（降级） |
| `agentmon` (CLI) | `scan` / `agents` / `watch` / `findings` / `report` / `profiles` | 用户 |
| `agentmon-app` | Tauri 2 桌面端，**只读**查询 SQLite | 用户 |

```
collectors ──► Event(unbounded channel) ──► Detector ──► Finding ──► StoreWriter ──► SQLite(WAL)
   │                                                                      │
   ├─ procscan   进程归属（祖先链）                                        └─► Alerter（桌面通知 / webhook）
   ├─ netflow    连接(lsof) + 字节(nettop/ss)
   ├─ fileaudit  eslogger / fanotify / ETW
   └─ artifacts  数据目录体积·熵·配置端点
```

## 归属推断

agent 常派生 node/python 子进程。`Registry` 每轮扫描把进程匹配到画像
（exe glob / 进程名 / cmdline 正则），匹配不到则沿父进程链向上查（最多 12 层），
事件同时记录 `pid` 与 `root_agent_id`。agentmon 自身进程被排除。

## 采集实现要点

**进程字节（macOS）**：`nettop -P -x -l 0 -J state,bytes_in,bytes_out` 给的是**进程生命周期累计值**，
且**必须挂在 PTY 上**（管道下无输出）→ 用 `portable-pty` 拉起，逐行解析后自行做差。
进程名可能含空格（`Lark Helper.1422`），所以数字从右侧取、名字取剩余前缀。

**连接**：`lsof -n -P -iTCP -sTCP:ESTABLISHED -F pcn`（字段模式，易解析）。
非 root 只能看到当前用户进程——对"监控自己的 agent"这个场景足够。

**域名归属**：把画像里的允许域名正向解析成 IP 集合（每 10 分钟刷新），
再配合 PTR 反查做展示。遇到 fake-ip 代理网段（`198.18.0.0/15`、`100.64/10`、文档网段等）
直接标记为不可解析，不做域名判定（否则必然误报）。

**文件审计（macOS）**：用 Apple 自带的 `/usr/bin/eslogger`（root 即可，不需要 Apple 特批的
ES entitlement），按行流式解析 JSON；只保留归属于 agent 进程、且命中敏感路径或进程工作区内的事件，
非敏感事件做每进程限速。

## 存储

SQLite（`rusqlite` bundled，WAL）。`agentmond` 是唯一写者，单线程批量事务（250ms 或 2000 条触发）；
CLI/GUI 以只读打开。表：`agents / processes / connections / volumes / file_events / http_requests /
artifacts / findings`。默认保留 7 天，findings 至少保留 30 天。

## 信任边界

- GUI/CLI 只能**读**数据库；唯一的写操作是 `findings.status`（忽略/恢复）和配置文件。
- 守护进程不执行来自数据库或 GUI 的任意命令/路径。
- 数据库目录 0700；root 模式下数据在 `/Library/Application Support/agentmon/`。
- CA 私钥仅本地保存（内容层），不经任何通道外传。

## 内容层（本地 MITM）

`agentmon wrap -- <cmd>` 或 config 里的 `proxy.enabled`（默认监听 `127.0.0.1:8899`）。

```
客户端 ──CONNECT──► 代理 ──TLS(自签叶证书)──► 解密 ──► 分类 ──► 转发(reqwest) ──► 上游
```

- **CA**：首次使用生成 `agentmon-ca.pem` / `.key`（0600），叶证书按 SNI 动态签发并缓存。
  TLS 只 advertise `http/1.1`，避免实现 h2 的复杂度。
- **零侵入信任**：`wrap` 注入 `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` /
  `CURL_CA_BUNDLE` / `GIT_SSL_CAINFO`，不改系统信任设置。自带根证书库或做证书固定的客户端
  会握手失败（这是它的选择，不是恶意信号）。
- **请求体不落内存**：body 以流的形式转发给上游，同时把前 1MB tee 到缓冲区做分类；
  大文件上传不会把代理撑爆。
- **分类**：magic 嗅探（gzip/zlib → 解压、base64 → 解码、zip/tar/7z/rar → 归档），
  再做密钥正则与源码评分（关键字行数 + 结构行占比 + 标点密度 + `::`/`->` 特征）。
  必须存在代码关键字行才可能判为源码——这条硬门槛把 JSON 与散文挡在外面。
- **GET query 也算通道**：长 query string（≥100 字符）同样送去分类，因为把数据塞进
  URL 参数是常见的隐蔽外传手法。
- **归属**：连接源端口 → pid 的映射每秒从 `lsof` 重建，带时间戳、6 秒过期，
  避免临时端口复用导致把上传算到无关进程头上。

## 平台差异

| 能力 | macOS | Linux | Windows |
|---|---|---|---|
| 按进程字节 | `nettop`（PTY，精确） | `ss -tinp`（近似） | 未实现 |
| 文件读取审计 | `eslogger` 子进程（root） | fanotify（未实现） | ETW（未实现） |
| 内容层 | 一致 | 一致 | 一致 |
