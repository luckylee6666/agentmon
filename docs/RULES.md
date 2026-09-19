# 检测规则

阈值都在 `~/.config/agentmon/config.yaml` 的 `thresholds` 段下可调。

## 关联规则（核心）

### `exfil.chain` — critical
**敏感/批量读取后，短时间内出现大额出站上传。**

- 触发源：`fs.sensitive_read` 或 `fs.bulk_read` 记录下的"读取信号"
- 条件：读取信号后 `thresholds.exfil_correlation_ms`（默认 120s）内，
  单次采样出站 ≥ 1MB
- 证据链：读取事件（含前 5 个文件样本）+ 上传事件，按时间排列
- 为什么重要：单独看"读文件"或"发请求"都正常，这个**时间耦合**才是 ZCode 那类
  "本地打包后上传"的特征签名
- 去重：同一 agent 在 `alert.dedupe_window_ms`（默认 10 分钟）内只报一次

## 文件规则（需 root 守护进程）

| 规则 | 级别 | 条件 |
|---|---|---|
| `fs.sensitive_read` | medium | 读取 `.env` / `.env.*` / `id_rsa` / `id_ed25519` / `*.pem` / `*.key` / `credentials` / `.ssh/` / `.aws/` / `.gnupg/` 等 |
| `fs.bulk_read` | medium | `bulk_read_window_ms`（60s）内读取同一仓库 `bulk_read_files`（200）个不同文件 |

`.git/**` 的读取本身不告警（正常 git 操作会读），但会计入"读取信号"：
60 秒内读 20 个以上 `.git` 文件会激活关联规则——这正是"打包整个仓库"的前兆。

## 网络规则

| 规则 | 级别 | 条件 |
|---|---|---|
| `egress.unknown_domain` | low | agent 连接到既不在其画像允许域名、也不在全局白名单、也不匹配已解析厂商 IP 的目标。跳过私有地址与保留网段。按 (agent, IP) 每小时去重 |
| `egress.volume_spike` | medium | `volume_spike_window_ms`（5 分钟）内累计出站 ≥ `volume_spike_bytes`（20MB） |
| `egress.sensitive_payload` | high | 代理抓包判定请求体含源码或密钥，且目标不在白名单 |
| `egress.sensitive_payload`（遥测端点） | **critical** | 同上，但目标命中该 agent 画像的 `telemetry_domains` |

最后一条值得单独说：**把源码发给模型 API 是这个 agent 的本职工作，发给遥测端点从来不是。**
所以允许列表里的"业务域名"和"遥测域名"要区别对待——后者一旦收到源码或密钥，
直接按 critical 处理。

`egress.unknown_domain` 默认只给 low：多提供商客户端（opencode/aider 等）会连很多
第三方 API，这属于"信息"而不是"告警"。真正需要紧张的是它和读取行为组合出现的场景。

## 痕迹规则

| 规则 | 级别 | 条件 |
|---|---|---|
| `artifact.hidden_blob` | medium | agent 数据目录中 ≥ `hidden_blob_bytes`（50MB）且香农熵 ≥ `hidden_blob_entropy`（7.5）的文件，且**不是**已知压缩/媒体/容器格式（mp4/db/pack/dylib…） |
| `artifact.unexpected_endpoint` | low | 配置文件中形如 `base_url` / `endpoint` / `telemetry` / `upload` / `ingest` 的键指向白名单外主机 |

端点提取只在"配置语义"下匹配，且跳过 `plugins/`、`marketplaces/`、`extensions/`、
`projects/`、`node_modules/` 等目录——否则会把许可证链接、文档 URL、会话记录里的
网址全部当成告警（实测噪音比约 100:1）。

## 误报处理

```bash
agentmon findings                 # 查看
agentmon ignore <id>              # 忽略
agentmon ignore <id> --undo       # 恢复
```

想长期消除某类噪音：把对应域名加进 config 的 `global_allowed_domains`，
或给该 agent 的画像补 `allowed_domains`（放 `~/.config/agentmon/profiles.d/`）。
