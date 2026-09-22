# agentmon — 项目记忆

监控 AI 编程 agent（Claude Code、Codex CLI、ZCode、opencode…）是否在用户不知情时
读取并外传本地代码与密钥。起因是智谱 ZCode 被曝静默打包上传整个仓库（含 `.git`）。

三层检测，能力递增、权限也递增：

1. **元数据层**（无权限）：进程归属、出站连接、按进程字节数（macOS 走 nettop+PTY）、静态痕迹扫描
2. **内容层**（`agentmon wrap` 起本地 MITM）：请求体判定源码/密钥/归档，密钥**只记类型不记值**
3. **文件层**（需 root 守护进程）：审计 `.git`/`.env`/私钥的读取

核心是 `exfil.chain`：敏感或批量读取后 120 秒内出现上传 → critical。
单看"读文件"或"发请求"都正常，**时间咬合**才是"打包后上传"的签名。

## 结构

- `crates/core` — 模型、配置、画像、SQLite、规则引擎、采集器、MITM 代理、安装器
- `crates/cli` — `agentmon`：scan / agents / watch / wrap / proxy / capture / report / install / doctor
- `crates/daemon` — `agentmond`：常驻采集+检测+落库；root 时自动启用文件层
- `crates/app` — Tauri 2 桌面端（`src-tauri` Rust 后端 + React/TS 前端）
- `profiles/*.yaml` — 17 个内置 agent 画像：进程特征、数据目录、允许域名、遥测域名

## 规则

- **只在 macOS 上真机验证过。** Linux fanotify 与 Windows ETW 的代码在，但没在真机跑过；
  不要把未验证的平台能力说成"可用"。
- **eslogger 解析器没有用真实输出验证过**（需要 root 才能拿到样本），字段是按文档写的。
  如果"文件层已启用"但文件读取事件恒为 0，先怀疑这里。
- 这是**检测工具，不阻断**。任何文案、README、视频都不要说成"拦截/防住"。
- 请求体原文**默认不落盘**（`capture.capture_bodies`），必须显式开启；这是有意的隐私设计。
- 安装计划必须**自给自足**：每一步写入的目录都要有先行的 `EnsureDir`。
  回归测试 `install::tests::the_plan_actually_installs_into_a_sandbox` 会把绝对路径重写进
  临时沙箱并真的执行整个脚本——`set -e` 会把漏掉的 mkdir 变成测试失败。
- 改完前端后要 `touch crates/app/src-tauri/src/lib.rs` 再构建，否则 `dist/` 不会被重新嵌入
  Tauri 二进制（Cargo 不知道 dist 变了）。
- 验证界面用无头 Chrome 截图（`pnpm dev` 起 1420 端口，浏览器里走 `src/mock.ts` 的样例数据），
  不要凭想象改样式。
- 提交信息写清"为什么这么做"和"发现了什么 bug"，末尾带 `Co-authored-by` trailer。

## 常用命令

```bash
cargo test                                  # 65 单测 + 2 端到端
cd crates/app && pnpm dev                   # 浏览器预览（mock 数据）
cd crates/app && pnpm tauri build --bundles app
sudo ./target/release/agentmon install      # 启用文件层（也可在桌面端设置页点按钮）
./target/release/agentmon doctor            # 一眼看清三层是否可用
```

## 尚未完成 / 未验证

**待验证**

- macOS root 守护进程**尚未真正装上**，装上后第一件事是确认 eslogger 解析器能吃真实输出。
- Linux fanotify 未在真机验证：协议层有 6 个测试，系统调用层只做过静态审查。
- CI 从未实际跑过，Linux/Windows 能否编译未验证（本地交叉编译装不上 target）。
- `exfil.chain` 在真实 root 环境下的表现未验证，目前只有合成事件单测 + 无 root 的端到端。
- 界面上的"文件审计"页还没有真实数据验证过（因为文件层还没跑起来）。
- nettop 常驻采样的 CPU 开销未测。

**未实现**

- Windows 文件审计（`collect/fileaudit/windows.rs` 是 stub）；Windows 服务安装只打印 `sc.exe` 命令。
- 打包只做了 macOS `.app`：没有 dmg / msi / AppImage / Homebrew formula。
- 代理只支持 HTTP/1.1（ALPN 限死），h2-only 客户端可能失败；做证书固定的客户端会 TLS 失败，
  目前没有降级策略。
- 只检查请求（上传），不检查响应。
- `docs/ARCHITECTURE.md` 未更新，缺 install / 代理 / fanotify 三块。

**已知薄弱点**

- 数据库迁移很简陋：只有一处手写的 `ALTER TABLE`（给 `http_requests` 加 `body`）。
- `agentmon` 组成员身份要重新登录才生效，在那之前桌面端读不到系统数据库（界面有提示）。

**手头的事**

- 抖音视频：文案已定，待录制。录之前要清掉库里我测试时造的演示上传
  （往 httpbin.org 传源码和假密钥那几条），否则会被当成真实抓到的外传。
