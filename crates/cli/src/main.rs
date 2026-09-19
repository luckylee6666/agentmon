use agentmon_core::collect::artifacts;
use agentmon_core::config::Config;
use agentmon_core::detect::{DetectCtx, Detector};
use agentmon_core::model::{Event, Finding, FindingStatus, Severity};
use agentmon_core::pipeline::Pipeline;
use agentmon_core::profiles::ProfileSet;
use agentmon_core::registry::Registry;
use agentmon_core::store::{self, FindingFilter};
use agentmon_core::util::{self, Ansi};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{Cell, Color, ContentArrangement, Table};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

mod doctor;
mod install;

#[derive(Parser)]
#[command(
    name = "agentmon",
    version,
    about = "Audit what your AI coding agents read and upload",
    long_about = "agentmon 检测 AI 编程 agent（Claude Code / Codex / ZCode / Cursor …）是否在读取\n\
                  本地代码、密钥并向未授权地址上传。无特权即可运行网络与痕迹监控；\n\
                  以 root 运行 agentmond 可额外启用文件读取审计（谁读了 .git/.env）。"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 静态扫描本机 agent 的数据目录、配置与内置端点（无需特权）
    Scan {
        /// 深扫：解析配置/资源文件中的端点
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        json: bool,
    },
    /// 列出本机检测到的 agent、数据目录体积与运行状态
    Agents {
        #[arg(long)]
        json: bool,
    },
    /// 实时监控（前台运行，不起守护进程）
    Watch {
        /// 运行 N 秒后退出
        #[arg(long)]
        duration: Option<u64>,
        #[arg(long)]
        json: bool,
    },
    /// 查看已记录的 findings
    Findings {
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// 包含已忽略的条目
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// 生成报告（Agent 概览 / 出站目标 / findings）
    Report {
        #[arg(long)]
        json: bool,
    },
    /// 列出内置 agent 画像
    Profiles {
        #[arg(long)]
        json: bool,
    },
    /// 用本地代理启动一个 agent，抓取并分类它发出的请求
    Wrap {
        /// 归属到指定 agent 画像（默认按命令名推断）
        #[arg(long)]
        agent: Option<String>,
        /// 代理监听地址（默认随机端口）
        #[arg(long)]
        listen: Option<String>,
        /// 只输出 JSON
        #[arg(long)]
        json: bool,
        /// 要运行的命令
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// 单独运行本地内容代理
    Proxy {
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// 本地 CA 管理
    Ca {
        #[command(subcommand)]
        cmd: CaCmd,
    },
    /// 把 agentmond 安装成系统服务（需 sudo，解锁文件读取审计）
    Install {
        /// 只打印将要执行的步骤，不做任何改动
        #[arg(long)]
        dry_run: bool,
        /// 要加入 agentmon 组的用户（默认当前登录用户）
        #[arg(long)]
        user: Option<String>,
        /// agentmond 二进制路径
        #[arg(long)]
        binary: Option<PathBuf>,
        /// 只写文件，不启动服务
        #[arg(long)]
        no_start: bool,
    },
    /// 卸载 agentmond 服务
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
    /// 查看 agentmond 服务状态
    ServiceStatus,
    /// 自检：本机各层能力、数据与权限现状
    Doctor,
    /// 配置管理
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// 忽略某条 finding
    Ignore {
        id: i64,
        /// 取消忽略
        #[arg(long)]
        undo: bool,
    },
}

#[derive(Subcommand)]
enum CaCmd {
    /// 打印 CA 证书路径
    Path,
    /// 打印在各平台信任该 CA 的命令（需要你自己执行）
    Install,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// 打印配置文件路径
    Path,
    /// 写入默认配置（已存在则报错）
    Init,
    /// 打印当前配置
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { deep, json } => cmd_scan(deep, json),
        Commands::Agents { json } => cmd_agents(json),
        Commands::Watch { duration, json } => cmd_watch(duration, json).await,
        Commands::Findings {
            severity,
            agent,
            limit,
            all,
            json,
        } => cmd_findings(severity, agent, limit, all, json),
        Commands::Report { json } => cmd_report(json),
        Commands::Profiles { json } => cmd_profiles(json),
        Commands::Wrap {
            agent,
            listen,
            json,
            command,
        } => cmd_wrap(agent, listen, json, command).await,
        Commands::Proxy {
            listen,
            agent,
            json,
        } => cmd_proxy(listen, agent, json).await,
        Commands::Ca { cmd } => cmd_ca(cmd),
        Commands::Install {
            dry_run,
            user,
            binary,
            no_start,
        } => install::install(install::InstallOptions {
            dry_run,
            user,
            binary,
            no_start,
        }),
        Commands::Uninstall { dry_run } => install::uninstall(dry_run),
        Commands::ServiceStatus => install::status(),
        Commands::Doctor => doctor::run(),
        Commands::Config { cmd } => cmd_config(cmd),
        Commands::Ignore { id, undo } => cmd_ignore(id, undo),
    }
}

fn load_context() -> Result<(Arc<Config>, Arc<ProfileSet>)> {
    let path = agentmon_core::paths::config_file();
    let config = if path.exists() {
        Config::load(&path)?
    } else {
        let config = Config::default();
        config.save(&path)?;
        config
    };
    let config = Arc::new(config);
    let profiles = Arc::new(ProfileSet::load(&config)?);
    Ok((config, profiles))
}

fn cmd_scan(deep: bool, json: bool) -> Result<()> {
    let (config, profiles) = load_context()?;
    let outcome = artifacts::scan(&profiles, &config, deep);
    let dns = agentmon_core::dns::DnsState::new();
    let mut detector = Detector::new(config.clone(), profiles.clone(), dns);
    let registry = Registry::new();
    let ctx = DetectCtx {
        registry: &registry,
    };

    let mut findings: Vec<Finding> = Vec::new();
    for artifact in outcome
        .artifacts
        .iter()
        .cloned()
        .chain(artifacts::endpoint_artifacts(&outcome))
    {
        findings.extend(detector.evaluate(&Event::Artifact(artifact), ctx));
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "findings": findings,
                "data_dirs": outcome.dir_usage.iter().map(|u| serde_json::json!({
                    "agent_id": u.agent_id,
                    "path": u.path,
                    "size": u.size,
                    "files": u.files,
                })).collect::<Vec<_>>(),
                "endpoints": outcome.endpoints.iter().map(|e| serde_json::json!({
                    "agent_id": e.agent_id,
                    "host": e.host,
                    "path": e.path,
                })).collect::<Vec<_>>(),
                "errors": outcome.errors,
            }))?
        );
        return Ok(());
    }

    print_title("静态扫描");
    if outcome.dir_usage.is_empty() {
        println!("未发现本机安装的 agent 数据目录。");
    } else {
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["agent", "数据目录", "体积", "文件数"]);
        for usage in &outcome.dir_usage {
            table.add_row(vec![
                Cell::new(&usage.agent_id),
                Cell::new(util::truncate_middle(&usage.path.to_string_lossy(), 56)),
                Cell::new(util::format_bytes(usage.size)),
                Cell::new(usage.files.to_string()),
            ]);
        }
        println!("{table}");
    }

    print_findings(&findings);
    println!(
        "{}扫描用时 {} ms{}",
        Ansi::DIM,
        outcome.duration_ms,
        Ansi::RESET
    );
    print_next_steps(&findings);
    Ok(())
}

fn cmd_agents(json: bool) -> Result<()> {
    let (_, profiles) = load_context()?;
    let mut system = sysinfo::System::new_all();
    let mut registry = Registry::new();
    registry.refresh(&mut system, &profiles);

    let running: HashMap<String, usize> = {
        let mut map = HashMap::new();
        for pid in registry.tracked_pids() {
            if let Some(agent) = registry.agent_id(pid) {
                *map.entry(agent.to_string()).or_insert(0) += 1;
            }
        }
        map
    };

    let mut rows = Vec::new();
    for profile in profiles.all() {
        let size: u64 = profile
            .data_dir_paths()
            .iter()
            .map(|p| artifacts::dir_size(p))
            .sum();
        rows.push(serde_json::json!({
            "id": profile.id,
            "name": profile.name,
            "vendor": profile.vendor,
            "installed": profile.installed(),
            "data_dir_bytes": size,
            "running_processes": running.get(&profile.id).copied().unwrap_or(0),
        }));
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    print_title("agent 清单");
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec![
        "id",
        "名称",
        "厂商",
        "已安装",
        "数据目录",
        "运行中进程",
    ]);
    for row in &rows {
        let installed = row["installed"].as_bool().unwrap_or(false);
        let running = row["running_processes"].as_u64().unwrap_or(0);
        table.add_row(vec![
            Cell::new(row["id"].as_str().unwrap_or("-")),
            Cell::new(row["name"].as_str().unwrap_or("-")),
            Cell::new(row["vendor"].as_str().unwrap_or("-")),
            Cell::new(if installed { "是" } else { "-" }).fg(if installed {
                Color::Green
            } else {
                Color::DarkGrey
            }),
            Cell::new(util::format_bytes(
                row["data_dir_bytes"].as_u64().unwrap_or(0),
            )),
            Cell::new(running.to_string()).fg(if running > 0 {
                Color::Yellow
            } else {
                Color::DarkGrey
            }),
        ]);
    }
    println!("{table}");
    Ok(())
}

async fn cmd_watch(duration: Option<u64>, json: bool) -> Result<()> {
    let (config, profiles) = load_context()?;
    let (mut pipeline, mut events) = Pipeline::start(config.clone(), profiles.clone()).await;
    let mut detector = Detector::new(config.clone(), profiles.clone(), pipeline.dns.clone());
    let registry = pipeline.registry.clone();

    if !json {
        print_title("实时监控");
        println!(
            "{}文件读取审计: {}   按进程字节统计: {}{}",
            Ansi::DIM,
            if pipeline.availability.file_audit {
                "启用"
            } else {
                "未启用（需以 root 运行 agentmond）"
            },
            if pipeline.availability.byte_accounting {
                "精确"
            } else {
                "近似"
            },
            Ansi::RESET
        );
        println!("{}按 Ctrl+C 退出{}\n", Ansi::DIM, Ansi::RESET);
    }

    let deadline = duration.map(|secs| tokio::time::Instant::now() + Duration::from_secs(secs));
    let startup_until = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut seen_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut agent_counts: HashMap<String, usize> = HashMap::new();
    let mut connection_count = 0usize;
    let mut finding_count = 0usize;
    let mut status = tokio::time::interval(Duration::from_secs(20));
    status.tick().await;

    loop {
        tokio::select! {
            maybe_event = events.recv() => {
                let Some(event) = maybe_event else { break };
                match &event {
                    Event::Process(info)
                        if seen_pids.insert(info.pid) => {
                            let agent = info.agent_id.clone().unwrap_or_else(|| "-".into());
                            *agent_counts.entry(agent.clone()).or_insert(0) += 1;
                            if !json && tokio::time::Instant::now() >= startup_until {
                                println!(
                                    "{}● 新 agent 进程{} pid={} agent={} cwd={}",
                                    Ansi::CYAN,
                                    Ansi::RESET,
                                    info.pid,
                                    agent,
                                    info.cwd.as_ref().map(|c| c.display().to_string()).unwrap_or_else(|| "-".into())
                                );
                            }
                        }
                    Event::Connection(_) => connection_count += 1,
                    _ => {}
                }
                let findings = {
                    let registry = registry.read().unwrap_or_else(|e| e.into_inner());
                    detector.evaluate(&event, DetectCtx { registry: &registry })
                };
                if !findings.is_empty() {
                    finding_count += findings.len();
                    if json {
                        for finding in &findings {
                            println!("{}", serde_json::to_string(finding)?);
                        }
                    } else {
                        print_findings(&findings);
                    }
                }
            }
            _ = status.tick() => {
                if !json {
                    let agents: Vec<String> = agent_counts
                        .iter()
                        .map(|(agent, count)| format!("{agent}×{count}"))
                        .collect();
                    println!(
                        "{}— 监控中: {} 个进程 [{}] | 出站连接 {} | findings {}{}",
                        Ansi::DIM,
                        seen_pids.len(),
                        agents.join(", "),
                        connection_count,
                        finding_count,
                        Ansi::RESET
                    );
                }
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = sleep_until(deadline) => break,
        }
    }

    pipeline.stop();
    if !json {
        let agents: Vec<String> = agent_counts
            .iter()
            .map(|(agent, count)| format!("{agent}×{count}"))
            .collect();
        println!(
            "\n{}监控结束: {} 个 agent 进程 [{}] | 出站连接 {} | findings {}{}",
            Ansi::DIM,
            seen_pids.len(),
            agents.join(", "),
            connection_count,
            finding_count,
            Ansi::RESET
        );
    }
    Ok(())
}

async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(instant) => tokio::time::sleep_until(instant).await,
        None => std::future::pending::<()>().await,
    }
}

fn cmd_findings(
    severity: Option<String>,
    agent: Option<String>,
    limit: i64,
    all: bool,
    json: bool,
) -> Result<()> {
    let path = agentmon_core::paths::active_db_path();
    if !path.exists() {
        println!(
            "尚无数据库 {}。先运行 `agentmond` 或 `agentmon watch`。",
            path.display()
        );
        return Ok(());
    }
    let conn = store::open_readonly(&path)?;
    let filter = FindingFilter {
        min_severity: severity.as_deref().and_then(Severity::parse),
        agent_id: agent,
        rule_id: None,
        include_ignored: all,
        limit,
    };
    let findings = store::list_findings(&conn, &filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&findings)?);
        return Ok(());
    }
    print_findings(&findings);
    Ok(())
}

fn cmd_report(json: bool) -> Result<()> {
    let path = agentmon_core::paths::active_db_path();
    if !path.exists() {
        println!(
            "尚无数据库 {}。先运行 `agentmond` 或 `agentmon watch`。",
            path.display()
        );
        return Ok(());
    }
    let conn = store::open_readonly(&path)?;
    let summaries = store::agent_summaries(&conn)?;
    let findings = store::list_findings(
        &conn,
        &FindingFilter {
            limit: 500,
            ..Default::default()
        },
    )?;
    let since = util::now_ms() - 24 * 3600 * 1000;
    let destinations = store::destinations(&conn, since, 50)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "agents": summaries.iter().map(|s| serde_json::json!({
                    "id": s.id, "name": s.name, "vendor": s.vendor,
                    "last_seen": s.last_seen, "bytes_out_24h": s.bytes_out_24h,
                    "open_findings": s.open_findings,
                })).collect::<Vec<_>>(),
                "findings": findings,
                "destinations": destinations.iter().map(|d| serde_json::json!({
                    "agent_id": d.agent_id, "host": d.host, "connections": d.connections,
                })).collect::<Vec<_>>(),
            }))?
        );
        return Ok(());
    }

    print_title("agentmon 报告");
    println!("生成时间: {}\n", util::format_ts(util::now_ms()));

    println!("## Agent 概览\n");
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["agent", "厂商", "最近活动", "24h 出站", "未处理"]);
    for summary in &summaries {
        table.add_row(vec![
            Cell::new(&summary.name),
            Cell::new(&summary.vendor),
            Cell::new(util::format_ago(summary.last_seen)),
            Cell::new(util::format_bytes(summary.bytes_out_24h)),
            Cell::new(summary.open_findings.to_string()),
        ]);
    }
    println!("{table}\n");

    println!("## 近 24h 出站目标（Top {}）\n", destinations.len().min(20));
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["agent", "目标", "连接次数"]);
    for destination in destinations.iter().take(20) {
        table.add_row(vec![
            Cell::new(destination.agent_id.clone().unwrap_or_else(|| "-".into())),
            Cell::new(&destination.host),
            Cell::new(destination.connections.to_string()),
        ]);
    }
    println!("{table}\n");

    println!("## Findings（{} 条未处理）\n", findings.len());
    print_findings(&findings);
    Ok(())
}

fn cmd_profiles(json: bool) -> Result<()> {
    let (_, profiles) = load_context()?;
    if json {
        let items: Vec<_> = profiles
            .all()
            .map(|p| {
                serde_json::json!({
                    "id": p.id, "name": p.name, "vendor": p.vendor,
                    "data_dirs": p.data_dirs, "allowed_domains": p.allowed_domains,
                    "telemetry_domains": p.telemetry_domains, "notes": p.notes,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    print_title("内置 agent 画像");
    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["id", "名称", "厂商", "允许域名", "数据目录"]);
    for profile in profiles.all() {
        table.add_row(vec![
            Cell::new(&profile.id),
            Cell::new(&profile.name),
            Cell::new(&profile.vendor),
            Cell::new(profile.allowed_domains.len().to_string()),
            Cell::new(profile.data_dirs.len().to_string()),
        ]);
    }
    println!("{table}");
    println!(
        "\n{}可在 {} 下放置自定义画像（同 id 覆盖内置）。{}",
        Ansi::DIM,
        agentmon_core::paths::user_profiles_dir().display(),
        Ansi::RESET
    );
    Ok(())
}

fn cmd_ca(cmd: CaCmd) -> Result<()> {
    let dir = agentmon_core::paths::ca_dir();
    match cmd {
        CaCmd::Path => {
            let ca = agentmon_core::proxy::ca::Ca::load_or_create(&dir)?;
            println!("{}", ca.cert_path().display());
        }
        CaCmd::Install => {
            let ca = agentmon_core::proxy::ca::Ca::load_or_create(&dir)?;
            let path = ca.cert_path();
            println!("CA 证书: {}\n", path.display());
            println!("让 agent 信任该 CA 的方式（三选一）：");
            println!(
                "\n1) 推荐：用 `agentmon wrap -- <命令>` 启动，会自动注入 NODE_EXTRA_CA_CERTS /\n   SSL_CERT_FILE / REQUESTS_CA_BUNDLE，无需改动系统信任设置。"
            );
            println!("\n2) 系统级信任（会全局生效，请自行决定）：");
            println!(
                "   macOS : sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '{}'",
                path.display()
            );
            println!(
                "   Linux : sudo cp '{}' /usr/local/share/ca-certificates/agentmon-ca.crt && sudo update-ca-certificates",
                path.display()
            );
            println!(
                "   Windows: certutil -addstore -user Root '{}'",
                path.display()
            );
            println!("\n3) 只给单个进程注入环境变量（示例）：");
            println!(
                "   HTTPS_PROXY=http://127.0.0.1:8899 SSL_CERT_FILE='{}' <命令>",
                path.display()
            );
        }
    }
    Ok(())
}

fn proxy_env_vars(
    addr: std::net::SocketAddr,
    ca_cert: &std::path::Path,
) -> Vec<(&'static str, String)> {
    let url = format!("http://{addr}");
    let ca = ca_cert.display().to_string();
    vec![
        ("HTTPS_PROXY", url.clone()),
        ("HTTP_PROXY", url.clone()),
        ("ALL_PROXY", url.clone()),
        ("https_proxy", url.clone()),
        ("http_proxy", url.clone()),
        ("all_proxy", url),
        ("NO_PROXY", "localhost,127.0.0.1,::1".to_string()),
        ("no_proxy", "localhost,127.0.0.1,::1".to_string()),
        ("NODE_EXTRA_CA_CERTS", ca.clone()),
        ("SSL_CERT_FILE", ca.clone()),
        ("REQUESTS_CA_BUNDLE", ca.clone()),
        ("CURL_CA_BUNDLE", ca.clone()),
        ("GIT_SSL_CAINFO", ca.clone()),
        ("NODE_USE_ENV_PROXY", "1".to_string()),
    ]
}

async fn cmd_wrap(
    agent: Option<String>,
    listen: Option<String>,
    json: bool,
    command: Vec<String>,
) -> Result<()> {
    let (config, profiles) = load_context()?;
    let ca = Arc::new(agentmon_core::proxy::ca::Ca::load_or_create(
        &agentmon_core::paths::ca_dir(),
    )?);
    let listen_addr: std::net::SocketAddr = listen
        .unwrap_or_else(|| "127.0.0.1:0".into())
        .parse()
        .context("解析 --listen 失败")?;

    let agent_id = agent.or_else(|| {
        let name = std::path::Path::new(&command[0])
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| command[0].clone());
        profiles
            .match_process(&name, None, &command)
            .map(|id| id.to_string())
    });

    let registry: agentmon_core::collect::SharedRegistry =
        Arc::new(std::sync::RwLock::new(Registry::new()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let proxy = agentmon_core::proxy::MitmProxy::start(
        agentmon_core::proxy::ProxyOptions {
            listen: listen_addr,
            default_agent: agent_id.clone(),
            capture_bytes: config.proxy.capture_bytes,
        },
        ca.clone(),
        Some(tx),
        registry.clone(),
        profiles.clone(),
    )
    .await?;

    // Captures are persisted as well as printed, so the desktop app sees the
    // same traffic without depending on the daemon's own proxy.
    let store = agentmon_core::store::StoreWriter::spawn(
        agentmon_core::paths::active_db_path(),
        config.retention_days,
    )
    .ok();
    let mut detector = Detector::new(
        config.clone(),
        profiles.clone(),
        agentmon_core::dns::DnsState::new(),
    );

    let captures = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Event::Http(capture) = &event {
                let findings = {
                    let registry = registry.read().unwrap_or_else(|e| e.into_inner());
                    detector.evaluate(&event, DetectCtx { registry: &registry })
                };
                if let Some(store) = &store {
                    store.send_event(event.clone());
                    store.send_findings(findings.clone());
                }
                if !json {
                    for finding in &findings {
                        print_finding_line(finding);
                    }
                }
                if json {
                    println!("{}", serde_json::to_string(capture).unwrap_or_default());
                } else {
                    print_capture(capture);
                }
            }
        }
        if let Some(store) = store {
            store.shutdown();
        }
    });

    if !json {
        print_title("内容审计代理");
        println!(
            "{}代理: {}   CA: {}\nagent: {}   命令: {}{}\n",
            Ansi::DIM,
            proxy.addr,
            ca.cert_path().display(),
            agent_id.as_deref().unwrap_or("(未识别)"),
            command.join(" "),
            Ansi::RESET
        );
    }

    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    for (key, value) in proxy_env_vars(proxy.addr, &ca.cert_path()) {
        cmd.env(key, value);
    }
    let status = cmd.status().await.context("启动子进程失败")?;

    captures.abort();
    proxy.stop();
    if !json {
        println!(
            "\n{}子进程退出码: {}{}",
            Ansi::DIM,
            status.code().unwrap_or(-1),
            Ansi::RESET
        );
    }
    Ok(())
}

async fn cmd_proxy(listen: Option<String>, agent: Option<String>, json: bool) -> Result<()> {
    let (config, profiles) = load_context()?;
    let ca = Arc::new(agentmon_core::proxy::ca::Ca::load_or_create(
        &agentmon_core::paths::ca_dir(),
    )?);
    let listen_addr: std::net::SocketAddr = listen
        .unwrap_or_else(|| config.proxy.listen.clone())
        .parse()
        .context("解析 --listen 失败")?;
    let registry: agentmon_core::collect::SharedRegistry =
        Arc::new(std::sync::RwLock::new(Registry::new()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let proxy = agentmon_core::proxy::MitmProxy::start(
        agentmon_core::proxy::ProxyOptions {
            listen: listen_addr,
            default_agent: agent,
            capture_bytes: config.proxy.capture_bytes,
        },
        ca.clone(),
        Some(tx),
        registry,
        profiles,
    )
    .await?;

    if !json {
        print_title("内容审计代理");
        println!(
            "{}监听 {}   CA: {}\n把 agent 的 HTTPS_PROXY 指向该地址，或用 `agentmon wrap` 启动。{}\n",
            Ansi::DIM,
            proxy.addr,
            ca.cert_path().display(),
            Ansi::RESET
        );
    }

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                let Some(event) = maybe else { break };
                if let Event::Http(capture) = event {
                    if json {
                        println!("{}", serde_json::to_string(&capture)?);
                    } else {
                        print_capture(&capture);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    proxy.stop();
    Ok(())
}

fn print_finding_line(finding: &Finding) {
    let color = Ansi::severity(finding.severity);
    println!(
        "  {color}↳ [{}] {}{}",
        finding.severity.as_str().to_uppercase(),
        finding.title,
        Ansi::RESET
    );
}

fn print_capture(capture: &agentmon_core::model::HttpCapture) {
    let color = match capture.class.as_str() {
        "secret" => Ansi::RED,
        "source_code" => Ansi::MAGENTA,
        "archive" => Ansi::YELLOW,
        _ => Ansi::DIM,
    };
    let agent = capture.agent_id.as_deref().unwrap_or("-");
    println!(
        "{color}[{}]{reset} {agent} → {host}{path}  {dim}{}{reset}",
        capture.class.to_uppercase(),
        util::format_bytes(capture.bytes_out),
        reset = Ansi::RESET,
        dim = Ansi::DIM,
        host = capture.host,
        path = truncate_path(&capture.path),
    );
    if let Some(sample) = &capture.sample {
        println!("      {}{}{}", Ansi::DIM, sample, Ansi::RESET);
    }
}

fn truncate_path(path: &str) -> String {
    if path.len() <= 80 {
        path.to_string()
    } else {
        format!("{}…", &path[..80])
    }
}

fn cmd_config(cmd: ConfigCmd) -> Result<()> {
    let path = agentmon_core::paths::config_file();
    match cmd {
        ConfigCmd::Path => println!("{}", path.display()),
        ConfigCmd::Init => {
            if path.exists() {
                anyhow::bail!("配置已存在: {}", path.display());
            }
            let path = Config::default().save_default()?;
            println!("已写入默认配置: {}", path.display());
        }
        ConfigCmd::Show => {
            let config = Config::load(&path)?;
            println!("{}", serde_norway::to_string(&config)?);
        }
    }
    Ok(())
}

fn cmd_ignore(id: i64, undo: bool) -> Result<()> {
    let path = agentmon_core::paths::active_db_path();
    if !path.exists() {
        anyhow::bail!("数据库不存在: {}", path.display());
    }
    let conn = store::open(&path).context("opening database")?;
    let status = if undo {
        FindingStatus::Open
    } else {
        FindingStatus::Ignored
    };
    store::set_finding_status(&conn, id, status)?;
    println!("finding {id} 已标记为 {}", status.as_str());
    Ok(())
}

fn print_title(title: &str) {
    if Ansi::enabled() {
        println!("\n{}{}{}{}", Ansi::BOLD, Ansi::CYAN, title, Ansi::RESET);
        println!("{}", "─".repeat(title.chars().count().max(20)));
    } else {
        println!("\n# {title}");
    }
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        println!("{}未发现可疑行为{}", Ansi::DIM, Ansi::RESET);
        return;
    }
    for finding in findings {
        let color = Ansi::severity(finding.severity);
        let id = finding.id.map(|id| format!(" #{id}")).unwrap_or_default();
        println!(
            "{color}[{}]{reset}{id} {bold}{}{reset}",
            finding.severity.as_str().to_uppercase(),
            finding.title,
            reset = Ansi::RESET,
            bold = Ansi::BOLD,
        );
        println!("      {}{}{}", Ansi::DIM, finding.detail, Ansi::RESET);
        for evidence in finding.evidence.iter().take(4) {
            println!(
                "      {}· {} {}{}",
                Ansi::DIM,
                util::format_ts(evidence.ts),
                evidence.summary,
                Ansi::RESET
            );
        }
        println!();
    }
}

fn print_next_steps(findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    println!(
        "{}提示: 实时查看请运行 `agentmon watch`；后台监控请以 root 运行 `agentmond`（启用文件读取审计）。{}",
        Ansi::DIM,
        Ansi::RESET
    );
}
