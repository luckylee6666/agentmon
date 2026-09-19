use agentmon_core::config::Config;
use agentmon_core::util::{self, Ansi};
use agentmon_core::{paths, store};
use anyhow::Result;
use std::path::Path;

fn which(program: &str) -> Option<std::path::PathBuf> {
    let candidates = [
        format!("/usr/bin/{program}"),
        format!("/usr/sbin/{program}"),
        format!("/bin/{program}"),
        format!("/sbin/{program}"),
        format!("/usr/local/bin/{program}"),
    ];
    for candidate in candidates {
        let path = std::path::PathBuf::from(&candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn line(ok: bool, label: &str, detail: &str) {
    let (mark, color) = if ok {
        ("✓", Ansi::GREEN)
    } else {
        ("✗", Ansi::YELLOW)
    };
    println!(
        "  {color}{mark}{reset} {label:<22} {dim}{detail}{reset}",
        reset = Ansi::RESET,
        dim = Ansi::DIM
    );
}

pub fn run() -> Result<()> {
    let config = Config::load_or_default_path();
    let root = util::is_root();

    println!("{}{}agentmon doctor{}", Ansi::BOLD, Ansi::CYAN, Ansi::RESET);
    println!(
        "  {} 平台 {} · {} · agentmon {}{}\n",
        Ansi::DIM,
        std::env::consts::OS,
        std::env::consts::ARCH,
        agentmon_core::VERSION,
        Ansi::RESET
    );

    println!("{}{}采集能力{}", Ansi::BOLD, Ansi::CYAN, Ansi::RESET);

    let lsof = which("lsof");
    line(
        lsof.is_some(),
        "lsof",
        &lsof
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "未找到：无法采集出站连接".into()),
    );

    let nettop_ok = cfg!(target_os = "macos") && which("nettop").is_some();
    if cfg!(target_os = "macos") {
        line(
            nettop_ok,
            "nettop",
            if nettop_ok {
                "可用：按进程字节数（精确，需要 PTY 拉起）"
            } else {
                "未找到：无法统计按进程上传量"
            },
        );
    }
    if cfg!(target_os = "linux") {
        let fanotify = Path::new("/proc/sys/fs/fanotify/max_queued_events").exists();
        line(
            fanotify,
            "fanotify",
            if fanotify {
                "可用：文件读取审计（需 root，未在真机验证）"
            } else {
                "内核不支持（需 >= 5.1）：无法审计文件读取"
            },
        );
        let ss = which("ss");
        line(
            ss.is_some(),
            "ss",
            &ss.as_ref()
                .map(|path| format!("{}（按进程字节数，近似）", path.display()))
                .unwrap_or_else(|| "未找到：请安装 iproute2".into()),
        );
    }

    let eslogger_ok = cfg!(target_os = "macos") && Path::new("/usr/bin/eslogger").exists();
    if cfg!(target_os = "macos") {
        line(
            eslogger_ok,
            "eslogger",
            if eslogger_ok {
                "可用（Apple 自带，无需 ES entitlement）"
            } else {
                "未找到：文件读取审计不可用"
            },
        );
    }

    println!(
        "\n{}{}内容层（本地代理）{}",
        Ansi::BOLD,
        Ansi::CYAN,
        Ansi::RESET
    );
    let ca = agentmon_core::proxy::ca::Ca::load_or_create(&paths::ca_dir())?;
    line(true, "本地 CA", &ca.cert_path().display().to_string());
    line(
        config.proxy.enabled,
        "代理开关",
        &format!(
            "proxy.enabled = {}（监听 {}）",
            config.proxy.enabled, config.proxy.listen
        ),
    );
    line(
        true,
        "使用方式",
        "agentmon wrap -- <agent 命令>（自动注入代理与 CA，无需改系统信任）",
    );

    println!(
        "\n{}{}文件读取审计（需要 root）{}",
        Ansi::BOLD,
        Ansi::CYAN,
        Ansi::RESET
    );
    line(
        root,
        "当前身份",
        if root {
            "root"
        } else {
            "普通用户 —— 以 sudo 运行 agentmond 或安装为服务后启用"
        },
    );
    let service_installed = service_installed();
    line(
        service_installed,
        "守护进程服务",
        if service_installed {
            "已安装"
        } else {
            "未安装：agentmon install --dry-run 查看将要执行的步骤"
        },
    );

    println!("\n{}{}数据{}", Ansi::BOLD, Ansi::CYAN, Ansi::RESET);
    let system_db = paths::db_path(true);
    let user_db = paths::db_path(false);
    line(
        system_db.exists(),
        "系统数据库",
        &format!(
            "{} {}",
            system_db.display(),
            if system_db.exists() {
                "(存在)"
            } else {
                "(未创建)"
            }
        ),
    );
    line(
        user_db.exists(),
        "用户数据库",
        &format!(
            "{} {}",
            user_db.display(),
            if user_db.exists() {
                "(存在)"
            } else {
                "(未创建)"
            }
        ),
    );

    let active = paths::active_db_path();
    if active.exists() {
        let size = std::fs::metadata(&active).map(|m| m.len()).unwrap_or(0);
        line(
            true,
            "当前使用",
            &format!("{} ({})", active.display(), util::format_bytes(size)),
        );
        match store::open_readonly(&active) {
            Ok(conn) => {
                let since = util::now_ms() - 24 * 3600 * 1000;
                let counts = store::counts(&conn, since)?;
                let findings = store::list_findings(
                    &conn,
                    &store::FindingFilter {
                        limit: 500,
                        ..Default::default()
                    },
                )?;
                line(
                    true,
                    "近 24h 数据",
                    &format!(
                        "连接 {} · 文件事件 {} · 抓包 {} · findings {}",
                        counts.0,
                        counts.1,
                        counts.2,
                        findings.len()
                    ),
                );
                let daemon_meta = store::get_meta(&conn, "pid");
                let fresh = std::fs::metadata(&active)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .map(|elapsed| elapsed.as_secs() < 120)
                    .unwrap_or(false);
                let running_detail = if fresh {
                    format!(
                        "运行中（pid {}）",
                        daemon_meta.unwrap_or_else(|| "?".into())
                    )
                } else {
                    "未运行或已停止（数据库超过 2 分钟未更新）".to_string()
                };
                line(fresh, "守护进程", &running_detail);
                line(
                    store::get_meta(&conn, "file_audit").as_deref() == Some("1"),
                    "文件审计",
                    "由守护进程上报",
                );
            }
            Err(err) => line(false, "数据库可读", &format!("打开失败: {err}")),
        }
    } else {
        line(
            false,
            "当前使用",
            "尚无数据库：先运行 agentmon watch 或 agentmond",
        );
    }

    println!("\n{}{}配置{}", Ansi::BOLD, Ansi::CYAN, Ansi::RESET);
    let config_path = paths::config_file();
    line(
        config_path.exists(),
        "配置文件",
        &config_path.display().to_string(),
    );
    line(true, "保留天数", &format!("{} 天", config.retention_days));
    line(
        config.alert.desktop,
        "桌面通知",
        &format!("最低级别 {}", config.alert.min_severity),
    );

    let group_ok = crate::install::group_id(crate::install::GROUP_NAME).is_some();
    println!("\n{}{}权限{}", Ansi::BOLD, Ansi::CYAN, Ansi::RESET);
    line(
        group_ok,
        "agentmon 组",
        if group_ok {
            "存在"
        } else {
            "不存在（安装服务时会自动创建，GUI 依赖它读取系统数据库）"
        },
    );

    println!("\n{}{}结论{}", Ansi::BOLD, Ansi::CYAN, Ansi::RESET);
    println!(
        "  元数据层（进程/连接/字节/痕迹）: {}{}{}",
        if lsof.is_some() {
            Ansi::GREEN
        } else {
            Ansi::YELLOW
        },
        if lsof.is_some() {
            "可用"
        } else {
            "部分可用"
        },
        Ansi::RESET
    );
    println!(
        "  内容层（请求体分类）          : {}可用{}（用 agentmon wrap 启动 agent）",
        Ansi::GREEN,
        Ansi::RESET
    );
    println!(
        "  文件层（谁读了 .git/.env）    : {}{}{}",
        if root || service_installed {
            Ansi::GREEN
        } else {
            Ansi::YELLOW
        },
        if root || service_installed {
            "可用"
        } else {
            "未启用（需 root 或安装服务）"
        },
        Ansi::RESET
    );
    Ok(())
}

fn service_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        paths::launchd_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        paths::systemd_unit_path().exists()
    }
    #[cfg(windows)]
    {
        false
    }
}
