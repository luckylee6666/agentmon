use crate::paths;
use crate::util::Ansi;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SERVICE_LABEL: &str = "ai.agentmon.agentmond";
#[allow(dead_code)]
pub const SERVICE_NAME: &str = "agentmond";
pub const GROUP_NAME: &str = "agentmon";

pub struct InstallOptions {
    pub dry_run: bool,
    pub user: Option<String>,
    pub binary: Option<PathBuf>,
    pub no_start: bool,
}

#[derive(Debug, Clone)]
pub enum Step {
    Note(String),
    EnsureDir {
        path: PathBuf,
        mode: u32,
        group: Option<String>,
    },
    WriteFile {
        path: PathBuf,
        mode: u32,
        contents: String,
    },
    CopyFile {
        from: PathBuf,
        to: PathBuf,
        mode: u32,
    },
    Run {
        program: String,
        args: Vec<String>,
        ignore_failure: bool,
    },
    Remove(PathBuf),
}

/// The plan a caller can render, show to the user, or execute directly.
pub fn plan_install(opts: &InstallOptions) -> Result<Vec<Step>> {
    let binary = daemon_binary(opts)?;
    let user = invoking_user(&opts.user);
    build_plan(opts, &binary, &user)
}

pub fn plan_uninstall() -> Vec<Step> {
    build_uninstall_plan()
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Renders a plan as a POSIX shell script. The desktop app runs this through
/// `osascript ... with administrator privileges`, so every path is quoted and
/// nothing here may come from the UI.
pub fn render_script(steps: &[Step]) -> String {
    let mut out = String::from("set -e\n");
    for step in steps {
        match step {
            Step::Note(text) => out.push_str(&format!("# {text}\n")),
            Step::EnsureDir { path, mode, group } => {
                out.push_str(&format!(
                    "mkdir -p {}\n",
                    shell_quote(&path.display().to_string())
                ));
                out.push_str(&format!(
                    "chmod {mode:o} {}\n",
                    shell_quote(&path.display().to_string())
                ));
                if let Some(group) = group {
                    out.push_str(&format!(
                        "chgrp {} {} 2>/dev/null || true\n",
                        shell_quote(group),
                        shell_quote(&path.display().to_string())
                    ));
                }
            }
            Step::WriteFile {
                path,
                mode,
                contents,
            } => {
                out.push_str(&format!(
                    "cat > {} <<'AGENTMON_EOF'\n",
                    shell_quote(&path.display().to_string())
                ));
                out.push_str(contents);
                if !contents.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("AGENTMON_EOF\n");
                out.push_str(&format!(
                    "chmod {mode:o} {}\n",
                    shell_quote(&path.display().to_string())
                ));
            }
            Step::CopyFile { from, to, mode } => {
                out.push_str(&format!(
                    "cp -f {} {}\n",
                    shell_quote(&from.display().to_string()),
                    shell_quote(&to.display().to_string())
                ));
                out.push_str(&format!(
                    "chmod {mode:o} {}\n",
                    shell_quote(&to.display().to_string())
                ));
            }
            Step::Run {
                program,
                args,
                ignore_failure,
            } => {
                let mut line = shell_quote(program);
                for arg in args {
                    line.push(' ');
                    line.push_str(&shell_quote(arg));
                }
                if *ignore_failure {
                    line.push_str(" || true");
                }
                out.push_str(&line);
                out.push('\n');
            }
            Step::Remove(path) => {
                out.push_str(&format!(
                    "rm -rf {}\n",
                    shell_quote(&path.display().to_string())
                ));
            }
        }
    }
    out
}

/// Human readable one-liners for a confirmation prompt.
pub fn describe(steps: &[Step]) -> Vec<String> {
    steps
        .iter()
        .filter_map(|step| match step {
            Step::Note(text) => Some(text.clone()),
            Step::CopyFile { to, .. } => Some(format!("复制二进制到 {}", to.display())),
            Step::WriteFile { path, .. } => Some(format!("写入 {}", path.display())),
            Step::EnsureDir { path, .. } => Some(format!("准备目录 {}", path.display())),
            Step::Remove(path) => Some(format!("删除 {}", path.display())),
            Step::Run { .. } => None,
        })
        .collect()
}

fn invoking_user(explicit: &Option<String>) -> String {
    if let Some(user) = explicit {
        return user.clone();
    }
    std::env::var("SUDO_USER")
        .ok()
        .filter(|user| !user.is_empty() && user != "root")
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "root".into())
}

fn daemon_binary(opts: &InstallOptions) -> Result<PathBuf> {
    if let Some(path) = &opts.binary {
        return Ok(path.clone());
    }
    let current = std::env::current_exe().context("locating current executable")?;
    let sibling = current.with_file_name(format!("agentmond{}", std::env::consts::EXE_SUFFIX));
    if sibling.is_file() {
        return Ok(sibling);
    }
    anyhow::bail!(
        "找不到 agentmond（期望在 {}）。用 --binary 指定路径。",
        sibling.display()
    )
}

fn managed_binary_dir() -> PathBuf {
    managed_binary_path()
        .parent()
        .map(|dir| dir.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/usr/local/lib/agentmon"))
}

fn managed_binary_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/usr/local/lib/agentmon/agentmond")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/usr/local/lib/agentmon/agentmond")
    }
    #[cfg(windows)]
    {
        PathBuf::from("C:\\ProgramData\\agentmon\\agentmond.exe")
    }
}

fn execute(step: &Step, dry_run: bool) {
    match step {
        Step::Note(text) => {
            if dry_run {
                println!("{}· {text}{}", Ansi::DIM, Ansi::RESET);
            }
        }
        Step::EnsureDir { path, mode, group } => {
            if dry_run {
                println!(
                    "{}mkdir -p {} (mode {:o}{}){}",
                    Ansi::DIM,
                    path.display(),
                    mode,
                    group
                        .as_ref()
                        .map(|group| format!(", group {group}"))
                        .unwrap_or_default(),
                    Ansi::RESET
                );
                return;
            }
            if let Err(err) = std::fs::create_dir_all(path) {
                eprintln!("创建目录失败 {}: {err}", path.display());
                return;
            }
            set_mode(path, *mode);
            if let Some(group) = group
                && let Some(gid) = group_id(group)
            {
                let _ = chown(path, 0, gid);
            }
        }
        Step::WriteFile {
            path,
            mode,
            contents,
        } => {
            if dry_run {
                println!(
                    "{}write {} (mode {:o}, {} bytes){}",
                    Ansi::DIM,
                    path.display(),
                    mode,
                    contents.len(),
                    Ansi::RESET
                );
                return;
            }
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(err) = std::fs::write(path, contents) {
                eprintln!("写入失败 {}: {err}", path.display());
                return;
            }
            set_mode(path, *mode);
        }
        Step::CopyFile { from, to, mode } => {
            if dry_run {
                println!(
                    "{}install -m {:o} {} {}{}",
                    Ansi::DIM,
                    mode,
                    from.display(),
                    to.display(),
                    Ansi::RESET
                );
                return;
            }
            if let Some(parent) = to.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(err) = std::fs::copy(from, to) {
                eprintln!("复制失败 {} -> {}: {err}", from.display(), to.display());
                return;
            }
            set_mode(to, *mode);
        }
        Step::Run {
            program,
            args,
            ignore_failure,
        } => {
            if dry_run {
                println!("{}{} {}{}", Ansi::DIM, program, args.join(" "), Ansi::RESET);
                return;
            }
            match Command::new(program).args(args).output() {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let message = format!(
                        "{program} 退出码 {:?}: {}",
                        output.status.code(),
                        stderr.trim()
                    );
                    if !ignore_failure {
                        eprintln!("{message}");
                    } else {
                        eprintln!("{}注意: {message}{}", Ansi::DIM, Ansi::RESET);
                    }
                }
                Err(err) => {
                    if !ignore_failure {
                        eprintln!("{program} 执行失败: {err}");
                    }
                }
            }
        }
        Step::Remove(path) => {
            if dry_run {
                println!("{}rm -f {}{}", Ansi::DIM, path.display(), Ansi::RESET);
                return;
            }
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

#[cfg(unix)]
fn chown(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::ffi::CString;
    let c_path = CString::new(path.as_os_str().to_string_lossy().as_bytes())?;
    // SAFETY: c_path is a valid NUL terminated string, uid/gid are plain ints.
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
pub fn group_id(name: &str) -> Option<u32> {
    use std::ffi::CString;
    let c_name = CString::new(name).ok()?;
    // SAFETY: getgrnam returns a pointer into a static buffer; we copy the field
    // we need immediately and never retain the pointer.
    let group = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if group.is_null() {
        None
    } else {
        Some(unsafe { (*group).gr_gid })
    }
}

#[cfg(not(unix))]
pub fn group_id(_name: &str) -> Option<u32> {
    None
}

pub fn install(opts: InstallOptions) -> Result<()> {
    if !opts.dry_run && !cfg!(windows) && !crate::util::is_root() {
        anyhow::bail!("安装系统级守护进程需要 root：请用 sudo 运行（或先 --dry-run 看看会做什么）");
    }
    let binary = daemon_binary(&opts)?;
    let user = invoking_user(&opts.user);
    let steps = build_plan(&opts, &binary, &user)?;

    println!(
        "{}{}安装 agentmond 服务（{}）{}",
        Ansi::BOLD,
        if opts.dry_run { "[dry-run] " } else { "" },
        std::env::consts::OS,
        Ansi::RESET
    );
    for step in &steps {
        execute(step, opts.dry_run);
    }

    if opts.dry_run {
        println!(
            "\n{}以上为 dry-run，未做任何改动。去掉 --dry-run 并加 sudo 执行真正安装。{}",
            Ansi::DIM,
            Ansi::RESET
        );
        return Ok(());
    }
    println!("\n{}安装完成。{}", Ansi::GREEN, Ansi::RESET);
    println!("  数据目录: {}", paths::data_dir(true).display());
    println!("  数据库  : {}", paths::db_path(true).display());
    println!("  日志    : {}", log_path().display());
    println!("  用户 {user} 已加入 {GROUP_NAME} 组，需重新登录后 GUI 才能读取系统数据库。");
    println!("\n验证: agentmon doctor");
    Ok(())
}

pub fn uninstall(dry_run: bool) -> Result<()> {
    let steps = build_uninstall_plan();
    println!(
        "{}{}卸载 agentmond 服务{}",
        Ansi::BOLD,
        if dry_run { "[dry-run] " } else { "" },
        Ansi::RESET
    );
    for step in &steps {
        execute(step, dry_run);
    }
    if !dry_run {
        println!(
            "\n服务已卸载；数据库保留在 {}（如需删除请手动 rm）。",
            paths::db_path(true).display()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn log_path() -> PathBuf {
    PathBuf::from("/var/log/agentmon.log")
}

#[cfg(not(target_os = "macos"))]
pub fn log_path() -> PathBuf {
    PathBuf::from("/var/log/agentmon/agentmon.log")
}

#[cfg(target_os = "macos")]
fn build_plan(opts: &InstallOptions, binary: &Path, user: &str) -> Result<Vec<Step>> {
    let mut steps = vec![
        Step::Note("复制二进制到稳定位置（避免 target/ 被清理后服务失效）".into()),
        Step::EnsureDir {
            path: managed_binary_dir(),
            mode: 0o755,
            group: None,
        },
        Step::CopyFile {
            from: binary.to_path_buf(),
            to: managed_binary_path(),
            mode: 0o755,
        },
        Step::Note(format!(
            "创建 {GROUP_NAME} 组并把 {user} 加进去（GUI 只读访问系统数据库）"
        )),
        Step::Run {
            program: "dscl".into(),
            args: [".", "-create", "/Groups/agentmon", "PrimaryGroupID", "350"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore_failure: true,
        },
        Step::Run {
            program: "dseditgroup".into(),
            args: ["-o", "edit", "-a", user, "-t", "user", GROUP_NAME]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore_failure: true,
        },
        Step::EnsureDir {
            path: paths::data_dir(true),
            mode: 0o750,
            group: Some(GROUP_NAME.into()),
        },
        Step::EnsureDir {
            path: paths::launchd_plist_path()
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/Library/LaunchDaemons")),
            mode: 0o755,
            group: None,
        },
        Step::WriteFile {
            path: paths::launchd_plist_path(),
            mode: 0o644,
            contents: launchd_plist(),
        },
    ];
    if !opts.no_start {
        steps.push(Step::Note("加载 LaunchDaemon".into()));
        steps.push(Step::Run {
            program: "launchctl".into(),
            args: [
                "bootout",
                "system",
                &paths::launchd_plist_path().display().to_string(),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ignore_failure: true,
        });
        steps.push(Step::Run {
            program: "launchctl".into(),
            args: [
                "bootstrap",
                "system",
                &paths::launchd_plist_path().display().to_string(),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ignore_failure: false,
        });
    }
    Ok(steps)
}

#[cfg(target_os = "linux")]
fn build_plan(opts: &InstallOptions, binary: &Path, user: &str) -> Result<Vec<Step>> {
    let mut steps = vec![
        Step::EnsureDir {
            path: managed_binary_dir(),
            mode: 0o755,
            group: None,
        },
        Step::CopyFile {
            from: binary.to_path_buf(),
            to: managed_binary_path(),
            mode: 0o755,
        },
        Step::EnsureDir {
            path: log_path()
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("/var/log")),
            mode: 0o755,
            group: None,
        },
        Step::Run {
            program: "groupadd".into(),
            args: ["-f", GROUP_NAME].iter().map(|s| s.to_string()).collect(),
            ignore_failure: true,
        },
        Step::Run {
            program: "usermod".into(),
            args: ["-aG", GROUP_NAME, user]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore_failure: true,
        },
        Step::EnsureDir {
            path: paths::data_dir(true),
            mode: 0o750,
            group: Some(GROUP_NAME.into()),
        },
        Step::EnsureDir {
            path: paths::systemd_unit_path()
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/etc/systemd/system")),
            mode: 0o755,
            group: None,
        },
        Step::WriteFile {
            path: paths::systemd_unit_path(),
            mode: 0o644,
            contents: systemd_unit(),
        },
        Step::Run {
            program: "systemctl".into(),
            args: ["daemon-reload"].iter().map(|s| s.to_string()).collect(),
            ignore_failure: false,
        },
    ];
    if !opts.no_start {
        steps.push(Step::Run {
            program: "systemctl".into(),
            args: ["enable", "--now", SERVICE_NAME]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore_failure: false,
        });
    }
    Ok(steps)
}

#[cfg(windows)]
fn build_plan(_opts: &InstallOptions, _binary: &Path, _user: &str) -> Result<Vec<Step>> {
    anyhow::bail!(
        "Windows 服务安装尚未实现。请先手动在管理员 PowerShell 中运行:\n  sc.exe create agentmond binPath= \"C:\\Path\\to\\agentmond.exe\" start= auto\n  sc.exe start agentmond"
    )
}

#[cfg(target_os = "macos")]
fn build_uninstall_plan() -> Vec<Step> {
    vec![
        Step::Run {
            program: "launchctl".into(),
            args: [
                "bootout",
                "system",
                &paths::launchd_plist_path().display().to_string(),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            ignore_failure: true,
        },
        Step::Remove(paths::launchd_plist_path()),
    ]
}

#[cfg(target_os = "linux")]
fn build_uninstall_plan() -> Vec<Step> {
    vec![
        Step::Run {
            program: "systemctl".into(),
            args: ["disable", "--now", SERVICE_NAME]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ignore_failure: true,
        },
        Step::Remove(paths::systemd_unit_path()),
        Step::Run {
            program: "systemctl".into(),
            args: ["daemon-reload"].iter().map(|s| s.to_string()).collect(),
            ignore_failure: true,
        },
    ]
}

#[cfg(windows)]
fn build_uninstall_plan() -> Vec<Step> {
    vec![Step::Run {
        program: "sc.exe".into(),
        args: ["delete", SERVICE_NAME]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ignore_failure: true,
    }]
}

fn launchd_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>--log-level</string>
        <string>info</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        SERVICE_LABEL = SERVICE_LABEL,
        binary = managed_binary_path().display(),
        log = log_path().display(),
    )
}

#[allow(dead_code)]
fn systemd_unit() -> String {
    format!(
        r#"[Unit]
Description=agentmon — audit what AI coding agents read and upload
Documentation=https://github.com/luckylee6666/agentmon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} --log-level info
Restart=always
RestartSec=3
# File read auditing on Linux needs CAP_SYS_ADMIN for fanotify.
AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=false

[Install]
WantedBy=multi-user.target
"#,
        binary = managed_binary_path().display(),
    )
}

/// Structured view for the desktop app: no printing, no privileges needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub binary_present: bool,
    pub unit_path: String,
    pub managed_binary: String,
    pub detail: String,
    pub root: bool,
}

pub fn service_status() -> ServiceStatus {
    let root = crate::util::is_root();
    let managed = managed_binary_path();
    let binary_present = managed.exists();

    #[cfg(target_os = "macos")]
    {
        let unit = paths::launchd_plist_path();
        let installed = unit.exists();
        let (running, detail) = match Command::new("launchctl")
            .args(["print", &format!("system/{SERVICE_LABEL}")])
            .output()
        {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                let state = text
                    .lines()
                    .find(|line| line.contains("state ="))
                    .map(|line| line.trim().trim_start_matches("state = ").to_string())
                    .unwrap_or_else(|| "已加载".into());
                (state == "running", state)
            }
            _ => (false, "未加载".into()),
        };
        return ServiceStatus {
            installed,
            running,
            binary_present,
            unit_path: unit.display().to_string(),
            managed_binary: managed.display().to_string(),
            detail,
            root,
        };
    }

    #[cfg(target_os = "linux")]
    {
        let unit = paths::systemd_unit_path();
        let installed = unit.exists();
        let output = Command::new("systemctl")
            .args(["is-active", SERVICE_NAME])
            .output();
        let detail = output
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        return ServiceStatus {
            installed,
            running: detail == "active",
            binary_present,
            unit_path: unit.display().to_string(),
            managed_binary: managed.display().to_string(),
            detail,
            root,
        };
    }

    #[cfg(windows)]
    {
        let _ = SERVICE_NAME;
        ServiceStatus {
            installed: false,
            running: false,
            binary_present,
            unit_path: "sc.exe create agentmond".into(),
            managed_binary: managed.display().to_string(),
            detail: "Windows 服务尚未实现，请手动注册".into(),
            root,
        }
    }
}

pub fn status() -> Result<()> {
    let _ = service_status();
    let root = crate::util::is_root();
    println!(
        "{}{}agentmond 服务状态{}",
        Ansi::BOLD,
        Ansi::CYAN,
        Ansi::RESET
    );

    #[cfg(target_os = "macos")]
    {
        let plist = paths::launchd_plist_path();
        println!(
            "  安装文件 : {} {}",
            plist.display(),
            if plist.exists() {
                "(存在)"
            } else {
                "(未安装)"
            }
        );
        let managed = managed_binary_path();
        println!(
            "  守护程序 : {} {}",
            managed.display(),
            if managed.exists() {
                "(存在)"
            } else {
                "(缺失)"
            }
        );
        let output = Command::new("launchctl")
            .args(["print", &format!("system/{SERVICE_LABEL}")])
            .output();
        match output {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                let state = text
                    .lines()
                    .find(|line| line.contains("state ="))
                    .map(|line| line.trim().to_string())
                    .unwrap_or_else(|| "已加载".into());
                println!("  运行状态 : {}{}{}", Ansi::GREEN, state, Ansi::RESET);
            }
            _ => println!("  运行状态 : {}未加载{}", Ansi::YELLOW, Ansi::RESET),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let unit = paths::systemd_unit_path();
        println!(
            "  安装文件 : {} {}",
            unit.display(),
            if unit.exists() {
                "(存在)"
            } else {
                "(未安装)"
            }
        );
        match Command::new("systemctl")
            .args(["is-active", SERVICE_NAME])
            .output()
        {
            Ok(output) => println!(
                "  运行状态 : {}",
                String::from_utf8_lossy(&output.stdout).trim()
            ),
            Err(_) => println!("  运行状态 : 未知"),
        }
    }

    let db = paths::db_path(true);
    println!(
        "  系统数据库: {} {}",
        db.display(),
        if db.exists() {
            format!(
                "({})",
                crate::util::format_bytes(std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0))
            )
        } else {
            "(尚未创建)".into()
        }
    );
    println!(
        "  当前身份 : {}（{}）",
        if root { "root" } else { "普通用户" },
        if root {
            "可读写系统数据库"
        } else {
            "需加入 agentmon 组才能读取"
        }
    );
    match group_id(GROUP_NAME) {
        Some(gid) => println!("  {GROUP_NAME} 组 : gid {gid}"),
        None => println!(
            "  {GROUP_NAME} 组 : {}(不存在，GUI 将无法读取系统数据库){}",
            Ansi::YELLOW,
            Ansi::RESET
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "agentmon-install-{}-{}",
            name,
            crate::util::now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The desktop app hands this script to `do shell script`, so quoting bugs
    /// would fail silently at the worst moment. Run it for real.
    #[test]
    fn rendered_script_survives_spaces_and_quotes() {
        let dir = tmp("script");
        let target = dir.join("with space").join("it's here.txt");
        let steps = vec![
            Step::Note("test".into()),
            Step::EnsureDir {
                path: target.parent().unwrap().to_path_buf(),
                mode: 0o750,
                group: None,
            },
            Step::WriteFile {
                path: target.clone(),
                mode: 0o640,
                contents: "line one\nsecond 'quoted' line\n".into(),
            },
            Step::Run {
                program: "/bin/echo".into(),
                args: vec!["hello world".into(), "it's fine".into()],
                ignore_failure: false,
            },
        ];

        let script = render_script(&steps);
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("sh");
        assert!(
            output.status.success(),
            "script failed: {}\n--- script ---\n{script}",
            String::from_utf8_lossy(&output.stderr)
        );

        let written = std::fs::read_to_string(&target).expect("file written");
        assert_eq!(written, "line one\nsecond 'quoted' line\n");
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello world"));

        // the heredoc must not leak into following commands
        let script_after_echo = render_script(&[
            Step::WriteFile {
                path: dir.join("a.txt"),
                mode: 0o600,
                contents: "x".into(),
            },
            Step::Run {
                program: "/bin/echo".into(),
                args: vec!["after".into()],
                ignore_failure: false,
            },
        ]);
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script_after_echo)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .ends_with("after")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rewrites a plan into a sandbox and really runs it. `--dry-run` cannot
    /// catch a plan that copies into a directory nothing ever creates; running
    /// the rendered script can, because `set -e` stops at exactly that step.
    #[test]
    fn the_plan_actually_installs_into_a_sandbox() {
        let root = tmp("sandbox");
        let opts = InstallOptions {
            dry_run: true,
            user: Some("tester".into()),
            binary: Some(PathBuf::from("/bin/echo")),
            no_start: true,
        };
        let rebase = |path: &Path| root.join(path.strip_prefix("/").unwrap_or(path));

        let plan: Vec<Step> = plan_install(&opts)
            .expect("plan")
            .into_iter()
            .filter_map(|step| match step {
                // 需要 root 的步骤在沙箱里没有意义
                Step::Note(_) | Step::Run { .. } | Step::Remove(_) => None,
                Step::EnsureDir { path, mode, .. } => Some(Step::EnsureDir {
                    path: rebase(&path),
                    mode,
                    group: None,
                }),
                Step::CopyFile { from, to, mode } => Some(Step::CopyFile {
                    from,
                    to: rebase(&to),
                    mode,
                }),
                Step::WriteFile { path, mode, contents } => Some(Step::WriteFile {
                    path: rebase(&path),
                    mode,
                    contents,
                }),
            })
            .collect();

        let script = render_script(&plan);
        let output = Command::new("/bin/sh").arg("-c").arg(&script).output().expect("sh");
        assert!(
            output.status.success(),
            "计划无法执行：{}\n--- script ---\n{script}",
            String::from_utf8_lossy(&output.stderr)
        );

        let installed = rebase(&managed_binary_path());
        assert!(installed.is_file(), "守护程序没有被复制到 {}", installed.display());
        assert!(rebase(&dir_of(&paths::launchd_plist_path())).is_dir());

        let _ = std::fs::remove_dir_all(&root);
    }

    fn dir_of(path: &Path) -> PathBuf {
        path.parent().map(Path::to_path_buf).unwrap_or_default()
    }

    #[test]
    fn script_fails_fast_and_describe_lists_the_steps() {
        let steps = vec![
            Step::Note("复制二进制".into()),
            Step::CopyFile {
                from: PathBuf::from("/nonexistent/source"),
                to: PathBuf::from("/tmp/agentmon-never"),
                mode: 0o755,
            },
        ];
        let script = render_script(&steps);
        assert!(script.starts_with("set -e"), "must fail fast: {script}");
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(!out.status.success(), "copying a missing file must fail");

        let described = describe(&steps);
        assert_eq!(described.len(), 2);
        assert!(described[0].contains("复制二进制"));
        assert!(described[1].contains("/tmp/agentmon-never"));
    }

    #[test]
    fn macos_plan_uses_the_stable_binary_location() {
        let opts = InstallOptions {
            dry_run: true,
            user: Some("tester".into()),
            binary: Some(PathBuf::from("/tmp/agentmond")),
            no_start: false,
        };
        let plan = plan_install(&opts).expect("plan");
        let described = describe(&plan).join("\n");
        assert!(
            described.contains("/usr/local/lib/agentmon/agentmond"),
            "{described}"
        );
        assert!(described.contains("agentmon 组") || described.contains("agentmon"));
    }
}
