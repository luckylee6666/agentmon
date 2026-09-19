use std::path::{Path, PathBuf};

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}B")
    } else if value >= 100.0 {
        format!("{value:.0}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

pub fn format_bytes_rate(bytes: u64, window_ms: i64) -> String {
    if window_ms <= 0 {
        return format!("{}/s", format_bytes(bytes));
    }
    let per_sec = bytes as f64 * 1000.0 / window_ms as f64;
    format!("{}/s", format_bytes(per_sec as u64))
}

pub fn format_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts)
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| ts.to_string())
}

pub fn format_ago(ts: i64) -> String {
    let delta = now_ms() - ts;
    if delta < 0 {
        return "just now".into();
    }
    let secs = delta / 1000;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

/// Shannon entropy in bits per byte, sampled from `data`.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts.iter() {
        if *count == 0 {
            continue;
        }
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy as f32
}

pub fn expand_tilde(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    } else if input == "~"
        && let Some(home) = home_dir()
    {
        return home;
    }
    PathBuf::from(input)
}

pub fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Addresses that can never identify a real destination: RFC 2544 benchmarking
/// space (used as fake-ip by Clash/Surge style proxies), documentation ranges,
/// CGNAT and other special-use blocks.
pub fn is_reserved_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let octets = v4.octets();
            let [a, b, c, d] = octets;
            if a == 198 && (b == 18 || b == 19) {
                return true;
            }
            if a == 100 && (64..=127).contains(&b) {
                return true;
            }
            if a == 192 && b == 0 && c == 2 {
                return true;
            }
            if a == 198 && b == 51 && c == 100 {
                return true;
            }
            if a == 203 && b == 0 && c == 113 {
                return true;
            }
            if a >= 240 {
                return true;
            }
            if a == 0 && b == 0 && c == 0 && d == 0 {
                return true;
            }
            false
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let segments = v6.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
        Err(_) => false,
    }
}

pub fn is_loopback_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_unspecified(),
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        Err(_) => false,
    }
}

pub fn is_private_ip(ip: &str) -> bool {
    let parsed: Result<std::net::IpAddr, _> = ip.parse();
    match parsed {
        Ok(std::net::IpAddr::V4(v4)) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
        Err(_) => false,
    }
}

pub fn truncate_middle(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(3) / 2;
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars[..keep].iter().collect();
    let tail: String = chars[chars.len() - keep..].iter().collect();
    format!("{head}...{tail}")
}

/// Directory of the containing git repository, if any.
pub fn git_repo_root(path: &Path) -> Option<PathBuf> {
    let mut current = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()?.to_path_buf()
    };
    loop {
        if current.join(".git").exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

pub struct Ansi;

impl Ansi {
    pub const RESET: &'static str = "\x1b[0m";
    pub const BOLD: &'static str = "\x1b[1m";
    pub const DIM: &'static str = "\x1b[2m";
    pub const RED: &'static str = "\x1b[31m";
    pub const GREEN: &'static str = "\x1b[32m";
    pub const YELLOW: &'static str = "\x1b[33m";
    pub const BLUE: &'static str = "\x1b[34m";
    pub const MAGENTA: &'static str = "\x1b[35m";
    pub const CYAN: &'static str = "\x1b[36m";

    pub fn severity(sev: crate::model::Severity) -> &'static str {
        use crate::model::Severity::*;
        match sev {
            Info => Self::DIM,
            Low => Self::BLUE,
            Medium => Self::YELLOW,
            High => Self::MAGENTA,
            Critical => Self::RED,
        }
    }

    pub fn enabled() -> bool {
        std::env::var_os("NO_COLOR").is_none() && is_tty()
    }
}

#[cfg(unix)]
fn is_tty() -> bool {
    // SAFETY: isatty is safe to call with any fd.
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

#[cfg(not(unix))]
fn is_tty() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros_is_zero() {
        assert_eq!(shannon_entropy(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn entropy_of_random_like_data_is_high() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(shannon_entropy(&data) > 7.9);
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(2048), "2.0KB");
        assert_eq!(format_bytes(20 * 1024 * 1024), "20.0MB");
    }

    #[test]
    fn detects_private_ips() {
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("192.168.1.10"));
        assert!(!is_private_ip("1.1.1.1"));
    }
}
