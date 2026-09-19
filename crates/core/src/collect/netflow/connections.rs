use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawConnection {
    pub pid: u32,
    pub command: String,
    pub local_port: Option<u16>,
    pub remote_ip: String,
    pub remote_port: Option<u16>,
}

fn lsof_path() -> Option<&'static PathBuf> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        for candidate in ["/usr/sbin/lsof", "/usr/bin/lsof", "/bin/lsof", "/sbin/lsof"] {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
        None
    })
    .as_ref()
}

/// `lsof -n -P -iTCP -sTCP:ESTABLISHED -F pcn` gives a machine readable stream:
/// `p<pid>` starts a process block, `n<local>-><remote>` is one connection.
pub fn sample_connections() -> Result<Vec<RawConnection>> {
    let Some(lsof) = lsof_path() else {
        anyhow::bail!("lsof not found");
    };
    let output = Command::new(lsof)
        .args(["-n", "-P", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"])
        .output()?;
    if !output.status.success() && output.stdout.is_empty() {
        anyhow::bail!("lsof exited with {}", output.status);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_lsof(&text))
}

pub fn parse_lsof(text: &str) -> Vec<RawConnection> {
    let mut out = Vec::new();
    let mut current_pid: Option<u32> = None;
    let mut current_command = String::new();
    for line in text.lines() {
        let mut chars = line.chars();
        let Some(tag) = chars.next() else { continue };
        let value = chars.as_str();
        match tag {
            'p' => {
                current_pid = value.parse().ok();
                current_command.clear();
            }
            'c' => current_command = value.to_string(),
            'n' => {
                let Some(pid) = current_pid else { continue };
                if let Some((ip, port)) = parse_remote(value) {
                    out.push(RawConnection {
                        pid,
                        command: current_command.clone(),
                        local_port: parse_local_port(value),
                        remote_ip: ip,
                        remote_port: port,
                    });
                }
            }
            _ => {}
        }
    }
    out
}

/// Local port of `<local>-><remote>`, used to map proxy connections back to a pid.
pub fn parse_local_port(name: &str) -> Option<u16> {
    let address = name.split_whitespace().next().unwrap_or(name);
    let (local, _) = address.split_once("->")?;
    parse_address_port(local.trim())
}

fn parse_address_port(value: &str) -> Option<u16> {
    if let Some(rest) = value.strip_prefix('[') {
        let (_, port) = rest.split_once("]:")?;
        return port.parse().ok();
    }
    let (_, port) = value.rsplit_once(':')?;
    port.parse().ok()
}

pub fn parse_remote(name: &str) -> Option<(String, Option<u16>)> {
    let address = name.split_whitespace().next().unwrap_or(name);
    let (_, remote) = address.split_once("->")?;
    let remote = remote.trim();
    if remote.starts_with('*') {
        return None;
    }
    if let Some(rest) = remote.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        return Some((ip.to_string(), port.parse().ok()));
    }
    let (ip, port) = remote.rsplit_once(':')?;
    if ip.is_empty() {
        return None;
    }
    Some((ip.to_string(), port.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../../../fixtures/lsof-sample.txt");

    #[test]
    fn parses_lsof_field_output() {
        let conns = parse_lsof(SAMPLE);
        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].pid, 2536);
        assert_eq!(conns[0].command, "codex");
        assert_eq!(conns[0].remote_ip, "160.79.104.10");
        assert_eq!(conns[0].remote_port, Some(443));
        assert_eq!(conns[2].remote_ip, "2404:6800:400a:80c::200e");
    }

    #[test]
    fn ignores_local_listeners() {
        assert!(parse_remote("127.0.0.1:8080").is_none());
        assert!(parse_remote("*:*").is_none());
        assert_eq!(
            parse_remote("192.168.1.5:51000->1.1.1.1:443"),
            Some(("1.1.1.1".into(), Some(443)))
        );
    }

    #[test]
    fn extracts_local_port_for_attribution() {
        assert_eq!(
            parse_local_port("192.168.1.5:51000->1.1.1.1:443"),
            Some(51000)
        );
        assert_eq!(
            parse_local_port("[fe80::1]:51002->[2404::1]:443"),
            Some(51002)
        );
        assert_eq!(parse_local_port("*:*"), None);
    }
}
