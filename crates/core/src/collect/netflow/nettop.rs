use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NettopRow {
    pub name: String,
    pub pid: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// nettop prints cumulative per-process counters (`-J state,bytes_in,bytes_out`),
/// one row per process per sample, e.g. `Lark Helper.1422   6466   4540`.
/// Process names may contain spaces, so the numbers are taken from the right.
pub fn parse_line(line: &str) -> Option<NettopRow> {
    let cleaned = strip_ansi(line);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 3 {
        return None;
    }
    let bytes_out: u64 = tokens[tokens.len() - 1].parse().ok()?;
    let bytes_in: u64 = tokens[tokens.len() - 2].parse().ok()?;
    let prefix = tokens[..tokens.len() - 2].join(" ");
    let (name, pid) = split_name_pid(&prefix)?;
    if name.is_empty() {
        return None;
    }
    Some(NettopRow {
        name,
        pid,
        bytes_in,
        bytes_out,
    })
}

fn split_name_pid(prefix: &str) -> Option<(String, u32)> {
    let bytes = prefix.as_bytes();
    for i in (0..bytes.len()).rev() {
        if bytes[i] != b'.' {
            continue;
        }
        let rest = &prefix[i + 1..];
        let digits = rest.split_whitespace().next().unwrap_or("");
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            let pid: u32 = digits.parse().ok()?;
            return Some((prefix[..i].trim().to_string(), pid));
        }
    }
    None
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            continue;
        }
        if c == '\r' {
            continue;
        }
        out.push(c);
    }
    out
}

#[derive(Default)]
pub struct DeltaTracker {
    last: HashMap<u32, (u64, u64)>,
}

impl DeltaTracker {
    /// Returns the delta since the previous sample, or `None` for the first
    /// observation of a pid. Counters reset when a process restarts.
    pub fn apply(&mut self, row: &NettopRow) -> Option<(u64, u64)> {
        let current = (row.bytes_in, row.bytes_out);
        match self.last.insert(row.pid, current) {
            Some((previous_in, previous_out)) => {
                let delta_in = if row.bytes_in >= previous_in {
                    row.bytes_in - previous_in
                } else {
                    row.bytes_in
                };
                let delta_out = if row.bytes_out >= previous_out {
                    row.bytes_out - previous_out
                } else {
                    row.bytes_out
                };
                Some((delta_in, delta_out))
            }
            None => None,
        }
    }

    pub fn forget_missing(&mut self, seen: &[u32]) {
        if self.last.len() <= seen.len() {
            return;
        }
        let keep: std::collections::HashSet<u32> = seen.iter().copied().collect();
        self.last.retain(|pid, _| keep.contains(pid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../../../../fixtures/nettop-sample.txt");

    #[test]
    fn parses_real_nettop_output() {
        let mut parsed = Vec::new();
        for line in SAMPLE.lines() {
            if let Some(row) = parse_line(line) {
                parsed.push(row);
            }
        }
        assert!(
            parsed.len() > 25,
            "expected many rows, got {}",
            parsed.len()
        );
        let syslogd = parsed.iter().find(|r| r.pid == 617).unwrap();
        assert_eq!(syslogd.name, "syslogd");
        assert_eq!(syslogd.bytes_out, 759);
    }

    #[test]
    fn handles_process_names_with_spaces() {
        let row =
            parse_line("Lark Helper.1422                                    6466            4540")
                .unwrap();
        assert_eq!(row.pid, 1422);
        assert_eq!(row.name, "Lark Helper");
        assert_eq!(row.bytes_in, 6466);
        assert_eq!(row.bytes_out, 4540);

        let row =
            parse_line("Xiaomi MiMo Hel.2176                     1291141       166949013").unwrap();
        assert_eq!(row.pid, 2176);
        assert_eq!(row.name, "Xiaomi MiMo Hel");
        assert_eq!(row.bytes_out, 166949013);
    }

    #[test]
    fn handles_optional_state_column() {
        let row = parse_line("Safari.900  Established  1024  2048").unwrap();
        assert_eq!(row.pid, 900);
        assert_eq!(row.name, "Safari");
        assert_eq!(row.bytes_in, 1024);
        assert_eq!(row.bytes_out, 2048);
    }

    #[test]
    fn skips_headers_and_noise() {
        assert!(parse_line("state        bytes_in       bytes_out").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("^D").is_none());
        assert!(parse_line("   \u{1b}[0m   ").is_none());
    }

    #[test]
    fn deltas_are_monotonic_and_reset_safe() {
        let mut tracker = DeltaTracker::default();
        let first = parse_line("codex.2536   5977   30839").unwrap();
        assert!(tracker.apply(&first).is_none());

        let second = parse_line("codex.2536   6000   31000").unwrap();
        assert_eq!(tracker.apply(&second), Some((23, 161)));

        let reset = parse_line("codex.2536   10   20").unwrap();
        assert_eq!(tracker.apply(&reset), Some((10, 20)));
    }
}
