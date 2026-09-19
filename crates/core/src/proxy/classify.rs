use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    Empty,
    Text,
    SourceCode,
    Secret,
    Archive,
    Binary,
}

impl PayloadClass {
    pub fn as_str(self) -> &'static str {
        match self {
            PayloadClass::Empty => "empty",
            PayloadClass::Text => "text",
            PayloadClass::SourceCode => "source_code",
            PayloadClass::Secret => "secret",
            PayloadClass::Archive => "archive",
            PayloadClass::Binary => "binary",
        }
    }

    pub fn is_sensitive(self) -> bool {
        matches!(self, PayloadClass::SourceCode | PayloadClass::Secret)
    }
}

#[derive(Debug, Clone)]
pub struct Classification {
    pub class: PayloadClass,
    /// Human readable reason. Never contains the secret value itself.
    pub sample: Option<String>,
}

/// Classifies a request body. Nested containers (gzip / base64 wrapped payloads)
/// are unwrapped first, because that is exactly how a "packed repository"
/// upload looks on the wire.
pub fn classify(body: &[u8], content_type: Option<&str>) -> Classification {
    classify_inner(body, content_type, 0)
}

fn classify_inner(body: &[u8], content_type: Option<&str>, depth: usize) -> Classification {
    if body.is_empty() {
        return Classification {
            class: PayloadClass::Empty,
            sample: None,
        };
    }
    if depth < 3 {
        if let Some(inner) = maybe_decompress(body) {
            let mut nested = classify_inner(&inner, content_type, depth + 1);
            nested.sample = Some(match nested.sample {
                Some(reason) => format!("gzip 解压后：{reason}"),
                None => "gzip 解压后内容".into(),
            });
            return nested;
        }
        if let Some(inner) = maybe_base64(body) {
            let mut nested = classify_inner(&inner, content_type, depth + 1);
            nested.sample = Some(match nested.sample {
                Some(reason) => format!("base64 解码后：{reason}"),
                None => "base64 编码内容".into(),
            });
            return nested;
        }
    }

    if is_archive(body) {
        return Classification {
            class: PayloadClass::Archive,
            sample: Some(format!("压缩包/归档格式（{} 字节）", body.len())),
        };
    }

    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(_) => {
            let printable = body
                .iter()
                .take(4096)
                .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                .count();
            let sampled = body.len().min(4096);
            if sampled > 0 && printable * 100 / sampled > 90 {
                return Classification {
                    class: PayloadClass::Text,
                    sample: None,
                };
            }
            return Classification {
                class: PayloadClass::Binary,
                sample: Some(format!("二进制数据（{} 字节）", body.len())),
            };
        }
    };

    if let Some(kind) = detect_secret(text) {
        return Classification {
            class: PayloadClass::Secret,
            sample: Some(format!("命中密钥特征：{kind}")),
        };
    }

    if looks_like_source_code(text) {
        return Classification {
            class: PayloadClass::SourceCode,
            sample: Some(describe_source(text)),
        };
    }

    let _ = content_type;
    Classification {
        class: PayloadClass::Text,
        sample: None,
    }
}

fn maybe_decompress(body: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::{GzDecoder, ZlibDecoder};
    use std::io::Read;

    let looks_gzip = body.len() > 2 && body[0] == 0x1f && body[1] == 0x8b;
    let looks_zlib =
        body.len() > 2 && body[0] == 0x78 && matches!(body[1], 0x01 | 0x5e | 0x9c | 0xda);
    if !looks_gzip && !looks_zlib {
        return None;
    }
    let mut out = Vec::new();
    let mut reader: Box<dyn Read> = if looks_gzip {
        Box::new(GzDecoder::new(body))
    } else {
        Box::new(ZlibDecoder::new(body))
    };
    let mut limited = (&mut reader).take(4 * 1024 * 1024);
    limited.read_to_end(&mut out).ok()?;
    if out.is_empty() { None } else { Some(out) }
}

fn maybe_base64(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 256 || body.len() > 4 * 1024 * 1024 {
        return None;
    }
    let sample = &body[..body.len().min(4096)];
    let allowed = sample
        .iter()
        .filter(|b| {
            b.is_ascii_alphanumeric()
                || **b == b'+'
                || **b == b'/'
                || **b == b'='
                || **b == b'\n'
                || **b == b'\r'
        })
        .count();
    if allowed * 100 / sample.len() < 98 {
        return None;
    }
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64_decode(&compact)
}

fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        Some(match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in input {
        if byte == b'=' {
            break;
        }
        let Some(value) = value(byte) else {
            return None;
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn is_archive(body: &[u8]) -> bool {
    if body.len() >= 4 && &body[..4] == b"PK\x03\x04" {
        return true;
    }
    if body.len() >= 262 && &body[257..262] == b"ustar" {
        return true;
    }
    if body.len() >= 6 && &body[..6] == b"7z\xbc\xaf\x27\x1c" {
        return true;
    }
    if body.len() >= 4 && &body[..4] == b"Rar!" {
        return true;
    }
    false
}

fn detect_secret(text: &str) -> Option<&'static str> {
    static PATTERNS: OnceLock<Vec<(&'static str, regex::Regex)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        vec![
            (
                "私钥文件内容",
                regex::Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
            ),
            (
                "AWS Access Key",
                regex::Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            ),
            (
                "AWS Secret Key 赋值",
                regex::Regex::new(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}")
                    .unwrap(),
            ),
            (
                "OpenAI/Anthropic 风格 API Key",
                regex::Regex::new(r"\b(sk|sk-ant|sk-proj)-[A-Za-z0-9_\-]{20,}").unwrap(),
            ),
            (
                "GitHub Token",
                regex::Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(),
            ),
            (
                "Slack Token",
                regex::Regex::new(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}").unwrap(),
            ),
            (
                "JWT",
                regex::Regex::new(
                    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
                )
                .unwrap(),
            ),
            (
                "密钥/口令赋值",
                regex::Regex::new(
                    r#"(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*["'][^"']{12,}["']"#,
                )
                .unwrap(),
            ),
        ]
    });
    let head = &text[..text.len().min(512 * 1024)];
    patterns
        .iter()
        .find(|(_, re)| re.is_match(head))
        .map(|(name, _)| *name)
}

pub fn looks_like_source_code(text: &str) -> bool {
    let sample = &text[..text.len().min(64 * 1024)];
    if sample.len() < 64 {
        return false;
    }
    let lines: Vec<&str> = sample.lines().take(600).collect();
    if lines.len() < 5 {
        return false;
    }

    let mut keyword_lines = 0usize;
    let mut structural_lines = 0usize;
    let mut path_like = 0usize;
    let mut punctuation = 0usize;

    for line in &lines {
        let trimmed = line.trim_start();
        if is_code_keyword_line(trimmed) {
            keyword_lines += 1;
        }
        if trimmed.ends_with('{')
            || trimmed.ends_with('}')
            || trimmed.ends_with(';')
            || trimmed.ends_with("=> {")
        {
            structural_lines += 1;
        }
        if trimmed.contains("/src/")
            || trimmed.contains(".rs\"")
            || trimmed.contains(".ts\"")
            || trimmed.contains(".py\"")
        {
            path_like += 1;
        }
        punctuation +=
            line.matches('{').count() + line.matches('}').count() + line.matches(';').count();
    }

    // Hard gate first: prose and JSON payloads have no code keyword lines at
    // all, so everything below only has to separate code from code-ish text.
    let keyword_ratio = keyword_lines * 100 / lines.len();
    let count_high = keyword_lines >= 8;
    if !count_high && keyword_ratio < 30 {
        return false;
    }

    // Scored rather than ratio-thresholded: real source files are mostly
    // declarations and blank lines, so a strict keyword ratio misses them while
    // a loose one starts flagging prose.
    let mut score = 1;
    if count_high {
        score += 1;
    }
    if keyword_ratio >= 30 {
        score += 1;
    }
    if structural_lines * 100 / lines.len() >= 25 {
        score += 1;
    }
    if punctuation * 100 / lines.len() >= 120 {
        score += 1;
    }
    if sample.contains("::") || sample.contains("->") || sample.contains("};") {
        score += 1;
    }
    if path_like >= 2 {
        score += 1;
    }
    score >= 3
}

fn is_code_keyword_line(trimmed: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "fn ",
        "pub fn ",
        "pub(crate) fn ",
        "async fn ",
        "def ",
        "class ",
        "function ",
        "import ",
        "from ",
        "use ",
        "package ",
        "const ",
        "let ",
        "export ",
        "func ",
        "impl ",
        "pub struct ",
        "struct ",
        "pub enum ",
        "enum ",
        "trait ",
        "interface ",
        "#include",
        "#[",
        "///",
        "@Override",
    ];
    PREFIXES.iter().any(|prefix| trimmed.starts_with(prefix))
}

fn describe_source(text: &str) -> String {
    let lines = text.lines().count();
    let extensions = [
        ".rs", ".ts", ".tsx", ".js", ".py", ".go", ".java", ".c", ".cpp", ".h", ".rb", ".php",
        ".swift", ".kt", ".sh", ".sql", ".yml", ".yaml", ".toml",
    ];
    let matched: Vec<&str> = extensions
        .iter()
        .copied()
        .filter(|ext| text.contains(ext))
        .take(5)
        .collect();
    if matched.is_empty() {
        format!("疑似源码片段（{lines} 行）")
    } else {
        format!(
            "疑似源码（{lines} 行，含 {} 等文件引用）",
            matched.join(" ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_plain_json_as_text() {
        let result = classify(
            br#"{"model":"gpt","messages":[{"role":"user","content":"hi"}]}"#,
            Some("application/json"),
        );
        assert_eq!(result.class, PayloadClass::Text);
    }

    #[test]
    fn detects_source_code() {
        let code = r#"
use std::collections::HashMap;
pub fn main() {
    let mut map = HashMap::new();
    map.insert("a", 1);
}
fn helper() -> u8 { 1 }
const VERSION: &str = "1";
export const x = 1;
"#;
        let result = classify(code.as_bytes(), None);
        assert_eq!(result.class, PayloadClass::SourceCode);
        assert!(result.sample.unwrap().contains("源码"));
    }

    /// Regression fixture: this very file must be recognised as source code.
    #[test]
    fn detects_its_own_source_file() {
        let source = include_str!("../model.rs");
        assert!(looks_like_source_code(source));
        assert_eq!(
            classify(source.as_bytes(), None).class,
            PayloadClass::SourceCode
        );
    }

    #[test]
    fn does_not_flag_prose_or_json_chat_payloads() {
        let prose = "Dear team,\n\nPlease review the attached document before the meeting.\n\
                     We should discuss the roadmap and the hiring plan.\nThank you.\nRegards,\nAlice\n";
        assert!(!looks_like_source_code(prose));

        let chat = r#"{"model":"claude-sonnet-4","max_tokens":1024,"messages":[{"role":"user","content":"帮我解释一下这个项目的架构和设计思路，以及后续的演进方向。"}]}"#;
        assert!(!looks_like_source_code(chat));

        let telemetry =
            r#"{"event":"session_start","session_id":"abc-123","os":"macos","version":"1.2.3"}"#;
        assert!(!looks_like_source_code(telemetry));
    }

    #[test]
    fn detects_private_keys_and_tokens() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert_eq!(classify(key.as_bytes(), None).class, PayloadClass::Secret);

        let aws = "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE";
        assert_eq!(classify(aws.as_bytes(), None).class, PayloadClass::Secret);

        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(classify(jwt.as_bytes(), None).class, PayloadClass::Secret);
    }

    #[test]
    fn unwraps_gzip_payloads() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;

        let code =
            b"pub fn secret() {}\nfn other() {}\nimport x\nuse y\nconst Z: u8 = 1;\nclass A {}";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(code).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = classify(&compressed, None);
        assert_eq!(result.class, PayloadClass::SourceCode);
        assert!(result.sample.unwrap().contains("gzip"));
    }

    #[test]
    fn detects_archives() {
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(classify(&tar, None).class, PayloadClass::Archive);

        let zip = b"PK\x03\x04rest";
        assert_eq!(classify(zip, None).class, PayloadClass::Archive);
    }

    #[test]
    fn unwraps_base64_source() {
        // Long enough to pass the 256 byte gate that keeps short tokens from
        // being mistaken for base64 payloads.
        let code = "fn alpha() {}\nfn beta() {}\nfn gamma() {}\nuse std::io;\nconst A: u8 = 1;\nfn delta() {}\n"
            .repeat(6);
        let encoded = base64_encode(code.as_bytes());
        assert!(encoded.len() > 256);
        let result = classify(encoded.as_bytes(), None);
        assert_eq!(result.class, PayloadClass::SourceCode);
        assert!(result.sample.unwrap().contains("base64"));
    }

    fn base64_encode(input: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn binary_and_empty() {
        assert_eq!(classify(&[], None).class, PayloadClass::Empty);
        let binary: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        assert_eq!(classify(&binary, None).class, PayloadClass::Binary);
    }
}
