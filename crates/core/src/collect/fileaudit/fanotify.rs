//! fanotify protocol bits: kernel constants plus a decoder for the event
//! stream. Kept platform independent on purpose so the parsing logic is
//! unit-testable everywhere, not only on Linux.

use std::path::{Path, PathBuf};

pub const FANOTIFY_METADATA_VERSION: u8 = 3;
/// `struct fanotify_event_metadata` is 24 bytes: u32 event_len, u8 vers,
/// u8 reserved, u16 metadata_len, u64 mask, i32 fd, i32 pid.
pub const FAN_EVENT_METADATA_LEN: usize = 24;

pub const FAN_ACCESS: u64 = 0x0000_0001;
pub const FAN_OPEN: u64 = 0x0000_0020;
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;

pub const FAN_CLOEXEC: u32 = 0x0000_0001;
pub const FAN_NONBLOCK: u32 = 0x0000_0002;
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub const FAN_UNLIMITED_MARKS: u32 = 0x0000_0020;
pub const FAN_REPORT_TID: u32 = 0x0000_0100;

pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;

pub const FAN_NOFD: i32 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanEvent {
    pub mask: u64,
    /// File descriptor for the object, or `FAN_NOFD` in FID mode.
    pub fd: i32,
    pub pid: u32,
}

impl FanEvent {
    pub fn is_open(&self) -> bool {
        self.mask & (FAN_OPEN | FAN_OPEN_EXEC) != 0
    }

    pub fn has_path(&self) -> bool {
        self.fd != FAN_NOFD
    }
}

/// Decodes a buffer filled by `read(2)` on a fanotify descriptor. Kernel
/// metadata is host-endian (little endian on the targets we support).
pub fn decode_events(buffer: &[u8]) -> Vec<FanEvent> {
    let mut events = Vec::new();
    let mut offset = 0usize;
    while offset + FAN_EVENT_METADATA_LEN <= buffer.len() {
        let event_len = u32::from_le_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;
        let vers = buffer[offset + 4];
        let mask = u64::from_le_bytes([
            buffer[offset + 8],
            buffer[offset + 9],
            buffer[offset + 10],
            buffer[offset + 11],
            buffer[offset + 12],
            buffer[offset + 13],
            buffer[offset + 14],
            buffer[offset + 15],
        ]);
        let fd = i32::from_le_bytes([
            buffer[offset + 16],
            buffer[offset + 17],
            buffer[offset + 18],
            buffer[offset + 19],
        ]);
        let pid = i32::from_le_bytes([
            buffer[offset + 20],
            buffer[offset + 21],
            buffer[offset + 22],
            buffer[offset + 23],
        ]);

        // A zero or undersized length would make the loop spin forever.
        if event_len < FAN_EVENT_METADATA_LEN {
            break;
        }
        if vers == FANOTIFY_METADATA_VERSION {
            events.push(FanEvent {
                mask,
                fd,
                pid: pid.max(0) as u32,
            });
        }
        offset += event_len;
    }
    events
}

/// `/proc/self/mountinfo` escapes space, tab, newline and backslash.
pub fn unescape_mountinfo(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let digits: String = chars.by_ref().take(3).collect();
        match u8::from_str_radix(&digits, 8) {
            Ok(byte) => out.push(byte as char),
            Err(_) => out.push_str(&format!("\\{digits}")),
        }
    }
    out
}

/// Longest mount point that contains `path`, i.e. the mount to mark.
pub fn mount_point_of(path: &Path, mountinfo: &str) -> Option<PathBuf> {
    let mut best: Option<PathBuf> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 5 {
            continue;
        }
        let mount_point = PathBuf::from(unescape_mountinfo(fields[4]));
        if !path.starts_with(&mount_point) {
            continue;
        }
        if best
            .as_ref()
            .map(|current| mount_point.as_os_str().len() > current.as_os_str().len())
            .unwrap_or(true)
        {
            best = Some(mount_point);
        }
    }
    best
}

pub fn read_mountinfo() -> std::io::Result<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_bytes(mask: u64, fd: i32, pid: i32, event_len: u32, vers: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&event_len.to_le_bytes());
        out.push(vers);
        out.push(0);
        out.extend_from_slice(&(FAN_EVENT_METADATA_LEN as u16).to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(&fd.to_le_bytes());
        out.extend_from_slice(&pid.to_le_bytes());
        out
    }

    #[test]
    fn decodes_a_single_event() {
        let buffer = event_bytes(FAN_OPEN, 42, 1234, FAN_EVENT_METADATA_LEN as u32, 3);
        let events = decode_events(&buffer);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 1234);
        assert_eq!(events[0].fd, 42);
        assert!(events[0].is_open());
        assert!(events[0].has_path());
    }

    #[test]
    fn decodes_multiple_events_in_one_read() {
        let mut buffer = Vec::new();
        buffer.extend(event_bytes(
            FAN_OPEN,
            7,
            100,
            FAN_EVENT_METADATA_LEN as u32,
            3,
        ));
        buffer.extend(event_bytes(
            FAN_ACCESS,
            8,
            200,
            FAN_EVENT_METADATA_LEN as u32,
            3,
        ));
        buffer.extend(event_bytes(
            FAN_OPEN,
            FAN_NOFD as i32,
            300,
            FAN_EVENT_METADATA_LEN as u32,
            3,
        ));

        let events = decode_events(&buffer);
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].pid, 200);
        assert!(!events[1].is_open(), "FAN_ACCESS is not an open");
        assert!(!events[2].has_path(), "FAN_NOFD means no descriptor");
    }

    #[test]
    fn skips_unknown_versions_but_keeps_walking() {
        let mut buffer = Vec::new();
        buffer.extend(event_bytes(
            FAN_OPEN,
            1,
            1,
            FAN_EVENT_METADATA_LEN as u32,
            99,
        ));
        buffer.extend(event_bytes(
            FAN_OPEN,
            2,
            2,
            FAN_EVENT_METADATA_LEN as u32,
            3,
        ));
        let events = decode_events(&buffer);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 2);
    }

    #[test]
    fn tolerates_truncated_and_broken_buffers() {
        assert!(decode_events(&[]).is_empty());
        assert!(decode_events(&[0u8; 10]).is_empty());

        // event_len of 0 must not loop forever.
        let broken = event_bytes(FAN_OPEN, 1, 1, 0, 3);
        assert!(decode_events(&broken).is_empty());

        // A partial trailing record is ignored.
        let mut buffer = event_bytes(FAN_OPEN, 1, 1, FAN_EVENT_METADATA_LEN as u32, 3);
        buffer.extend_from_slice(&[0u8; 5]);
        assert_eq!(decode_events(&buffer).len(), 1);
    }

    const MOUNTINFO: &str = "\
25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
26 30 0:24 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
33 30 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 33 8:2 / /home rw,relatime shared:2 - ext4 /dev/sda2 rw
55 40 0:30 / /home/dev/with\\040space rw,relatime shared:9 - tmpfs tmpfs rw
";

    #[test]
    fn finds_the_longest_containing_mount() {
        assert_eq!(
            mount_point_of(Path::new("/home/dev/project/file.rs"), MOUNTINFO),
            Some(PathBuf::from("/home"))
        );
        assert_eq!(
            mount_point_of(Path::new("/etc/hosts"), MOUNTINFO),
            Some(PathBuf::from("/"))
        );
        assert_eq!(
            mount_point_of(Path::new("/proc/self/status"), MOUNTINFO),
            Some(PathBuf::from("/proc"))
        );
    }

    #[test]
    fn unescapes_mountinfo_paths() {
        assert_eq!(
            unescape_mountinfo("/home/dev/with\\040space"),
            "/home/dev/with space"
        );
        assert_eq!(
            mount_point_of(Path::new("/home/dev/with space/x"), MOUNTINFO),
            Some(PathBuf::from("/home/dev/with space"))
        );
    }
}
