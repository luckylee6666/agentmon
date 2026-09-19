use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    if cfg!(windows) {
        directories::BaseDirs::new()
            .map(|b| b.config_dir().join("agentmon"))
            .unwrap_or_else(|| PathBuf::from("agentmon"))
    } else {
        crate::util::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/agentmon")
    }
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.yaml")
}

pub fn user_profiles_dir() -> PathBuf {
    config_dir().join("profiles.d")
}

pub fn ca_dir() -> PathBuf {
    config_dir().join("ca")
}

/// Data directory. `system` selects the root-daemon location.
pub fn data_dir(system: bool) -> PathBuf {
    if system {
        if cfg!(target_os = "macos") {
            PathBuf::from("/Library/Application Support/agentmon")
        } else if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\agentmon")
        } else {
            PathBuf::from("/var/lib/agentmon")
        }
    } else if cfg!(target_os = "macos") {
        crate::util::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Application Support/agentmon")
    } else if cfg!(windows) {
        directories::BaseDirs::new()
            .map(|b| b.data_dir().join("agentmon"))
            .unwrap_or_else(|| PathBuf::from("agentmon"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                crate::util::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".local/share")
            })
            .join("agentmon")
    }
}

pub fn db_path(system: bool) -> PathBuf {
    data_dir(system).join("agentmon.db")
}

/// Prefer the system database when the privileged daemon has created one.
pub fn active_db_path() -> PathBuf {
    let system = db_path(true);
    if system.exists() {
        system
    } else {
        db_path(false)
    }
}

pub fn systemd_unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/agentmond.service")
}

pub fn launchd_plist_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/ai.agentmon.agentmond.plist")
}

pub fn socket_path(system: bool) -> PathBuf {
    if system {
        #[cfg(unix)]
        {
            PathBuf::from("/var/run/agentmond.sock")
        }
        #[cfg(not(unix))]
        {
            data_dir(true).join("agentmond.sock")
        }
    } else {
        data_dir(false).join("agentmond.sock")
    }
}

pub fn ensure_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}
