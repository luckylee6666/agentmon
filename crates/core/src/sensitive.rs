use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Credentials and secrets.
    Secret,
    /// Git metadata: `.git` internals carry full history and remote credentials.
    GitMetadata,
}

impl Sensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Secret => "secret",
            Sensitivity::GitMetadata => "git-metadata",
        }
    }
}

const SECRET_FILENAMES: &[&str] = &[
    ".env",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pypirc",
    ".dockercfg",
    ".git-credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "credentials",
    "credentials.json",
    "secrets.yaml",
    "secrets.yml",
];

const SECRET_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks", "keystore", "ppk"];

const SECRET_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".config/gcloud",
    ".config/gh",
];

pub struct SensitiveMatcher {
    extra: Option<GlobSet>,
}

impl SensitiveMatcher {
    pub fn new(extra_globs: &[String]) -> Self {
        let extra = if extra_globs.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            let mut built = false;
            for pattern in extra_globs {
                if let Ok(glob) = Glob::new(pattern) {
                    builder.add(glob);
                    built = true;
                }
            }
            if built { builder.build().ok() } else { None }
        };
        SensitiveMatcher { extra }
    }

    pub fn classify(&self, path: &Path) -> Option<Sensitivity> {
        for component in path.components() {
            let part = component.as_os_str().to_string_lossy();
            if part == ".git" {
                return Some(Sensitivity::GitMetadata);
            }
        }

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let lower = name.to_ascii_lowercase();
            if SECRET_FILENAMES.iter().any(|n| lower == *n) {
                return Some(Sensitivity::Secret);
            }
            if lower.starts_with(".env.") {
                return Some(Sensitivity::Secret);
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext = ext.to_ascii_lowercase();
                if SECRET_EXTENSIONS.iter().any(|e| ext == *e) {
                    return Some(Sensitivity::Secret);
                }
            }
        }

        for dir in SECRET_DIRS {
            let needle = format!("/{dir}/");
            if path.to_string_lossy().contains(&needle) {
                return Some(Sensitivity::Secret);
            }
        }

        if let Some(extra) = &self.extra
            && extra.is_match(path)
        {
            return Some(Sensitivity::Secret);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn matcher() -> SensitiveMatcher {
        SensitiveMatcher::new(&[])
    }

    #[test]
    fn flags_git_metadata() {
        let m = matcher();
        assert_eq!(
            m.classify(&PathBuf::from("/Users/me/proj/.git/config")),
            Some(Sensitivity::GitMetadata)
        );
    }

    #[test]
    fn flags_secrets() {
        let m = matcher();
        assert_eq!(
            m.classify(&PathBuf::from("/Users/me/proj/.env")),
            Some(Sensitivity::Secret)
        );
        assert_eq!(
            m.classify(&PathBuf::from("/Users/me/.ssh/id_ed25519")),
            Some(Sensitivity::Secret)
        );
        assert_eq!(
            m.classify(&PathBuf::from("/Users/me/cert/server.pem")),
            Some(Sensitivity::Secret)
        );
        assert_eq!(
            m.classify(&PathBuf::from("/Users/me/proj/.env.local")),
            Some(Sensitivity::Secret)
        );
    }

    #[test]
    fn ignores_regular_sources() {
        let m = matcher();
        assert_eq!(
            m.classify(&PathBuf::from("/Users/me/proj/src/main.rs")),
            None
        );
        assert_eq!(m.classify(&PathBuf::from("/Users/me/proj/README.md")), None);
    }
}
