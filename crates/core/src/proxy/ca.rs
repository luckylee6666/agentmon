use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CERT_FILE: &str = "agentmon-ca.pem";
const KEY_FILE: &str = "agentmon-ca.key";

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    dir: PathBuf,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl Ca {
    pub fn load_or_create(dir: &Path) -> Result<Ca> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating CA dir {}", dir.display()))?;
        restrict_permissions(dir)?;

        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
            (
                std::fs::read_to_string(&cert_path)?,
                std::fs::read_to_string(&key_path)?,
            )
        } else {
            let (cert_pem, key_pem) = generate_ca()?;
            std::fs::write(&cert_path, &cert_pem)?;
            std::fs::write(&key_path, &key_pem)?;
            restrict_permissions(&cert_path)?;
            restrict_permissions(&key_path)?;
            tracing::info!("generated local CA at {}", cert_path.display());
            (cert_pem, key_pem)
        };

        let key = KeyPair::from_pem(&key_pem).context("parsing stored CA key")?;
        let issuer =
            Issuer::from_ca_cert_pem(&cert_pem, key).context("parsing stored CA certificate")?;

        Ok(Ca {
            issuer,
            cert_pem,
            dir: dir.to_path_buf(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CERT_FILE)
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join(KEY_FILE)
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// A leaf certificate for `host`, generated on first use and then cached.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(cached) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(host).cloned())
        {
            return Ok(cached);
        }

        let mut params = CertificateParams::new(vec![host.to_string()])
            .with_context(|| format!("building certificate params for {host}"))?;
        params
            .distinguished_name
            .push(DnType::CommonName, host.to_string());
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let key_pair = KeyPair::generate().context("generating leaf key")?;
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .context("signing leaf certificate")?;

        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(key_der))
                .context("loading leaf signing key")?;
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert.der().to_vec())],
            signing_key,
        ));

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(host.to_string(), certified.clone());
        }
        Ok(certified)
    }

    pub fn server_config(self: &Arc<Self>) -> Arc<ServerConfig> {
        let resolver = Arc::new(CaResolver { ca: self.clone() });
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        // Only HTTP/1.1 is advertised: it keeps the MITM simple and the
        // clients downgrade cleanly.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}

struct CaResolver {
    ca: Arc<Ca>,
}

impl std::fmt::Debug for CaResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CaResolver")
    }
}

impl rustls::server::ResolvesServerCert for CaResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?.to_string();
        match self.ca.leaf_for(&host) {
            Ok(key) => Some(key),
            Err(err) => {
                tracing::warn!("cannot issue certificate for {host}: {err:#}");
                None
            }
        }
    }
}

fn generate_ca() -> Result<(String, String)> {
    let mut params = CertificateParams::new(Vec::new()).context("CA params")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "agentmon Local Audit CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "agentmon");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().context("generating CA key")?;
    let cert = params.self_signed(&key).context("self-signing CA")?;
    Ok((cert.pem(), key.serialize_pem()))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reuses_ca() {
        let dir = std::env::temp_dir().join(format!("agentmon-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let ca = Ca::load_or_create(&dir).unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.cert_path().exists());

        let reloaded = Ca::load_or_create(&dir).unwrap();
        assert_eq!(ca.cert_pem(), reloaded.cert_pem());

        let leaf = ca.leaf_for("api.example.com").unwrap();
        assert!(!leaf.cert.is_empty());
        let again = ca.leaf_for("api.example.com").unwrap();
        assert!(Arc::ptr_eq(&leaf, &again), "leaf certificates are cached");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
