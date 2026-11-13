//! HTTPS served by the server itself, for setups without a TLS reverse proxy.
//!
//! The mode is a setting read at startup: `Off` (plain HTTP, also the right choice behind
//! Caddy or nginx), a self-signed certificate generated and kept in `data/admin/tls/`, or a
//! certificate and key from PEM files. When TLS cannot start, the server falls back to plain
//! HTTP and reports why, so a wrong certificate never locks the admin out.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    auth::write_private_file,
    settings::{Settings, TlsMode, public_url_host},
};

const SELF_SIGNED_CERT: &str = "self-signed-cert.pem";
const SELF_SIGNED_KEY: &str = "self-signed-key.pem";
const SELF_SIGNED_NAMES: &str = "self-signed-names.json";

/// What the admin panel shows about HTTPS as it is running now.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TlsStatus {
    pub mode: TlsMode,
    /// HTTPS is being served on `https_port`.
    pub active: bool,
    pub https_port: Option<u16>,
    /// SHA-256 of the certificate, to compare with what a browser shows.
    pub fingerprint: Option<String>,
    /// Names the self-signed certificate is valid for.
    pub names: Vec<String>,
    /// Why TLS is not running although it is configured.
    pub error: Option<String>,
}

/// A ready TLS configuration and the facts shown about it.
pub struct TlsSetup {
    pub config: ServerConfig,
    pub fingerprint: String,
    pub names: Vec<String>,
}

/// Builds the TLS configuration for the settings, or `None` when TLS is off.
pub async fn prepare(settings: &Settings, dir: &Path) -> Result<Option<TlsSetup>> {
    let (certs, key, names) = match settings.tls_mode {
        TlsMode::Off => return Ok(None),
        TlsMode::SelfSigned => self_signed(settings, dir).await?,
        TlsMode::Files => {
            let cert_path = PathBuf::from(settings.tls_cert_path.trim());
            let key_path = PathBuf::from(settings.tls_key_path.trim());
            (
                load_certs(&cert_path).await?,
                load_key(&key_path).await?,
                Vec::new(),
            )
        }
    };
    let fingerprint = fingerprint(&certs[0]);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("cannot set the TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the certificate and the private key do not match or are not supported")?;
    Ok(Some(TlsSetup {
        config,
        fingerprint,
        names,
    }))
}

/// Names the self-signed certificate covers: the public URL's host, `localhost`, the bind
/// address when it is a specific one, and 127.0.0.1.
pub fn certificate_names(settings: &Settings) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(host) = public_url_host(&settings.public_url) {
        candidates.push(
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_string(),
        );
    }
    candidates.push("localhost".to_string());
    if !settings.bind_addr.is_unspecified() {
        candidates.push(settings.bind_addr.to_string());
    }
    candidates.push(IpAddr::from([127, 0, 0, 1]).to_string());
    let mut names = Vec::new();
    for name in candidates {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

type CertAndKey = (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<String>,
);

/// Loads the stored self-signed certificate, or makes a new one when there is none or the
/// names it should cover have changed.
async fn self_signed(settings: &Settings, dir: &Path) -> Result<CertAndKey> {
    let names = certificate_names(settings);
    let cert_path = dir.join(SELF_SIGNED_CERT);
    let key_path = dir.join(SELF_SIGNED_KEY);
    let names_path = dir.join(SELF_SIGNED_NAMES);

    let stored_names: Option<Vec<String>> = tokio::fs::read(&names_path)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    if stored_names.as_ref() == Some(&names)
        && let (Ok(certs), Ok(key)) = (load_certs(&cert_path).await, load_key(&key_path).await)
    {
        return Ok((certs, key, names));
    }

    let generated = rcgen::generate_simple_self_signed(names.clone())
        .context("cannot generate a self-signed certificate")?;
    write_private_file(&cert_path, generated.cert.pem().as_bytes()).await?;
    write_private_file(&key_path, generated.signing_key.serialize_pem().as_bytes()).await?;
    write_private_file(&names_path, &serde_json::to_vec(&names)?).await?;
    println!(
        "Generated a self-signed certificate for {} in {}",
        names.join(", "),
        dir.display()
    );
    Ok((
        load_certs(&cert_path).await?,
        load_key(&key_path).await?,
        names,
    ))
}

async fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("cannot read the certificate {}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid certificate {}: {e}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificate in {}", path.display());
    }
    Ok(certs)
}

async fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("cannot read the private key {}", path.display()))?;
    PrivateKeyDer::from_pem_slice(&bytes)
        .map_err(|e| anyhow!("invalid private key {}: {e}", path.display()))
}

fn fingerprint(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Where a plain-HTTP request is sent when HTTPS is on: same path, HTTPS port. The host
/// comes from `public_url` when it is an HTTPS address, otherwise from the request's own
/// Host header, so a visitor is only ever sent to the host they already asked for.
pub fn https_redirect_target(
    settings: &Settings,
    https_port: u16,
    request_host: &str,
    path_and_query: &str,
) -> String {
    let host = match public_url_host(&settings.public_url) {
        Some(host) if settings.public_url_is_https() => host,
        _ => strip_port(request_host),
    };
    let port = if https_port == 443 { String::new() } else { format!(":{https_port}") };
    format!("https://{host}{port}{path_and_query}")
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .split_once(']')
            .map_or(host, |(ip, _)| &host[..ip.len() + 1]);
    }
    host.rsplit_once(':').map_or(host, |(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(public_url: &str, mode: TlsMode) -> Settings {
        Settings {
            public_url: public_url.into(),
            tls_mode: mode,
            ..Settings::default()
        }
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("bhs-tls-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn self_signed_certificate_is_kept_until_its_names_change() {
        let dir = temp_dir();
        let first = prepare(
            &settings("https://share.example.com", TlsMode::SelfSigned),
            &dir,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            first.names,
            vec!["share.example.com", "localhost", "127.0.0.1"]
        );
        let again = prepare(
            &settings("https://share.example.com/", TlsMode::SelfSigned),
            &dir,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(first.fingerprint, again.fingerprint);

        let renamed = prepare(
            &settings("https://other.example.com", TlsMode::SelfSigned),
            &dir,
        )
        .await
        .unwrap()
        .unwrap();
        assert_ne!(first.fingerprint, renamed.fingerprint);

        // The same files also work as "your own certificate".
        let own = Settings {
            tls_cert_path: dir.join(SELF_SIGNED_CERT).to_string_lossy().into_owned(),
            tls_key_path: dir.join(SELF_SIGNED_KEY).to_string_lossy().into_owned(),
            ..settings("", TlsMode::Files)
        };
        let loaded = prepare(&own, &dir).await.unwrap().unwrap();
        assert_eq!(loaded.fingerprint, renamed.fingerprint);
    }

    #[tokio::test]
    async fn missing_or_mismatched_files_are_errors() {
        let dir = temp_dir();
        let missing = Settings {
            tls_cert_path: "/nonexistent/cert.pem".into(),
            tls_key_path: "/nonexistent/key.pem".into(),
            ..settings("", TlsMode::Files)
        };
        assert!(prepare(&missing, &dir).await.is_err());
        assert!(
            prepare(&settings("", TlsMode::Off), &dir)
                .await
                .unwrap()
                .is_none()
        );

        // A certificate with the key of another one.
        let a = rcgen::generate_simple_self_signed(vec!["a".to_string()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["b".to_string()]).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.pem"), a.cert.pem()).unwrap();
        std::fs::write(dir.join("b.key"), b.signing_key.serialize_pem()).unwrap();
        let mismatched = Settings {
            tls_cert_path: dir.join("a.pem").to_string_lossy().into_owned(),
            tls_key_path: dir.join("b.key").to_string_lossy().into_owned(),
            ..settings("", TlsMode::Files)
        };
        assert!(prepare(&mismatched, &dir).await.is_err());
    }

    #[test]
    fn plain_http_is_redirected_to_the_https_port() {
        let public = settings("https://share.example.com", TlsMode::SelfSigned);
        assert_eq!(
            https_redirect_target(&public, 8443, "evil.example:8080", "/f/x?a=1"),
            "https://share.example.com:8443/f/x?a=1"
        );
        let plain = settings("", TlsMode::SelfSigned);
        assert_eq!(
            https_redirect_target(&plain, 443, "192.168.1.5:8080", "/"),
            "https://192.168.1.5/"
        );
        assert_eq!(
            https_redirect_target(&plain, 8443, "[::1]:8080", "/admin"),
            "https://[::1]:8443/admin"
        );
    }
}
