//! Runtime settings, stored in `data/admin/settings.json` and edited from the admin panel.
//!
//! Most values apply to the next request. The listening addresses, the TLS setup and
//! `admin_session_max_age_minutes` are read once at startup, so a change takes effect only
//! after a restart; `running()` keeps the values the server started with.

use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::{fs, sync::Mutex};

use crate::auth::write_private_file;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

pub const MAX_ASSET_DURATION_LIMIT_MINUTES: u32 = 24 * 60;
pub const MAX_ASSETS_LIMIT: usize = 100_000;
pub const MAX_ASSET_SIZE_LIMIT_BYTES: usize = 100 * MIB as usize;
pub const MAX_UPLOADS_PER_IP_LIMIT: usize = 10_000;
pub const MIN_LOG_FILE_BYTES: u64 = MIB;
pub const MAX_ROTATED_LOGS_LIMIT: usize = 1000;
pub const MAX_RECENT_ACTIVITY_LIMIT: usize = 1000;
pub const MAX_TRUSTED_PROXIES: usize = 64;
pub const MAX_FILE_SIZE_LIMIT_BYTES: u64 = 100 * GIB;
pub const MAX_FILE_DURATION_LIMIT_MINUTES: u32 = 365 * 24 * 60;
pub const MIN_SESSION_MAX_AGE_MINUTES: u32 = 5;
pub const MAX_SESSION_MAX_AGE_MINUTES: u32 = 7 * 24 * 60;
pub const MAX_LOGIN_FAILURES_LIMIT: u32 = 100;
pub const MAX_LOCKOUT_MINUTES: u32 = 24 * 60;
pub const MAX_REQUEST_UPLOADS_PER_HOUR_LIMIT: u32 = 10_000;
pub const MAX_PUBLIC_URL_CHARS: usize = 300;
pub const MAX_TLS_PATH_CHARS: usize = 1000;

/// How the server itself serves HTTPS. Behind a reverse proxy that does TLS (Caddy,
/// nginx...) it stays `Off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    #[default]
    Off,
    /// A certificate generated and kept in `data/admin/tls/`. Browsers warn about it.
    SelfSigned,
    /// A certificate and key from PEM files given by path.
    Files,
}

/// Missing fields take their default, so a file written by an older version still loads.
/// Unknown fields are rejected: in a hand-edited file they are almost always typos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub min_asset_duration_minutes: u32,
    pub max_asset_duration_minutes: u32,
    pub max_assets: usize,
    pub max_asset_size_bytes: usize,
    pub max_total_storage_bytes: usize,
    pub max_uploads_per_ip: usize,
    /// Largest file the admin can share.
    pub max_file_size_bytes: u64,
    /// Disk space for all shared files together.
    pub max_files_total_bytes: u64,
    pub max_file_duration_minutes: u32,
    pub max_log_file_bytes: u64,
    pub max_rotated_logs: usize,
    pub max_recent_activity: usize,
    /// Proxies allowed to report the client address via `X-Forwarded-For`.
    pub trusted_proxies: Vec<IpAddr>,
    /// Read at startup: the session cookie's Max-Age is fixed when the server starts.
    pub admin_session_max_age_minutes: u32,
    /// Read at startup.
    pub bind_addr: IpAddr,
    /// Read at startup.
    pub bind_port: u16,
    /// The address people use to reach the service, like `https://share.example.com`.
    /// Used for the links the admin copies and for the self-signed certificate. Empty:
    /// links use the address in the browser.
    pub public_url: String,
    /// Read at startup.
    pub tls_mode: TlsMode,
    /// Read at startup. PEM certificate chain for `TlsMode::Files`.
    pub tls_cert_path: String,
    /// Read at startup. PEM private key for `TlsMode::Files`.
    pub tls_key_path: String,
    /// Read at startup. HTTPS port when TLS is on; `bind_port` then redirects to it.
    pub https_port: u16,
    /// Wrong passwords from one address before it is locked out.
    pub max_login_failures: u32,
    pub login_lockout_minutes: u32,
    /// Files one address may send through upload requests per hour.
    pub max_request_uploads_per_ip_per_hour: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            min_asset_duration_minutes: 1,
            max_asset_duration_minutes: 60,
            max_assets: 1000,
            max_asset_size_bytes: 3 * MIB as usize,
            max_total_storage_bytes: 512 * MIB as usize,
            max_uploads_per_ip: 10,
            max_file_size_bytes: GIB,
            max_files_total_bytes: 10 * GIB,
            max_file_duration_minutes: 7 * 24 * 60,
            max_log_file_bytes: 50 * MIB,
            max_rotated_logs: 10,
            max_recent_activity: 20,
            trusted_proxies: Vec::new(),
            admin_session_max_age_minutes: 8 * 60,
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_port: 8080,
            public_url: String::new(),
            tls_mode: TlsMode::Off,
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            https_port: 8443,
            max_login_failures: 5,
            login_lockout_minutes: 15,
            max_request_uploads_per_ip_per_hour: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    pub field: String,
    pub message: String,
}

impl Settings {
    /// Every rule that is broken, so the admin panel can mark all wrong fields at once.
    pub fn validate(&self) -> Vec<FieldError> {
        let mut errors = Vec::new();
        let mut check = |ok: bool, field: &'static str, message: String| {
            if !ok {
                errors.push(FieldError {
                    field: field.to_string(),
                    message,
                });
            }
        };

        check(
            self.min_asset_duration_minutes >= 1,
            "min_asset_duration_minutes",
            "must be at least 1".into(),
        );
        check(
            self.max_asset_duration_minutes <= MAX_ASSET_DURATION_LIMIT_MINUTES,
            "max_asset_duration_minutes",
            format!("must be at most {MAX_ASSET_DURATION_LIMIT_MINUTES}"),
        );
        check(
            self.max_asset_duration_minutes >= self.min_asset_duration_minutes,
            "max_asset_duration_minutes",
            "must not be lower than the minimum duration".into(),
        );
        check(
            (1..=MAX_ASSETS_LIMIT).contains(&self.max_assets),
            "max_assets",
            format!("must be between 1 and {MAX_ASSETS_LIMIT}"),
        );
        check(
            (1..=MAX_ASSET_SIZE_LIMIT_BYTES).contains(&self.max_asset_size_bytes),
            "max_asset_size_bytes",
            format!("must be between 1 and {MAX_ASSET_SIZE_LIMIT_BYTES} bytes"),
        );
        check(
            self.max_total_storage_bytes >= self.max_asset_size_bytes,
            "max_total_storage_bytes",
            "must not be lower than the maximum asset size".into(),
        );
        check(
            (1..=MAX_UPLOADS_PER_IP_LIMIT).contains(&self.max_uploads_per_ip),
            "max_uploads_per_ip",
            format!("must be between 1 and {MAX_UPLOADS_PER_IP_LIMIT}"),
        );
        check(
            (1..=MAX_FILE_SIZE_LIMIT_BYTES).contains(&self.max_file_size_bytes),
            "max_file_size_bytes",
            format!("must be between 1 and {MAX_FILE_SIZE_LIMIT_BYTES} bytes"),
        );
        check(
            self.max_files_total_bytes >= self.max_file_size_bytes,
            "max_files_total_bytes",
            "must not be lower than the maximum file size".into(),
        );
        check(
            (1..=MAX_FILE_DURATION_LIMIT_MINUTES).contains(&self.max_file_duration_minutes),
            "max_file_duration_minutes",
            format!("must be between 1 and {MAX_FILE_DURATION_LIMIT_MINUTES}"),
        );
        check(
            self.max_log_file_bytes >= MIN_LOG_FILE_BYTES,
            "max_log_file_bytes",
            format!("must be at least {MIN_LOG_FILE_BYTES} bytes"),
        );
        check(
            self.max_rotated_logs <= MAX_ROTATED_LOGS_LIMIT,
            "max_rotated_logs",
            format!("must be at most {MAX_ROTATED_LOGS_LIMIT}"),
        );
        check(
            (1..=MAX_RECENT_ACTIVITY_LIMIT).contains(&self.max_recent_activity),
            "max_recent_activity",
            format!("must be between 1 and {MAX_RECENT_ACTIVITY_LIMIT}"),
        );
        check(
            self.trusted_proxies.len() <= MAX_TRUSTED_PROXIES,
            "trusted_proxies",
            format!("must list at most {MAX_TRUSTED_PROXIES} addresses"),
        );
        check(
            (MIN_SESSION_MAX_AGE_MINUTES..=MAX_SESSION_MAX_AGE_MINUTES)
                .contains(&self.admin_session_max_age_minutes),
            "admin_session_max_age_minutes",
            format!(
                "must be between {MIN_SESSION_MAX_AGE_MINUTES} and {MAX_SESSION_MAX_AGE_MINUTES}"
            ),
        );
        check(
            self.bind_port >= 1,
            "bind_port",
            "must be between 1 and 65535".into(),
        );
        check(
            self.public_url.is_empty() || public_url_host(&self.public_url).is_some(),
            "public_url",
            "must be empty or like https://share.example.com (scheme and host, optional port, no path)"
                .into(),
        );
        let tls_on = self.tls_mode != TlsMode::Off;
        check(
            self.https_port >= 1,
            "https_port",
            "must be between 1 and 65535".into(),
        );
        check(
            !tls_on || self.https_port != self.bind_port,
            "https_port",
            "must differ from the HTTP port".into(),
        );
        for (field, path) in [
            ("tls_cert_path", &self.tls_cert_path),
            ("tls_key_path", &self.tls_key_path),
        ] {
            check(
                path.chars().count() <= MAX_TLS_PATH_CHARS && !path.chars().any(char::is_control),
                field,
                format!("must be at most {MAX_TLS_PATH_CHARS} characters"),
            );
            check(
                self.tls_mode != TlsMode::Files || !path.trim().is_empty(),
                field,
                "is required for your own certificate".into(),
            );
        }
        check(
            (1..=MAX_LOGIN_FAILURES_LIMIT).contains(&self.max_login_failures),
            "max_login_failures",
            format!("must be between 1 and {MAX_LOGIN_FAILURES_LIMIT}"),
        );
        check(
            (1..=MAX_LOCKOUT_MINUTES).contains(&self.login_lockout_minutes),
            "login_lockout_minutes",
            format!("must be between 1 and {MAX_LOCKOUT_MINUTES}"),
        );
        check(
            (1..=MAX_REQUEST_UPLOADS_PER_HOUR_LIMIT)
                .contains(&self.max_request_uploads_per_ip_per_hour),
            "max_request_uploads_per_ip_per_hour",
            format!("must be between 1 and {MAX_REQUEST_UPLOADS_PER_HOUR_LIMIT}"),
        );
        errors
    }

    /// Whether `public_url` says people reach the service over HTTPS.
    pub fn public_url_is_https(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    pub fn admin_session_max_age_secs(&self) -> i64 {
        i64::from(self.admin_session_max_age_minutes) * 60
    }
}

#[derive(Debug)]
pub enum UpdateError {
    Invalid(Vec<FieldError>),
    Internal(anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    path: PathBuf,
    current: Arc<RwLock<Settings>>,
    running: Arc<Settings>,
    /// Serializes updates so the file and the in-memory copy never disagree.
    write: Arc<Mutex<()>>,
}

impl SettingsStore {
    /// Loads the settings file, creating it with the defaults on first start. A file that
    /// cannot be parsed or holds invalid values stops startup instead of being replaced.
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let settings = match fs::read(&path).await {
            Ok(bytes) => {
                let settings: Settings = serde_json::from_slice(&bytes)
                    .with_context(|| format!("invalid settings file {}", path.display()))?;
                let errors = settings.validate();
                if !errors.is_empty() {
                    let details: Vec<String> = errors
                        .iter()
                        .map(|e| format!("{} {}", e.field, e.message))
                        .collect();
                    bail!(
                        "invalid settings in {}: {}",
                        path.display(),
                        details.join("; ")
                    );
                }
                settings
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let settings = Settings::default();
                persist(&path, &settings).await?;
                println!("Settings file created with defaults at {}", path.display());
                settings
            }
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        Ok(Self::with_settings(path, settings))
    }

    fn with_settings(path: PathBuf, settings: Settings) -> Self {
        Self {
            path,
            running: Arc::new(settings.clone()),
            current: Arc::new(RwLock::new(settings)),
            write: Arc::new(Mutex::new(())),
        }
    }

    /// Store that starts from `settings` without reading a file; `update` writes to `path`.
    #[cfg(test)]
    pub fn with_values(path: impl Into<PathBuf>, settings: Settings) -> Self {
        Self::with_settings(path.into(), settings)
    }

    /// The settings in effect now.
    pub fn get(&self) -> Settings {
        // Poisoning can only come from a panic in `clone` or `replace`, which leaves an
        // already validated value in place, so the data is still safe to serve.
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The settings the server started with, used for the restart-only values.
    pub fn running(&self) -> &Settings {
        &self.running
    }

    /// Validates, saves and applies new settings. Returns the previous ones.
    pub async fn update(&self, new: Settings) -> Result<Settings, UpdateError> {
        let errors = new.validate();
        if !errors.is_empty() {
            return Err(UpdateError::Invalid(errors));
        }
        let _guard = self.write.lock().await;
        persist(&self.path, &new)
            .await
            .map_err(UpdateError::Internal)?;
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(std::mem::replace(&mut *current, new))
    }
}

/// The host of a valid public URL: `http` or `https`, a host name or IP, an optional port,
/// and at most a trailing slash. `None` for anything else.
pub fn public_url_host(url: &str) -> Option<&str> {
    if url.chars().count() > MAX_PUBLIC_URL_CHARS {
        return None;
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ']) {
        return None;
    }
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        // [IPv6]:port
        let (ip, after) = inner.split_once(']')?;
        ip.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (&authority[..ip.len() + 2], port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if let Some(port) = port
        && !port.parse::<u16>().is_ok_and(|p| p >= 1)
    {
        return None;
    }
    let valid_name = host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    (host.starts_with('[') || valid_name).then_some(host)
}

async fn persist(path: &Path, settings: &Settings) -> Result<()> {
    let json = serde_json::to_vec_pretty(settings)?;
    write_private_file(path, &json).await
}
