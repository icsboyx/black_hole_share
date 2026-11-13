//! Runtime settings, stored in `data/admin/settings.json` and edited from the admin panel.
//!
//! Most values apply to the next request. The listening addresses, the TLS setup and
//! `admin_session_max_age_minutes` are read once at startup, so a change takes effect only
//! after a restart; `running()` keeps the values the server started with.
//!
//! A few settings can be fixed by environment variables ([`ENV_SETTINGS`]), the usual way to
//! configure a container: they are applied and saved at every start, and the admin panel
//! cannot change them.

use std::{
    collections::BTreeMap,
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

/// Environment variables that set a setting at every start, and the field each one sets.
pub const ENV_SETTINGS: &[(&str, &str)] = &[
    ("BIND_ADDR", "bind_addr"),
    ("BIND_PORT_HTTP", "bind_port"),
    ("BIND_PORT_HTTPS", "https_port"),
    ("TRUSTED_PROXIES", "trusted_proxies"),
    ("EXTERNAL_FQDN", "public_url"),
];

/// Settings fixed by environment variables: field name to variable name.
pub type LockedFields = BTreeMap<&'static str, &'static str>;

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
    /// Fields set by environment variables, which `update` refuses to change.
    locked: Arc<LockedFields>,
}

impl SettingsStore {
    /// Loads the settings file, creating it with the defaults on first start, then applies
    /// the environment variables in [`ENV_SETTINGS`]. A file or a variable that cannot be
    /// parsed, or invalid values, stop startup instead of being replaced.
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self> {
        Self::load_with_env(path, |name| std::env::var(name).ok()).await
    }

    /// `load` with the environment read through `env`, so tests do not touch the process.
    pub async fn load_with_env(
        path: impl Into<PathBuf>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let path = path.into();
        let (saved, created) = match fs::read(&path).await {
            Ok(bytes) => (
                Some(
                    serde_json::from_slice::<Settings>(&bytes)
                        .with_context(|| format!("invalid settings file {}", path.display()))?,
                ),
                false,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, true),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let mut settings = saved.clone().unwrap_or_default();
        let locked = apply_env(&mut settings, env)?;

        let errors = settings.validate();
        if !errors.is_empty() {
            let details: Vec<String> = errors
                .iter()
                .map(|e| match locked.get(e.field.as_str()) {
                    Some(var) => format!("{} (from {var}) {}", e.field, e.message),
                    None => format!("{} {}", e.field, e.message),
                })
                .collect();
            bail!(
                "invalid settings in {}: {}",
                path.display(),
                details.join("; ")
            );
        }
        if saved.as_ref() != Some(&settings) {
            persist(&path, &settings).await?;
            if created {
                println!("Settings file created at {}", path.display());
            }
        }
        for (field, var) in &locked {
            println!("Setting {field} is fixed by {var}");
        }
        let mut store = Self::with_settings(path, settings);
        store.locked = Arc::new(locked);
        Ok(store)
    }

    fn with_settings(path: PathBuf, settings: Settings) -> Self {
        Self {
            path,
            running: Arc::new(settings.clone()),
            current: Arc::new(RwLock::new(settings)),
            write: Arc::new(Mutex::new(())),
            locked: Arc::default(),
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

    /// Fields fixed by environment variables, with the variable that sets each one.
    pub fn locked(&self) -> &LockedFields {
        &self.locked
    }

    /// The settings the server started with, used for the restart-only values.
    pub fn running(&self) -> &Settings {
        &self.running
    }

    /// Validates, saves and applies new settings. Returns the previous ones.
    pub async fn update(&self, new: Settings) -> Result<Settings, UpdateError> {
        let mut errors = new.validate();
        if !self.locked.is_empty() {
            let current =
                serde_json::to_value(self.get()).map_err(|e| UpdateError::Internal(e.into()))?;
            let wanted = serde_json::to_value(&new).map_err(|e| UpdateError::Internal(e.into()))?;
            for (field, var) in self.locked.iter() {
                if current.get(field) != wanted.get(field) {
                    errors.push(FieldError {
                        field: (*field).to_string(),
                        message: format!("is set by the {var} environment variable"),
                    });
                }
            }
        }
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

/// Applies the environment variables in [`ENV_SETTINGS`] that are set and not empty.
/// Returns the fields they fixed; a value that cannot be parsed is an error naming the
/// variable. Ranges are checked afterwards by `validate`.
pub fn apply_env(
    settings: &mut Settings,
    env: impl Fn(&str) -> Option<String>,
) -> Result<LockedFields> {
    let mut locked = LockedFields::new();
    for &(var, field) in ENV_SETTINGS {
        let Some(raw) = env(var) else { continue };
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        let invalid = |what: &str| anyhow::anyhow!("{var}={value:?} is not {what}");
        match field {
            "bind_addr" => {
                settings.bind_addr = value.parse().map_err(|_| invalid("an IP address"))?
            }
            "bind_port" => settings.bind_port = value.parse().map_err(|_| invalid("a port"))?,
            "https_port" => settings.https_port = value.parse().map_err(|_| invalid("a port"))?,
            "trusted_proxies" => {
                settings.trusted_proxies = value
                    .split(',')
                    .map(str::trim)
                    .filter(|ip| !ip.is_empty())
                    .map(|ip| ip.parse())
                    .collect::<Result<_, _>>()
                    .map_err(|_| invalid("a comma-separated list of IP addresses"))?;
            }
            "public_url" => {
                // A host name, optionally with a port: the scheme is always https, the
                // address of a TLS proxy or of this server's own HTTPS.
                if value.contains("://") || value.contains('/') {
                    return Err(invalid("a host name without scheme or path"));
                }
                let url = format!("https://{value}");
                if public_url_host(&url).is_none() {
                    return Err(invalid("a valid host name"));
                }
                settings.public_url = url;
            }
            _ => unreachable!("ENV_SETTINGS names a field apply_env does not handle"),
        }
        locked.insert(field, var);
    }
    Ok(locked)
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
