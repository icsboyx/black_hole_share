//! Runtime settings, stored in `data/admin/settings.json` and edited from the admin panel.
//!
//! Most values apply to the next request. `bind_addr`, `bind_port` and
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
        errors
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

async fn persist(path: &Path, settings: &Settings) -> Result<()> {
    let json = serde_json::to_vec_pretty(settings)?;
    write_private_file(path, &json).await
}
