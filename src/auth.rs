//! Admin credentials and session key, persisted on disk so they survive restarts.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_web::cookie::Key;
use anyhow::{Context, Result, anyhow, bail};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::AsyncWriteExt,
    sync::{Mutex, Semaphore},
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{AdminKeyPair, OpenKeyError};

pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_PASSWORD_CHARS: usize = 256;
pub const MAX_USERNAME_CHARS: usize = 64;

// Each Argon2 run with default params uses about 19 MiB; cap how many run at once so
// a flood of login attempts cannot exhaust memory.
const MAX_CONCURRENT_HASHES: usize = 2;

#[derive(Debug)]
pub enum AuthError {
    AlreadyConfigured,
    NotConfigured,
    InvalidCredentials,
    InvalidInput(&'static str),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AuthError {
    fn from(error: anyhow::Error) -> Self {
        AuthError::Internal(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credentials {
    username: String,
    password_hash: String,
    /// Bumped on every password change and logout; sessions issued for an older version
    /// are rejected.
    version: u64,
    /// Key pair for encrypted files; the private half is protected by the password.
    /// Missing in files written before file encryption existed: created at the next login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keys: Option<AdminKeyPair>,
}

#[derive(Debug, Clone)]
pub struct CredentialStore {
    path: PathBuf,
    current: Arc<Mutex<Option<Credentials>>>,
    hashing: Arc<Semaphore>,
}

impl CredentialStore {
    /// Loads the credentials file if it exists. A file that cannot be parsed is an error:
    /// treating it as missing would reopen the first-login setup to anyone.
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let current = match fs::read(&path).await {
            Ok(bytes) => Some(
                serde_json::from_slice::<Credentials>(&bytes)
                    .with_context(|| format!("invalid credentials file {}", path.display()))?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(e).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        Ok(Self {
            path,
            current: Arc::new(Mutex::new(current)),
            hashing: Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES)),
        })
    }

    pub async fn is_configured(&self) -> bool {
        self.current.lock().await.is_some()
    }

    /// Creates the admin account. Only the first call succeeds.
    pub async fn setup(&self, username: &str, password: &str) -> Result<u64, AuthError> {
        validate_username(username)?;
        validate_password(password)?;

        // Held for the whole operation so two concurrent setups cannot both succeed.
        let mut current = self.current.lock().await;
        if current.is_some() {
            return Err(AuthError::AlreadyConfigured);
        }
        let credentials = Credentials {
            username: username.to_string(),
            password_hash: self.hash(password).await?,
            version: 1,
            keys: Some(self.generate_keys(password).await?),
        };
        self.persist(&credentials).await?;
        let version = credentials.version;
        *current = Some(credentials);
        Ok(version)
    }

    /// Returns the credentials version when username and password match.
    pub async fn verify(&self, username: &str, password: &str) -> Result<u64, AuthError> {
        let Some(credentials) = self.current.lock().await.clone() else {
            return Err(AuthError::NotConfigured);
        };
        // The hash is checked even for a wrong username, so the response time does not
        // reveal whether the username exists.
        let password_ok = self.check(password, &credentials.password_hash).await?;
        if !(password_ok && username == credentials.username) {
            return Err(AuthError::InvalidCredentials);
        }
        if credentials.keys.is_none()
            && let Err(e) = self.add_missing_keys(password, credentials.version).await
        {
            // The login itself is valid; only encrypted uploads stay unavailable.
            eprintln!("Cannot create the admin encryption keys: {e:#}");
        }
        Ok(credentials.version)
    }

    /// Creates the key pair for credentials written before file encryption existed. Needs
    /// the password, so it runs right after a successful login.
    async fn add_missing_keys(&self, password: &str, version: u64) -> Result<()> {
        let keys = self.generate_keys(password).await?;
        let mut current = self.current.lock().await;
        // The password may have changed while the keys were generated: they would be
        // protected by the old one.
        let Some(credentials) = current
            .as_ref()
            .filter(|c| c.version == version && c.keys.is_none())
        else {
            return Ok(());
        };
        let updated = Credentials {
            keys: Some(keys),
            ..credentials.clone()
        };
        self.persist(&updated).await?;
        *current = Some(updated);
        Ok(())
    }

    /// The public key that encrypted file keys are wrapped for. `None` until the key pair
    /// exists.
    pub async fn public_key(&self) -> Option<PublicKey> {
        let current = self.current.lock().await;
        let keys = current.as_ref()?.keys.as_ref()?;
        keys.public_key()
            .map_err(|e| eprintln!("Admin key pair is damaged: {e:#}"))
            .ok()
    }

    /// Decrypts the admin's private key with the password, to unwrap file keys.
    pub async fn unlock(&self, password: &str) -> Result<StaticSecret, AuthError> {
        let Some(credentials) = self.current.lock().await.clone() else {
            return Err(AuthError::NotConfigured);
        };
        let Some(keys) = credentials.keys else {
            return Err(AuthError::InvalidInput(
                "No encryption keys yet: log out and log in again",
            ));
        };
        let password = password.to_string();
        match self.blocking(move || Ok(keys.open(&password))).await? {
            Ok(secret) => Ok(secret),
            Err(OpenKeyError::WrongPassword) => Err(AuthError::InvalidCredentials),
            Err(OpenKeyError::Internal(e)) => Err(AuthError::Internal(e)),
        }
    }

    /// Replaces the password and invalidates every session issued before the change.
    pub async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<u64, AuthError> {
        validate_password(new_password)?;

        let mut current = self.current.lock().await;
        let Some(credentials) = current.as_ref() else {
            return Err(AuthError::NotConfigured);
        };
        if !self
            .check(current_password, &credentials.password_hash)
            .await?
        {
            return Err(AuthError::InvalidCredentials);
        }
        // The key pair stays the same, so file keys wrapped before the change still open;
        // only the protection of the private key moves to the new password.
        let keys = match credentials.keys.clone() {
            Some(keys) => {
                let (current_password, new_password) =
                    (current_password.to_string(), new_password.to_string());
                Some(
                    self.blocking(move || match keys.open(&current_password) {
                        Ok(secret) => AdminKeyPair::seal(&secret, &new_password),
                        // The password hash matched, so the key must open too.
                        Err(OpenKeyError::WrongPassword) => Err(anyhow!(
                            "admin key pair does not open with the current password"
                        )),
                        Err(OpenKeyError::Internal(e)) => Err(e),
                    })
                    .await?,
                )
            }
            None => Some(self.generate_keys(new_password).await?),
        };
        let updated = Credentials {
            username: credentials.username.clone(),
            password_hash: self.hash(new_password).await?,
            version: credentials.version + 1,
            keys,
        };
        self.persist(&updated).await?;
        let version = updated.version;
        *current = Some(updated);
        Ok(version)
    }

    /// Invalidates every issued session. Session cookies cannot be revoked one by one,
    /// so logging out ends the admin's sessions on every device.
    pub async fn revoke_sessions(&self) -> Result<(), AuthError> {
        let mut current = self.current.lock().await;
        let Some(credentials) = current.as_ref() else {
            return Err(AuthError::NotConfigured);
        };
        let updated = Credentials {
            version: credentials.version + 1,
            ..credentials.clone()
        };
        self.persist(&updated).await?;
        *current = Some(updated);
        Ok(())
    }

    /// True when a session for `username` at `version` is still valid.
    pub async fn session_is_current(&self, username: &str, version: u64) -> bool {
        self.current
            .lock()
            .await
            .as_ref()
            .is_some_and(|c| c.username == username && c.version == version)
    }

    async fn persist(&self, credentials: &Credentials) -> Result<()> {
        let json = serde_json::to_vec_pretty(credentials)?;
        write_private_file(&self.path, &json).await
    }

    /// Runs Argon2 work off the async worker threads, a few at a time: it is CPU and
    /// memory heavy.
    async fn blocking<T, F>(&self, work: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let _permit = self.hashing.acquire().await?;
        tokio::task::spawn_blocking(work).await?
    }

    async fn generate_keys(&self, password: &str) -> Result<AdminKeyPair> {
        let password = password.to_string();
        self.blocking(move || AdminKeyPair::generate(&password))
            .await
    }

    async fn hash(&self, password: &str) -> Result<String> {
        let password = password.to_string();
        self.blocking(move || {
            Argon2::default()
                .hash_password(password.as_bytes())
                .map(|hash| hash.to_string())
                .map_err(|e| anyhow!("password hashing failed: {e}"))
        })
        .await
    }

    async fn check(&self, password: &str, stored_hash: &str) -> Result<bool> {
        let password = password.to_string();
        let stored_hash = stored_hash.to_string();
        self.blocking(move || {
            let parsed = PasswordHash::new(&stored_hash)
                .map_err(|e| anyhow!("stored password hash is invalid: {e}"))?;
            Ok(Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok())
        })
        .await
    }
}

fn validate_username(username: &str) -> Result<(), AuthError> {
    let chars = username.chars().count();
    if chars == 0 || chars > MAX_USERNAME_CHARS {
        return Err(AuthError::InvalidInput(
            "Username must be 1 to 64 characters",
        ));
    }
    if username.trim() != username || username.chars().any(char::is_control) {
        return Err(AuthError::InvalidInput(
            "Username must not contain control characters or leading/trailing spaces",
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), AuthError> {
    let chars = password.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&chars) {
        return Err(AuthError::InvalidInput(
            "Password must be 8 to 256 characters",
        ));
    }
    Ok(())
}

/// Loads the key that signs and encrypts session cookies, creating it on first start.
/// Keeping it on disk means admins stay logged in across restarts.
pub async fn load_or_create_session_key(path: &Path) -> Result<Key> {
    match fs::read(path).await {
        Ok(bytes) => Key::try_from(bytes.as_slice())
            .map_err(|e| anyhow!("invalid session key file {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = Key::try_generate().ok_or_else(|| anyhow!("cannot generate session key"))?;
            write_private_file(path, key.master()).await?;
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Writes through a temporary file and a rename, so a crash never leaves a half-written file.
/// The file is readable only by the owner because it holds secrets.
pub(crate) async fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let Some(dir) = path.parent() else {
        bail!("{} has no parent directory", path.display());
    };
    fs::create_dir_all(dir).await?;

    let tmp = path.with_extension("tmp");
    // A leftover from an interrupted write would keep its old permissions, so start fresh.
    match fs::remove_file(&tmp).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot remove {}", tmp.display())),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(&tmp)
        .await
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    file.write_all(contents).await?;
    file.sync_all().await?;
    drop(file);
    fs::rename(&tmp, path)
        .await
        .with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}
