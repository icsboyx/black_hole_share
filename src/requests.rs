//! Upload requests: links the admin creates so that someone else can send files.
//!
//! A request sets the largest file it accepts, the allowed extensions, an optional number
//! of files, a title and message for the uploader, and whether the uploader must give a
//! name. Requests are stored in `data/storage/requests.json`; the files they receive are
//! stored by the file store, encrypted for the admin.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::{fs, sync::Mutex};
use uuid::Uuid;

use crate::auth::write_private_file;

pub const MAX_TITLE_CHARS: usize = 100;
pub const MAX_MESSAGE_CHARS: usize = 1000;
pub const MAX_UPLOADER_CHARS: usize = 100;
pub const MAX_EXTENSIONS: usize = 50;
pub const MAX_EXTENSION_CHARS: usize = 16;
pub const MAX_FILES_PER_REQUEST: u32 = 10_000;
pub const MAX_REQUEST_DURATION_MINUTES: u32 = 365 * 24 * 60;
/// Total size a new request accepts when none is given.
pub const DEFAULT_REQUEST_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadRequest {
    /// Random and unguessable: it is the only thing that grants the right to upload.
    pub id: Uuid,
    pub title: String,
    pub message: String,
    pub max_file_size_bytes: u64,
    /// All files together. `None` only for requests created before this limit existed.
    #[serde(default)]
    pub max_total_bytes: Option<u64>,
    /// Lowercase, without the dot. Empty means any file type.
    pub extensions: Vec<String>,
    /// The request closes after this many files.
    pub max_files: Option<u32>,
    pub require_name: bool,
    pub created_at: i64,
    /// After this time the link no longer accepts files. `None`: no expiry.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// Files received so far.
    pub uploads: u32,
    /// Bytes received so far.
    #[serde(default)]
    pub received_bytes: u64,
}

impl UploadRequest {
    pub fn bytes_left(&self) -> Option<u64> {
        self.max_total_bytes
            .map(|max| max.saturating_sub(self.received_bytes))
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }

    /// Whether the name ends in one of the allowed extensions. The extension is only what
    /// the uploader chose to call the file; it says nothing certain about the content.
    pub fn allows(&self, file_name: &str) -> bool {
        if self.extensions.is_empty() {
            return true;
        }
        file_name
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_lowercase())
            .is_some_and(|ext| self.extensions.contains(&ext))
    }

    pub fn files_left(&self) -> Option<u32> {
        self.max_files.map(|max| max.saturating_sub(self.uploads))
    }
}

/// What the admin asks for when creating a request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRequest {
    pub title: String,
    #[serde(default)]
    pub message: String,
    /// All files together; 100 MiB when not given.
    #[serde(default = "default_total")]
    pub max_total_bytes: u64,
    /// Largest single file; the total when not given. Never above the total.
    #[serde(default)]
    pub max_file_size_bytes: Option<u64>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub max_files: Option<u32>,
    #[serde(default)]
    pub require_name: bool,
    /// How long the link accepts files. `None`: until it is full or closed.
    #[serde(default)]
    pub expires_in_minutes: Option<u32>,
}

fn default_total() -> u64 {
    DEFAULT_REQUEST_TOTAL_BYTES
}

#[derive(Debug, PartialEq, Eq)]
pub enum SlotError {
    NotFound,
    Expired,
    /// The file is larger than the request's per-file limit.
    FileTooLarge,
    /// The file would go over what is left of the request's total.
    TotalExceeded {
        bytes_left: u64,
    },
    /// Every allowed file is received or being received.
    Full,
}

#[derive(Debug)]
pub enum CreateError {
    Invalid(String),
    Internal(anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct RequestStore {
    path: PathBuf,
    requests: Arc<Mutex<Vec<UploadRequest>>>,
    /// Uploads in progress per request (count, bytes), so concurrent uploads cannot exceed
    /// `max_files` or `max_total_bytes` together.
    pending: Arc<StdMutex<HashMap<Uuid, (u32, u64)>>>,
}

/// The right to upload one file to a request. Dropping it without `complete` gives the
/// place back, also when the upload future is cancelled because the client went away.
pub struct UploadSlot {
    store: RequestStore,
    request: UploadRequest,
    bytes: u64,
}

impl UploadSlot {
    pub fn request(&self) -> &UploadRequest {
        &self.request
    }

    /// Counts the received file. The request may have been deleted in the meantime; then
    /// there is nothing left to count.
    pub async fn complete(self) -> Result<()> {
        let mut requests = self.store.requests.lock().await;
        let Some(index) = requests.iter().position(|r| r.id == self.request.id) else {
            return Ok(());
        };
        let mut updated = requests.clone();
        updated[index].uploads += 1;
        updated[index].received_bytes += self.bytes;
        self.store.persist(&updated).await?;
        *requests = updated;
        Ok(())
    }
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut pending = self.store.pending.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((count, bytes)) = pending.get_mut(&self.request.id) {
            *count -= 1;
            *bytes -= self.bytes;
            if *count == 0 {
                pending.remove(&self.request.id);
            }
        }
    }
}

impl RequestStore {
    /// Loads the requests file, or starts empty when it does not exist. A file that cannot
    /// be parsed stops startup instead of silently dropping every request.
    pub async fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let requests = match fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid upload requests file {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        Ok(Self {
            path,
            requests: Arc::new(Mutex::new(requests)),
            pending: Arc::new(StdMutex::new(HashMap::new())),
        })
    }

    /// Creates a request after checking it. `max_file_size_limit` is the current
    /// per-file limit from the settings.
    pub async fn create(
        &self,
        new: NewRequest,
        max_file_size_limit: u64,
        max_total_limit: u64,
    ) -> Result<UploadRequest, CreateError> {
        let request = validate(new, max_file_size_limit, max_total_limit)?;
        let mut requests = self.requests.lock().await;
        let mut updated = requests.clone();
        updated.push(request.clone());
        self.persist(&updated)
            .await
            .map_err(CreateError::Internal)?;
        *requests = updated;
        Ok(request)
    }

    pub async fn get(&self, id: &Uuid) -> Option<UploadRequest> {
        let requests = self.requests.lock().await;
        requests.iter().find(|r| r.id == *id).cloned()
    }

    /// Every request, newest first.
    pub async fn list(&self) -> Vec<UploadRequest> {
        let requests = self.requests.lock().await;
        requests.iter().rev().cloned().collect()
    }

    /// Deletes a request: its link stops accepting files. Files already received stay.
    pub async fn remove(&self, id: &Uuid) -> Result<Option<UploadRequest>> {
        let mut requests = self.requests.lock().await;
        let Some(index) = requests.iter().position(|r| r.id == *id) else {
            return Ok(None);
        };
        let mut updated = requests.clone();
        let removed = updated.remove(index);
        self.persist(&updated).await?;
        *requests = updated;
        Ok(Some(removed))
    }

    /// Takes a place for one upload of `bytes`, if the request still accepts files and the
    /// file fits both the per-file limit and what is left of the total.
    pub async fn begin_upload(&self, id: &Uuid, bytes: u64) -> Result<UploadSlot, SlotError> {
        let requests = self.requests.lock().await;
        let request = requests
            .iter()
            .find(|r| r.id == *id)
            .ok_or(SlotError::NotFound)?
            .clone();
        if request.is_expired(Utc::now().timestamp_millis()) {
            return Err(SlotError::Expired);
        }
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let (in_progress, pending_bytes) = pending.get(id).copied().unwrap_or((0, 0));
        if let Some(max) = request.max_files
            && request.uploads + in_progress >= max
        {
            return Err(SlotError::Full);
        }
        if let Some(left) = request.bytes_left()
            && left.saturating_sub(pending_bytes) == 0
        {
            return Err(SlotError::Full);
        }
        if bytes > request.max_file_size_bytes {
            return Err(SlotError::FileTooLarge);
        }
        if let Some(left) = request.bytes_left() {
            let left = left.saturating_sub(pending_bytes);
            if bytes > left {
                return Err(SlotError::TotalExceeded { bytes_left: left });
            }
        }
        let entry = pending.entry(*id).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
        drop(pending);
        Ok(UploadSlot {
            store: self.clone(),
            request,
            bytes,
        })
    }

    async fn persist(&self, requests: &[UploadRequest]) -> Result<()> {
        let json = serde_json::to_vec_pretty(requests)?;
        write_private_file(&self.path, &json).await
    }
}

fn has_control_chars(text: &str, allow_newlines: bool) -> bool {
    text.chars()
        .any(|c| c.is_control() && !(allow_newlines && matches!(c, '\n' | '\r' | '\t')))
}

/// `max_file_size_limit` and `max_total_limit` come from the settings: the per-file limit
/// and the disk budget of all files.
fn validate(
    new: NewRequest,
    max_file_size_limit: u64,
    max_total_limit: u64,
) -> Result<UploadRequest, CreateError> {
    let invalid = |message: String| Err(CreateError::Invalid(message));
    let title = new.title.trim().to_string();
    if title.is_empty()
        || title.chars().count() > MAX_TITLE_CHARS
        || has_control_chars(&title, false)
    {
        return invalid(format!(
            "The title must be 1 to {MAX_TITLE_CHARS} characters, without control characters"
        ));
    }
    let message = new.message.trim().to_string();
    if message.chars().count() > MAX_MESSAGE_CHARS || has_control_chars(&message, true) {
        return invalid(format!(
            "The message must be at most {MAX_MESSAGE_CHARS} characters"
        ));
    }
    if !(1..=max_total_limit).contains(&new.max_total_bytes) {
        return invalid(format!(
            "The total size must be between 1 and {max_total_limit} bytes (the disk budget in the settings)"
        ));
    }
    let max_file_size = new.max_file_size_bytes.unwrap_or(new.max_total_bytes);
    if max_file_size == 0 || max_file_size > new.max_total_bytes {
        return invalid("The largest file must be more than 0 and not above the total size".into());
    }
    if max_file_size > max_file_size_limit {
        return invalid(format!(
            "The largest file can be at most {max_file_size_limit} bytes (the per-file limit in the settings)"
        ));
    }
    let mut extensions: Vec<String> = Vec::new();
    for raw in &new.extensions {
        let ext = raw.trim().trim_start_matches('.').to_lowercase();
        if ext.is_empty() {
            continue;
        }
        if ext.chars().count() > MAX_EXTENSION_CHARS
            || !ext.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return invalid(format!(
                "\"{}\" is not a valid extension: use letters and digits only, like pdf or jpg",
                raw.trim()
            ));
        }
        if !extensions.contains(&ext) {
            extensions.push(ext);
        }
    }
    if extensions.len() > MAX_EXTENSIONS {
        return invalid(format!("At most {MAX_EXTENSIONS} extensions"));
    }
    if let Some(max) = new.max_files
        && !(1..=MAX_FILES_PER_REQUEST).contains(&max)
    {
        return invalid(format!(
            "Max files must be between 1 and {MAX_FILES_PER_REQUEST}"
        ));
    }
    if let Some(minutes) = new.expires_in_minutes
        && !(1..=MAX_REQUEST_DURATION_MINUTES).contains(&minutes)
    {
        return invalid(format!(
            "The link can stay open between 1 and {MAX_REQUEST_DURATION_MINUTES} minutes"
        ));
    }
    let now = Utc::now().timestamp_millis();
    Ok(UploadRequest {
        id: Uuid::new_v4(),
        title,
        message,
        max_file_size_bytes: max_file_size,
        max_total_bytes: Some(new.max_total_bytes),
        extensions,
        max_files: new.max_files,
        require_name: new.require_name,
        created_at: now,
        expires_at: new
            .expires_in_minutes
            .map(|minutes| now + i64::from(minutes) * 60_000),
        uploads: 0,
        received_bytes: 0,
    })
}

/// Checks the uploader's name: optional unless the request requires it. Returns the
/// trimmed name, or `None` when none was given.
pub fn clean_uploader(raw: Option<&str>, required: bool) -> Result<Option<String>, String> {
    match raw.map(str::trim).filter(|name| !name.is_empty()) {
        None if required => Err("Enter your name".into()),
        None => Ok(None),
        Some(name)
            if name.chars().count() > MAX_UPLOADER_CHARS || has_control_chars(name, false) =>
        {
            Err(format!(
                "The name must be at most {MAX_UPLOADER_CHARS} characters, without control characters"
            ))
        }
        Some(name) => Ok(Some(name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(extensions: &[&str], max_files: Option<u32>) -> NewRequest {
        NewRequest {
            title: "Contract documents".into(),
            message: "Please send the signed copy.\nThanks".into(),
            max_total_bytes: 1000,
            max_file_size_bytes: Some(100),
            extensions: extensions.iter().map(|e| e.to_string()).collect(),
            max_files,
            require_name: false,
            expires_in_minutes: None,
        }
    }

    #[test]
    fn extensions_are_normalized_and_checked_on_the_file_name() {
        let created = validate(request(&[".PDF", " jpg", "pdf", ""], None), 1000, 10_000).unwrap();
        assert_eq!(created.extensions, vec!["pdf", "jpg"]);
        assert!(created.allows("Scan.Pdf"));
        assert!(created.allows("photo.final.JPG"));
        assert!(!created.allows("archive.zip"));
        assert!(!created.allows("pdf"));
        assert!(!created.allows("document.pdf.exe"));

        let any = validate(request(&[], None), 1000, 10_000).unwrap();
        assert!(any.allows("whatever"));
    }

    #[test]
    fn invalid_requests_are_refused() {
        let cases = [
            NewRequest {
                title: "  ".into(),
                ..request(&[], None)
            },
            NewRequest {
                title: "a\u{7}b".into(),
                ..request(&[], None)
            },
            NewRequest {
                message: "x".repeat(1001),
                ..request(&[], None)
            },
            NewRequest {
                max_file_size_bytes: Some(0),
                ..request(&[], None)
            },
            // Per file above the total.
            NewRequest {
                max_file_size_bytes: Some(1001),
                ..request(&[], None)
            },
            // Per file above the settings' per-file limit.
            NewRequest {
                max_total_bytes: 5000,
                max_file_size_bytes: Some(1001),
                ..request(&[], None)
            },
            // Total above the disk budget.
            NewRequest {
                max_total_bytes: 10_001,
                max_file_size_bytes: None,
                ..request(&[], None)
            },
            NewRequest {
                max_total_bytes: 0,
                ..request(&[], None)
            },
            request(&["p.df"], None),
            request(&["tar/gz"], None),
            request(&[], Some(0)),
            NewRequest {
                expires_in_minutes: Some(0),
                ..request(&[], None)
            },
        ];
        for case in cases {
            assert!(
                matches!(
                    validate(case.clone(), 1000, 10_000),
                    Err(CreateError::Invalid(_))
                ),
                "{case:?}"
            );
        }
    }

    #[test]
    fn uploader_name_is_optional_unless_required() {
        assert_eq!(clean_uploader(None, false), Ok(None));
        assert_eq!(clean_uploader(Some("  "), false), Ok(None));
        assert!(clean_uploader(Some(" "), true).is_err());
        assert_eq!(clean_uploader(Some(" Ada "), true), Ok(Some("Ada".into())));
        assert!(clean_uploader(Some("a\nb"), false).is_err());
    }

    #[test]
    fn largest_file_defaults_to_the_total() {
        let created = validate(
            NewRequest {
                max_file_size_bytes: None,
                ..request(&[], None)
            },
            1000,
            10_000,
        )
        .unwrap();
        assert_eq!(created.max_file_size_bytes, 1000);
        assert_eq!(created.max_total_bytes, Some(1000));
    }

    #[tokio::test]
    async fn slots_respect_the_total_size_including_uploads_in_progress() {
        let path = std::env::temp_dir()
            .join(format!("bhs-req-{}", Uuid::new_v4()))
            .join("requests.json");
        let store = RequestStore::load(path).await.unwrap();
        // 1000 in total, at most 600 per file.
        let created = store
            .create(
                NewRequest {
                    max_file_size_bytes: Some(600),
                    ..request(&[], None)
                },
                1000,
                10_000,
            )
            .await
            .unwrap();
        assert_eq!(
            store.begin_upload(&created.id, 601).await.err(),
            Some(SlotError::FileTooLarge)
        );
        let first = store.begin_upload(&created.id, 600).await.unwrap();
        // 600 are in progress: only 400 are left.
        assert_eq!(
            store.begin_upload(&created.id, 500).await.err(),
            Some(SlotError::TotalExceeded { bytes_left: 400 })
        );
        let second = store.begin_upload(&created.id, 400).await.unwrap();
        drop(second);
        first.complete().await.unwrap();
        assert_eq!(
            store.get(&created.id).await.unwrap().bytes_left(),
            Some(400)
        );
        let last = store.begin_upload(&created.id, 400).await.unwrap();
        last.complete().await.unwrap();
        assert_eq!(
            store.begin_upload(&created.id, 1).await.err(),
            Some(SlotError::Full)
        );
    }

    #[tokio::test]
    async fn slots_respect_max_files_and_are_given_back_when_dropped() {
        let path = std::env::temp_dir()
            .join(format!("bhs-req-{}", Uuid::new_v4()))
            .join("requests.json");
        let store = RequestStore::load(path.clone()).await.unwrap();
        let created = store
            .create(request(&[], Some(2)), 1000, 10_000)
            .await
            .unwrap();

        let first = store.begin_upload(&created.id, 10).await.unwrap();
        let second = store.begin_upload(&created.id, 10).await.unwrap();
        assert_eq!(
            store.begin_upload(&created.id, 10).await.err(),
            Some(SlotError::Full)
        );

        // A failed upload gives its place back.
        drop(second);
        let second = store.begin_upload(&created.id, 10).await.unwrap();
        first.complete().await.unwrap();
        second.complete().await.unwrap();
        assert_eq!(
            store.begin_upload(&created.id, 10).await.err(),
            Some(SlotError::Full)
        );
        assert_eq!(store.get(&created.id).await.unwrap().files_left(), Some(0));

        // Counts survive a restart.
        let reloaded = RequestStore::load(path).await.unwrap();
        assert_eq!(reloaded.get(&created.id).await.unwrap().uploads, 2);

        // An expired link refuses files.
        let expiring = store
            .create(
                NewRequest {
                    expires_in_minutes: Some(1),
                    ..request(&[], None)
                },
                1000,
                10_000,
            )
            .await
            .unwrap();
        assert!(store.begin_upload(&expiring.id, 10).await.is_ok());
        {
            let mut requests = store.requests.lock().await;
            let entry = requests.iter_mut().find(|r| r.id == expiring.id).unwrap();
            entry.expires_at = Some(Utc::now().timestamp_millis() - 1);
        }
        assert_eq!(
            store.begin_upload(&expiring.id, 10).await.err(),
            Some(SlotError::Expired)
        );

        assert!(store.remove(&created.id).await.unwrap().is_some());
        assert_eq!(
            store.begin_upload(&created.id, 10).await.err(),
            Some(SlotError::NotFound)
        );
    }
}
