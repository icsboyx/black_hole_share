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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadRequest {
    /// Random and unguessable: it is the only thing that grants the right to upload.
    pub id: Uuid,
    pub title: String,
    pub message: String,
    pub max_file_size_bytes: u64,
    /// Lowercase, without the dot. Empty means any file type.
    pub extensions: Vec<String>,
    /// The request closes after this many files.
    pub max_files: Option<u32>,
    pub require_name: bool,
    pub created_at: i64,
    /// Files received so far.
    pub uploads: u32,
}

impl UploadRequest {
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
    pub max_file_size_bytes: u64,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub max_files: Option<u32>,
    #[serde(default)]
    pub require_name: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SlotError {
    NotFound,
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
    /// Uploads in progress per request, so concurrent uploads cannot exceed `max_files`.
    pending: Arc<StdMutex<HashMap<Uuid, u32>>>,
}

/// The right to upload one file to a request. Dropping it without `complete` gives the
/// place back, also when the upload future is cancelled because the client went away.
pub struct UploadSlot {
    store: RequestStore,
    request: UploadRequest,
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
        self.store.persist(&updated).await?;
        *requests = updated;
        Ok(())
    }
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut pending = self.store.pending.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = pending.get_mut(&self.request.id) {
            *count -= 1;
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
    ) -> Result<UploadRequest, CreateError> {
        let request = validate(new, max_file_size_limit)?;
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

    /// Takes a place for one upload, if the request still accepts files.
    pub async fn begin_upload(&self, id: &Uuid) -> Result<UploadSlot, SlotError> {
        let requests = self.requests.lock().await;
        let request = requests
            .iter()
            .find(|r| r.id == *id)
            .ok_or(SlotError::NotFound)?
            .clone();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let in_progress = pending.get(id).copied().unwrap_or(0);
        if let Some(max) = request.max_files
            && request.uploads + in_progress >= max
        {
            return Err(SlotError::Full);
        }
        *pending.entry(*id).or_insert(0) += 1;
        drop(pending);
        Ok(UploadSlot {
            store: self.clone(),
            request,
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

fn validate(new: NewRequest, max_file_size_limit: u64) -> Result<UploadRequest, CreateError> {
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
    if !(1..=max_file_size_limit).contains(&new.max_file_size_bytes) {
        return invalid(format!(
            "The largest file must be between 1 and {max_file_size_limit} bytes (the per-file limit in the settings)"
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
    Ok(UploadRequest {
        id: Uuid::new_v4(),
        title,
        message,
        max_file_size_bytes: new.max_file_size_bytes,
        extensions,
        max_files: new.max_files,
        require_name: new.require_name,
        created_at: Utc::now().timestamp_millis(),
        uploads: 0,
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
            max_file_size_bytes: 100,
            extensions: extensions.iter().map(|e| e.to_string()).collect(),
            max_files,
            require_name: false,
        }
    }

    #[test]
    fn extensions_are_normalized_and_checked_on_the_file_name() {
        let created = validate(request(&[".PDF", " jpg", "pdf", ""], None), 1000).unwrap();
        assert_eq!(created.extensions, vec!["pdf", "jpg"]);
        assert!(created.allows("Scan.Pdf"));
        assert!(created.allows("photo.final.JPG"));
        assert!(!created.allows("archive.zip"));
        assert!(!created.allows("pdf"));
        assert!(!created.allows("document.pdf.exe"));

        let any = validate(request(&[], None), 1000).unwrap();
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
                max_file_size_bytes: 0,
                ..request(&[], None)
            },
            NewRequest {
                max_file_size_bytes: 1001,
                ..request(&[], None)
            },
            request(&["p.df"], None),
            request(&["tar/gz"], None),
            request(&[], Some(0)),
        ];
        for case in cases {
            assert!(
                matches!(validate(case.clone(), 1000), Err(CreateError::Invalid(_))),
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

    #[tokio::test]
    async fn slots_respect_max_files_and_are_given_back_when_dropped() {
        let path = std::env::temp_dir()
            .join(format!("bhs-req-{}", Uuid::new_v4()))
            .join("requests.json");
        let store = RequestStore::load(path.clone()).await.unwrap();
        let created = store.create(request(&[], Some(2)), 1000).await.unwrap();

        let first = store.begin_upload(&created.id).await.unwrap();
        let second = store.begin_upload(&created.id).await.unwrap();
        assert_eq!(
            store.begin_upload(&created.id).await.err(),
            Some(SlotError::Full)
        );

        // A failed upload gives its place back.
        drop(second);
        let second = store.begin_upload(&created.id).await.unwrap();
        first.complete().await.unwrap();
        second.complete().await.unwrap();
        assert_eq!(
            store.begin_upload(&created.id).await.err(),
            Some(SlotError::Full)
        );
        assert_eq!(store.get(&created.id).await.unwrap().files_left(), Some(0));

        // Counts survive a restart.
        let reloaded = RequestStore::load(path).await.unwrap();
        assert_eq!(reloaded.get(&created.id).await.unwrap().uploads, 2);

        assert!(store.remove(&created.id).await.unwrap().is_some());
        assert_eq!(
            store.begin_upload(&created.id).await.err(),
            Some(SlotError::NotFound)
        );
    }
}
