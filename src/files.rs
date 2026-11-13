//! Files shared by the admin, stored on disk under `data/storage/`.
//!
//! Each file is stored as `<uuid>`, written first as `<uuid>.part` and renamed when complete.
//! `index.json` lists the files with their limits, so shared files survive a restart.

use std::{
    fmt::Display,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use actix_web::web::Bytes;
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};
use uuid::Uuid;

use crate::{auth::write_private_file, settings::Settings};

const INDEX_FILE: &str = "index.json";
const PART_SUFFIX: &str = ".part";
pub const MAX_FILE_NAME_CHARS: usize = 255;
/// How far in the future `valid_from` may be. The file uses disk space while it waits.
pub const MAX_VALID_FROM_AHEAD_MS: i64 = 365 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFile {
    pub id: Uuid,
    /// Name shown to the downloader and used for the downloaded file.
    pub name: String,
    pub size: u64,
    /// Unix time in milliseconds, like every other timestamp here.
    pub created_at: i64,
    /// Before this time the link exists but the download is refused.
    pub valid_from: Option<i64>,
    pub expires_at: i64,
    /// The file is deleted after this many downloads.
    pub max_downloads: Option<u32>,
    pub downloads: u32,
}

impl SharedFile {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    pub fn is_available(&self, now: i64) -> bool {
        self.valid_from.is_none_or(|from| now >= from)
    }

    pub fn downloads_left(&self) -> Option<u32> {
        self.max_downloads
            .map(|max| max.saturating_sub(self.downloads))
    }
}

/// What the admin asks for when uploading.
#[derive(Debug, Clone)]
pub struct NewFile {
    pub name: String,
    pub duration_minutes: u32,
    pub valid_from: Option<i64>,
    pub max_downloads: Option<u32>,
}

#[derive(Debug)]
pub enum FileError {
    InvalidInput(String),
    TooLarge,
    StorageFull,
    /// The body was shorter or longer than its Content-Length.
    LengthMismatch,
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for FileError {
    fn from(error: anyhow::Error) -> Self {
        FileError::Internal(error)
    }
}

impl From<std::io::Error> for FileError {
    fn from(error: std::io::Error) -> Self {
        FileError::Internal(error.into())
    }
}

/// Result of a download request.
#[derive(Debug)]
pub enum Download {
    NotFound,
    NotYetAvailable {
        valid_from: i64,
    },
    /// The file is open and its download is already counted. When this was the last allowed
    /// download the file is already deleted from disk; the open handle still reads it.
    Ready {
        file: SharedFile,
        handle: fs::File,
    },
}

#[derive(Debug, Clone)]
pub struct FileStore {
    dir: PathBuf,
    files: Arc<Mutex<Vec<SharedFile>>>,
    /// Bytes promised to uploads still in progress, so they cannot together exceed the
    /// budget. Increased only while `files` is locked; released by `Reservation::drop`.
    reserved: Arc<AtomicU64>,
}

/// Disk space held for one upload. Dropping it gives the space back, even when the upload
/// future is cancelled because the client went away.
struct Reservation {
    counter: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// A `.part` file that is deleted on drop unless the upload completed.
struct PartFile {
    path: PathBuf,
    keep: bool,
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.keep {
            // Drop cannot await; a cancelled upload is rare, so a short blocking call is fine.
            if let Err(e) = std::fs::remove_file(&self.path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("Cannot remove {}: {e}", self.path.display());
            }
        }
    }
}

impl FileStore {
    /// Loads the index and reconciles it with the directory: entries without content are
    /// dropped, and content or partial uploads without an entry are deleted. Only names this
    /// store creates (`<uuid>` and `<uuid>.part`) are ever deleted.
    pub async fn load(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("cannot create {}", dir.display()))?;

        let index_path = dir.join(INDEX_FILE);
        let indexed: Vec<SharedFile> = match fs::read(&index_path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid file index {}", index_path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot read {}", index_path.display()));
            }
        };

        let indexed_count = indexed.len();
        let mut files = Vec::with_capacity(indexed_count);
        for file in indexed {
            if fs::try_exists(content_path(&dir, &file.id)).await? {
                files.push(file);
            } else {
                eprintln!(
                    "Shared file {} has no content on disk; dropping it",
                    file.id
                );
            }
        }

        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let (stem, partial) = match name.strip_suffix(PART_SUFFIX) {
                Some(stem) => (stem, true),
                None => (name, false),
            };
            let Ok(id) = Uuid::parse_str(stem) else {
                continue;
            };
            // Uuid::parse_str accepts other spellings too; only touch names written here.
            if id.to_string() != stem {
                continue;
            }
            if partial || !files.iter().any(|file| file.id == id) {
                println!("Removing orphan shared file {}", entry.path().display());
                fs::remove_file(entry.path()).await?;
            }
        }

        let dropped = files.len() != indexed_count;
        let store = Self {
            dir,
            files: Arc::new(Mutex::new(files)),
            reserved: Arc::new(AtomicU64::new(0)),
        };
        if dropped {
            let files = store.files.lock().await;
            store.persist(&files).await?;
        }
        Ok(store)
    }

    /// Streams `body` to disk and adds the file. `length` is the declared Content-Length;
    /// the space is reserved before writing, so concurrent uploads cannot exceed the budget.
    pub async fn add<S, E>(
        &self,
        new: NewFile,
        length: u64,
        mut body: S,
        settings: &Settings,
    ) -> Result<SharedFile, FileError>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Display,
    {
        let now = Utc::now().timestamp_millis();
        let (name, valid_from, expires_at) = validate_new(&new, now, settings)?;
        if length > settings.max_file_size_bytes {
            return Err(FileError::TooLarge);
        }
        let _reservation = {
            let files = self.files.lock().await;
            let used: u64 = files.iter().map(|file| file.size).sum();
            if used + self.reserved.load(Ordering::SeqCst) + length > settings.max_files_total_bytes
            {
                return Err(FileError::StorageFull);
            }
            self.reserved.fetch_add(length, Ordering::SeqCst);
            Reservation {
                counter: Arc::clone(&self.reserved),
                bytes: length,
            }
        };

        let id = Uuid::new_v4();
        let mut part = PartFile {
            path: self.dir.join(format!("{id}{PART_SUFFIX}")),
            keep: false,
        };
        write_body(&part.path, length, &mut body).await?;
        fs::rename(&part.path, content_path(&self.dir, &id)).await?;
        // Renamed: nothing is left at the .part path.
        part.keep = true;

        let mut files = self.files.lock().await;

        let file = SharedFile {
            id,
            name,
            size: length,
            created_at: now,
            valid_from,
            expires_at,
            max_downloads: new.max_downloads,
            downloads: 0,
        };
        let mut updated = files.clone();
        updated.push(file.clone());
        if let Err(e) = self.persist(&updated).await {
            drop(files);
            remove_if_exists(&content_path(&self.dir, &id)).await;
            return Err(e.into());
        }
        *files = updated;
        Ok(file)
    }

    /// Opens the file for download and counts the download.
    pub async fn start_download(&self, id: &Uuid) -> Result<Download> {
        let now = Utc::now().timestamp_millis();
        let mut files = self.files.lock().await;
        let Some(index) = files
            .iter()
            .position(|file| file.id == *id && !file.is_expired(now))
        else {
            return Ok(Download::NotFound);
        };
        let file = &files[index];
        if !file.is_available(now) {
            return Ok(Download::NotYetAvailable {
                valid_from: file.valid_from.unwrap_or(now),
            });
        }
        if file.downloads_left() == Some(0) {
            return Ok(Download::NotFound);
        }

        let path = content_path(&self.dir, id);
        let handle = fs::File::open(&path)
            .await
            .with_context(|| format!("cannot open {}", path.display()))?;

        let mut updated = files.clone();
        updated[index].downloads += 1;
        let file = updated[index].clone();
        let exhausted = file.downloads_left() == Some(0);
        if exhausted {
            updated.remove(index);
        }
        self.persist(&updated).await?;
        *files = updated;
        drop(files);

        if exhausted {
            // Unlinking keeps the open handle readable, so this download still completes.
            remove_if_exists(&path).await;
        }
        Ok(Download::Ready { file, handle })
    }

    /// The file if it exists and has not expired, whether or not it is available yet.
    pub async fn get(&self, id: &Uuid) -> Option<SharedFile> {
        let now = Utc::now().timestamp_millis();
        let files = self.files.lock().await;
        files
            .iter()
            .find(|file| file.id == *id && !file.is_expired(now))
            .cloned()
    }

    /// Files that have not expired, oldest first.
    pub async fn list(&self) -> Vec<SharedFile> {
        let now = Utc::now().timestamp_millis();
        let files = self.files.lock().await;
        files
            .iter()
            .filter(|file| !file.is_expired(now))
            .cloned()
            .collect()
    }

    /// Number of stored files and their total size, expired ones included until cleanup.
    pub async fn usage(&self) -> (usize, u64) {
        let files = self.files.lock().await;
        (files.len(), files.iter().map(|file| file.size).sum())
    }

    /// Deletes a file now. Returns it so the caller can log the deletion.
    pub async fn remove(&self, id: &Uuid) -> Result<Option<SharedFile>> {
        let mut files = self.files.lock().await;
        let Some(index) = files.iter().position(|file| file.id == *id) else {
            return Ok(None);
        };
        let mut updated = files.clone();
        let removed = updated.remove(index);
        self.persist(&updated).await?;
        *files = updated;
        drop(files);
        remove_if_exists(&content_path(&self.dir, id)).await;
        Ok(Some(removed))
    }

    /// Deletes expired files and returns them.
    pub async fn remove_expired(&self) -> Result<Vec<SharedFile>> {
        let now = Utc::now().timestamp_millis();
        let mut files = self.files.lock().await;
        if !files.iter().any(|file| file.is_expired(now)) {
            return Ok(Vec::new());
        }
        let (expired, kept): (Vec<SharedFile>, Vec<SharedFile>) =
            files.iter().cloned().partition(|file| file.is_expired(now));
        self.persist(&kept).await?;
        *files = kept;
        drop(files);
        for file in &expired {
            remove_if_exists(&content_path(&self.dir, &file.id)).await;
        }
        Ok(expired)
    }

    async fn persist(&self, files: &[SharedFile]) -> Result<()> {
        let json = serde_json::to_vec_pretty(files)?;
        write_private_file(&self.dir.join(INDEX_FILE), &json).await
    }
}

fn content_path(dir: &Path, id: &Uuid) -> PathBuf {
    dir.join(id.to_string())
}

/// Checks the upload request against the settings. Returns the cleaned name, `valid_from`
/// and `expires_at`. The duration counts from `valid_from` when set, so the link is usable
/// for the whole duration.
fn validate_new(
    new: &NewFile,
    now: i64,
    settings: &Settings,
) -> Result<(String, Option<i64>, i64), FileError> {
    let name = clean_file_name(&new.name)
        .ok_or_else(|| FileError::InvalidInput("File name is missing or too long".into()))?;
    if !(1..=settings.max_file_duration_minutes).contains(&new.duration_minutes) {
        return Err(FileError::InvalidInput(format!(
            "Duration must be between 1 and {} minutes",
            settings.max_file_duration_minutes
        )));
    }
    if new.max_downloads == Some(0) {
        return Err(FileError::InvalidInput(
            "Max downloads must be at least 1".into(),
        ));
    }
    let valid_from = match new.valid_from {
        Some(from) if from > now + MAX_VALID_FROM_AHEAD_MS => {
            return Err(FileError::InvalidInput(
                "Valid from must be within 365 days".into(),
            ));
        }
        // A start in the past means "now"; storing it would only confuse the listing.
        Some(from) if from > now => Some(from),
        _ => None,
    };
    let start = valid_from.unwrap_or(now);
    let expires_at = start + i64::from(new.duration_minutes) * 60 * 1000;
    Ok((name, valid_from, expires_at))
}

/// Keeps only the last path component and rejects control characters, so the name is safe
/// to show and to put in a Content-Disposition header. `None` when nothing usable is left.
pub fn clean_file_name(raw: &str) -> Option<String> {
    let name = raw.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && name.chars().count() <= MAX_FILE_NAME_CHARS
        && !name.chars().any(char::is_control);
    valid.then(|| name.to_string())
}

async fn write_body<S, E>(path: &Path, length: u64, body: &mut S) -> Result<(), FileError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Display,
{
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .await
        .with_context(|| format!("cannot create {}", path.display()))?;

    let mut written: u64 = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| FileError::Internal(anyhow!("upload interrupted: {e}")))?;
        written += chunk.len() as u64;
        if written > length {
            return Err(FileError::LengthMismatch);
        }
        file.write_all(&chunk).await?;
    }
    if written != length {
        return Err(FileError::LengthMismatch);
    }
    file.sync_all().await?;
    Ok(())
}

async fn remove_if_exists(path: &Path) {
    match fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("Cannot remove {}: {e}", path.display()),
    }
}
