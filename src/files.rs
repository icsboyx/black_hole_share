//! Files shared by the admin, stored on disk under `data/storage/`.
//!
//! Each file is stored as `<uuid>`, written first as `<uuid>.part` and renamed when complete.
//! `index.json` lists the files with their limits, so shared files survive a restart.

use std::{
    fmt::{self, Display},
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
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use uuid::Uuid;

use crate::{
    auth::write_private_file,
    crypto::{
        ChunkCipher, FileKey, PLAIN_CHUNK_BYTES, TAG_BYTES, WrappedKey, chunk_count,
        encrypted_size, plain_chunk_len,
    },
    settings::Settings,
};

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
    /// Present when the content is encrypted: its key, wrapped for the admin's public key.
    /// `size` is still the plaintext size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key: Option<WrappedKey>,
    /// Present for a file received through an upload request. Such a file is private: it
    /// never has a public link, only the admin can download it, and it does not expire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received: Option<Received>,
}

/// Where a received file came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Received {
    pub request_id: Uuid,
    /// Kept so the file still says where it came from after the request is deleted.
    pub request_title: String,
    pub uploader: Option<String>,
    pub ip: Option<String>,
}

/// Received files are kept until the admin deletes them.
const NEVER: i64 = i64::MAX;

impl SharedFile {
    /// A file shared through a public link, as opposed to one received from a request.
    pub fn is_shared(&self) -> bool {
        self.received.is_none()
    }

    pub fn is_encrypted(&self) -> bool {
        self.wrapped_key.is_some()
    }

    /// Bytes used on disk, which is what the storage budget counts.
    pub fn stored_size(&self) -> u64 {
        if self.is_encrypted() { encrypted_size(self.size) } else { self.size }
    }

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
    /// Set for a file received through an upload request; the duration and limits above
    /// are then ignored.
    pub received: Option<Received>,
}

/// How to encrypt an upload: the new file's key and the same key wrapped for the admin.
pub struct FileEncryption<'a> {
    pub key: &'a FileKey,
    pub wrapped: WrappedKey,
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
    /// The file is encrypted and no key was given.
    KeyRequired,
    /// The key does not decrypt the file. The download is not counted.
    WrongKey,
    /// The file is open and its download is already counted. When this was the last allowed
    /// download the file is already deleted from disk; the open handle still reads it.
    /// For an encrypted file the handle is positioned after the first chunk.
    Ready {
        file: Box<SharedFile>,
        handle: fs::File,
        decryption: Option<Box<Decryption>>,
    },
}

/// Result of checking a key without downloading.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyCheck {
    NotFound,
    NotYetAvailable { valid_from: i64 },
    NotEncrypted,
    WrongKey,
    Valid,
}

/// What is needed to decrypt the rest of a download.
pub struct Decryption {
    pub cipher: ChunkCipher,
    /// The first chunk, decrypted already to check the key.
    pub first_chunk: Vec<u8>,
}

impl fmt::Debug for Decryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryption")
            .field("first_chunk_len", &self.first_chunk.len())
            .finish_non_exhaustive()
    }
}

/// Files on disk by kind, for the admin overview. Sizes are as stored (encrypted files
/// take a little more than their content).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FileUsage {
    pub shared_files: usize,
    pub shared_bytes: u64,
    pub received_files: usize,
    pub received_bytes: u64,
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

    /// Streams `body` to disk, encrypting it when `encryption` is given, and adds the file.
    /// `length` is the declared Content-Length; the space is reserved before writing, so
    /// concurrent uploads cannot exceed the budget.
    pub async fn add<S, E>(
        &self,
        new: NewFile,
        length: u64,
        mut body: S,
        settings: &Settings,
        encryption: Option<FileEncryption<'_>>,
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
        let stored = if encryption.is_some() { encrypted_size(length) } else { length };
        let _reservation = {
            let files = self.files.lock().await;
            let used: u64 = files.iter().map(SharedFile::stored_size).sum();
            if used + self.reserved.load(Ordering::SeqCst) + stored > settings.max_files_total_bytes
            {
                return Err(FileError::StorageFull);
            }
            self.reserved.fetch_add(stored, Ordering::SeqCst);
            Reservation {
                counter: Arc::clone(&self.reserved),
                bytes: stored,
            }
        };
        let (cipher, wrapped_key) = match encryption {
            Some(FileEncryption { key, wrapped }) => (Some(ChunkCipher::new(key)), Some(wrapped)),
            None => (None, None),
        };

        let id = Uuid::new_v4();
        let mut part = PartFile {
            path: self.dir.join(format!("{id}{PART_SUFFIX}")),
            keep: false,
        };
        write_body(&part.path, length, &mut body, cipher.as_ref()).await?;
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
            wrapped_key,
            received: new.received,
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

    /// Opens the file for download and counts the download. An encrypted file needs its
    /// key, which is checked by decrypting the first chunk before anything is counted.
    pub async fn start_download(&self, id: &Uuid, key: Option<&FileKey>) -> Result<Download> {
        let now = Utc::now().timestamp_millis();
        let mut files = self.files.lock().await;
        let Some(index) = files
            .iter()
            .position(|file| file.id == *id && file.is_shared() && !file.is_expired(now))
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
        let mut handle = fs::File::open(&path)
            .await
            .with_context(|| format!("cannot open {}", path.display()))?;
        let decryption = match (file.is_encrypted(), key) {
            (false, _) => None,
            (true, None) => return Ok(Download::KeyRequired),
            (true, Some(key)) => match read_first_chunk(&mut handle, file.size, key).await? {
                Some(decryption) => Some(Box::new(decryption)),
                None => return Ok(Download::WrongKey),
            },
        };

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
        Ok(Download::Ready {
            file: Box::new(file),
            handle,
            decryption,
        })
    }

    /// Checks a key against an encrypted file without counting a download, so the download
    /// page can report a wrong key before starting the real download.
    pub async fn check_key(&self, id: &Uuid, key: &FileKey) -> Result<KeyCheck> {
        let now = Utc::now().timestamp_millis();
        let Some(file) = self.get(id).await else {
            return Ok(KeyCheck::NotFound);
        };
        if !file.is_available(now) {
            return Ok(KeyCheck::NotYetAvailable {
                valid_from: file.valid_from.unwrap_or(now),
            });
        }
        if file.downloads_left() == Some(0) {
            return Ok(KeyCheck::NotFound);
        }
        if !file.is_encrypted() {
            return Ok(KeyCheck::NotEncrypted);
        }
        let path = content_path(&self.dir, id);
        let mut handle = match fs::File::open(&path).await {
            Ok(handle) => handle,
            // Deleted since the lookup: its last download or an admin delete.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(KeyCheck::NotFound),
            Err(e) => {
                return Err(e).with_context(|| format!("cannot open {}", path.display()));
            }
        };
        Ok(match read_first_chunk(&mut handle, file.size, key).await? {
            Some(_) => KeyCheck::Valid,
            None => KeyCheck::WrongKey,
        })
    }

    /// The shared file if it exists and has not expired, whether or not it is available yet.
    /// Received files are never returned: they have no public link.
    pub async fn get(&self, id: &Uuid) -> Option<SharedFile> {
        let now = Utc::now().timestamp_millis();
        let files = self.files.lock().await;
        files
            .iter()
            .find(|file| file.id == *id && file.is_shared() && !file.is_expired(now))
            .cloned()
    }

    /// Shared files that have not expired, oldest first.
    pub async fn list(&self) -> Vec<SharedFile> {
        let now = Utc::now().timestamp_millis();
        let files = self.files.lock().await;
        files
            .iter()
            .filter(|file| file.is_shared() && !file.is_expired(now))
            .cloned()
            .collect()
    }

    /// Files received through upload requests, newest first.
    pub async fn list_received(&self) -> Vec<SharedFile> {
        let files = self.files.lock().await;
        let mut received: Vec<SharedFile> = files
            .iter()
            .filter(|file| !file.is_shared())
            .cloned()
            .collect();
        received.reverse();
        received
    }

    /// Opens a received file for the admin and checks its key on the first chunk. Not
    /// counted as a download. `None` when no such received file exists.
    pub async fn open_received(
        &self,
        id: &Uuid,
        key: &FileKey,
    ) -> Result<Option<(SharedFile, fs::File, Box<Decryption>)>> {
        let file = {
            let files = self.files.lock().await;
            match files
                .iter()
                .find(|file| file.id == *id && !file.is_shared())
            {
                Some(file) => file.clone(),
                None => return Ok(None),
            }
        };
        let path = content_path(&self.dir, id);
        let mut handle = match fs::File::open(&path).await {
            Ok(handle) => handle,
            // Deleted since the lookup.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
        };
        let decryption = read_first_chunk(&mut handle, file.size, key)
            .await?
            .ok_or_else(|| anyhow!("the stored key does not open received file {id}"))?;
        Ok(Some((file, handle, Box::new(decryption))))
    }

    /// Number of stored files and their total size, expired ones included until cleanup.
    pub async fn usage(&self) -> (usize, u64) {
        let files = self.files.lock().await;
        (files.len(), files.iter().map(SharedFile::stored_size).sum())
    }

    /// Like `usage`, split into shared files and files received through upload requests.
    pub async fn usage_by_kind(&self) -> FileUsage {
        let files = self.files.lock().await;
        let mut usage = FileUsage::default();
        for file in files.iter() {
            if file.is_shared() {
                usage.shared_files += 1;
                usage.shared_bytes += file.stored_size();
            } else {
                usage.received_files += 1;
                usage.received_bytes += file.stored_size();
            }
        }
        usage
    }

    /// Deletes a shared (`received == false`) or received file now. Returns it so the
    /// caller can log the deletion.
    pub async fn remove(&self, id: &Uuid, received: bool) -> Result<Option<SharedFile>> {
        let mut files = self.files.lock().await;
        let Some(index) = files
            .iter()
            .position(|file| file.id == *id && file.is_shared() != received)
        else {
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
    if new.received.is_some() {
        return Ok((name, None, NEVER));
    }
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

/// Reads and decrypts the first chunk of an encrypted file. `None` means a wrong key.
async fn read_first_chunk(
    handle: &mut fs::File,
    plain_size: u64,
    key: &FileKey,
) -> Result<Option<Decryption>> {
    let mut chunk = vec![0; plain_chunk_len(plain_size, 0) + TAG_BYTES];
    handle
        .read_exact(&mut chunk)
        .await
        .context("encrypted file is shorter than its first chunk")?;
    let cipher = ChunkCipher::new(key);
    if cipher
        .open(0, chunk_count(plain_size) == 1, &mut chunk)
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(Decryption {
        cipher,
        first_chunk: chunk,
    }))
}

/// Encrypts the plaintext in chunks of `PLAIN_CHUNK_BYTES` as it arrives. A chunk is only
/// sealed once it is known whether it is the last, which the declared length tells.
struct ChunkWriter<'a> {
    cipher: &'a ChunkCipher,
    buffer: Vec<u8>,
    index: u64,
    last_index: u64,
}

impl ChunkWriter<'_> {
    async fn push(&mut self, file: &mut fs::File, mut data: &[u8]) -> Result<(), FileError> {
        while !data.is_empty() {
            if self.buffer.len() == PLAIN_CHUNK_BYTES {
                if self.index == self.last_index {
                    // More data than the declared length announced.
                    return Err(FileError::LengthMismatch);
                }
                self.seal_and_write(file, false).await?;
            }
            let room = PLAIN_CHUNK_BYTES - self.buffer.len();
            let (now, rest) = data.split_at(room.min(data.len()));
            self.buffer.extend_from_slice(now);
            data = rest;
        }
        Ok(())
    }

    async fn seal_and_write(&mut self, file: &mut fs::File, last: bool) -> Result<(), FileError> {
        self.cipher.seal(self.index, last, &mut self.buffer)?;
        file.write_all(&self.buffer).await?;
        self.buffer.clear();
        self.index += 1;
        Ok(())
    }

    async fn finish(mut self, file: &mut fs::File) -> Result<(), FileError> {
        if self.index != self.last_index {
            return Err(FileError::LengthMismatch);
        }
        self.seal_and_write(file, true).await
    }
}

async fn write_body<S, E>(
    path: &Path,
    length: u64,
    body: &mut S,
    cipher: Option<&ChunkCipher>,
) -> Result<(), FileError>
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

    let mut writer = cipher.map(|cipher| ChunkWriter {
        cipher,
        buffer: Vec::with_capacity(PLAIN_CHUNK_BYTES + TAG_BYTES),
        index: 0,
        last_index: chunk_count(length) - 1,
    });
    let mut written: u64 = 0;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| FileError::Internal(anyhow!("upload interrupted: {e}")))?;
        written += chunk.len() as u64;
        if written > length {
            return Err(FileError::LengthMismatch);
        }
        match writer.as_mut() {
            Some(writer) => writer.push(&mut file, &chunk).await?,
            None => file.write_all(&chunk).await?,
        }
    }
    if written != length {
        return Err(FileError::LengthMismatch);
    }
    if let Some(writer) = writer {
        writer.finish(&mut file).await?;
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
