use anyhow::Result;

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_web::HttpRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    fs::{File, OpenOptions, rename},
    io::AsyncWriteExt,
    sync::Mutex,
};

use crate::{MAX_LOG_FILE_BYTES, MAX_ROTATED_LOGS};

const MAX_RECENT_ACTIVITY: usize = 20;

/// Counters for the current run, kept in memory so /api/stats never has to read the log.
#[derive(Debug, Clone, Default)]
pub struct LogStats {
    pub total_requests: usize,
    pub total_uploads: usize,
    pub total_deleted: usize,
    pub recent_activity: VecDeque<LogEvent>,
}

impl LogStats {
    fn record(&mut self, log_event: &LogEvent) {
        match log_event.event {
            LogEventType::HttpRequest(_) => self.total_requests += 1,
            LogEventType::AssetUploaded(_) => self.total_uploads += 1,
            LogEventType::AssetDeleted(_) => self.total_deleted += 1,
            LogEventType::Error(_) => return,
        }
        if !matches!(log_event.event, LogEventType::HttpRequest(_)) {
            self.recent_activity.push_back(log_event.clone());
            if self.recent_activity.len() > MAX_RECENT_ACTIVITY {
                self.recent_activity.pop_front();
            }
        }
    }
}

#[derive(Debug)]
struct LogWriter {
    file: File,
    size: u64,
}

#[derive(Debug, Clone)]
pub struct LogFile {
    path: PathBuf,
    writer: Arc<Mutex<LogWriter>>,
    stats: Arc<Mutex<LogStats>>,
    max_bytes: u64,
    max_rotated: usize,
}

impl LogFile {
    pub async fn new(path: impl Into<PathBuf>) -> Result<Self> {
        Self::with_limits(path, MAX_LOG_FILE_BYTES, MAX_ROTATED_LOGS).await
    }

    pub async fn with_limits(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        max_rotated: usize,
    ) -> Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        if LogFile::log_file_exist(&path).await? {
            LogFile::log_file_rotate(&path).await?;
            LogFile::prune_rotated_logs(&path, max_rotated).await?;
        }

        let file = LogFile::open_log(&path).await?;
        println!("Log file created at: {}", path.display());
        Ok(Self {
            path,
            writer: Arc::new(Mutex::new(LogWriter { file, size: 0 })),
            stats: Arc::new(Mutex::new(LogStats::default())),
            max_bytes,
            max_rotated,
        })
    }

    async fn open_log(path: &Path) -> Result<File> {
        Ok(OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?)
    }

    pub async fn stats(&self) -> LogStats {
        self.stats.lock().await.clone()
    }

    pub async fn write_event(&self, event: LogEventType) -> Result<()> {
        let log_event: LogEvent = event.into();
        self.stats.lock().await.record(&log_event);
        let line = serde_json::to_string(&log_event)? + "\n";
        let mut writer = self.writer.lock().await;
        if writer.size + line.len() as u64 > self.max_bytes {
            writer.file.flush().await?;
            LogFile::log_file_rotate(&self.path).await?;
            LogFile::prune_rotated_logs(&self.path, self.max_rotated).await?;
            writer.file = LogFile::open_log(&self.path).await?;
            writer.size = 0;
        }
        writer.file.write_all(line.as_bytes()).await?;
        writer.size += line.len() as u64;
        Ok(())
    }

    /// Deletes the oldest rotated logs, keeping at most `keep` of them.
    async fn prune_rotated_logs(path: &Path, keep: usize) -> Result<()> {
        let Some(dir) = path.parent() else {
            return Ok(());
        };
        let filename = path.file_name().unwrap_or_default().to_string_lossy();
        let suffix = format!("_{}", filename);

        let mut rotated = Vec::new();
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name().to_string_lossy().ends_with(&suffix) {
                rotated.push((entry.metadata().await?.modified()?, entry.path()));
            }
        }

        rotated.sort();
        let excess = rotated.len().saturating_sub(keep);
        for (_, old_log) in rotated.into_iter().take(excess) {
            tokio::fs::remove_file(old_log).await?;
        }
        Ok(())
    }

    async fn log_file_exist(path: impl Into<PathBuf>) -> Result<bool> {
        if tokio::fs::metadata(path.into()).await.is_ok() { Ok(true) } else { Ok(false) }
    }
    async fn log_file_rotate(path: impl Into<PathBuf>) -> Result<()> {
        let path: PathBuf = path.into();
        let now = chrono::Utc::now().format("%Y_%m_%d-%H%M%S_%3f").to_string();
        let Some(dir) = path.parent() else {
            return Err(anyhow::anyhow!("Failed to get parent directory for log rotation"));
        };
        let filename = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("log.txt"));
        let rotated = dir.join(format!("{}_{}", now, filename.to_string_lossy()));
        rename(path, rotated).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHttpRequest {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub scheme: String,
    pub ip: String,
    pub real_ip: String,
    pub user_agent: String,
}
impl From<HttpRequest> for LogHttpRequest {
    fn from(req: HttpRequest) -> Self {
        let method = req.method().as_str().to_string();
        let uri = req.uri();
        let path = uri.path().to_string();
        let query_string = uri.query().unwrap_or("-").to_string();

        let connection_info = req.connection_info();
        let scheme = connection_info.scheme().to_string();
        let ip = connection_info.peer_addr().unwrap_or("-").to_string();
        let real_ip = crate::client_ip(&req).unwrap_or_else(|| "-".to_string());

        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();

        LogHttpRequest {
            method,
            path,
            query_string,
            scheme,
            ip,
            real_ip,
            user_agent,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogEventType {
    AssetUploaded(Value),
    AssetDeleted(Value),
    HttpRequest(LogHttpRequest),
    Error(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub time: String,
    pub event: LogEventType,
}

impl From<LogEventType> for LogEvent {
    fn from(event: LogEventType) -> Self {
        let time = chrono::Utc::now().to_rfc3339();
        LogEvent { time, event }
    }
}
