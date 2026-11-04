use std::sync::Arc;
use std::{collections::HashMap, fmt::Debug};

use actix_web::web::Bytes;
use anyhow::Result;
use chrono::{Duration, Utc};
use futures::lock::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{MAX_ASSETS, MAX_TOTAL_STORAGE_BYTES};
use crate::logs::LogFile;
use crate::{MAX_UPLOADS_PER_USER, logs::LogEventType};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Asset {
    id: String,
    share_duration: u32,
    created_at: i64,
    expires_at: i64,
    mime: String,
    #[serde(skip)]
    content: Bytes,
    uploader_ip: Option<String>,
}

#[allow(dead_code)]
impl Asset {
    pub fn new(
        share_duration: u32,
        mime: String,
        content: Vec<u8>,
        uploader_ip: Option<String>,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let created_at = Utc::now().timestamp_millis();
        let expires_at = created_at + Duration::minutes(share_duration as i64).num_milliseconds();
        Asset {
            id,
            share_duration,
            created_at,
            expires_at,
            mime,
            content: content.into(),
            uploader_ip,
        }
    }
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp_millis() > self.expires_at
    }

    pub fn id(&self) -> String {
        self.id.clone()
    }

    pub fn mime(&self) -> String {
        self.mime.clone()
    }

    pub fn content(&self) -> Bytes {
        self.content.clone()
    }

    pub fn share_duration(&self) -> u32 {
        self.share_duration
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn mime_type(&self) -> &str {
        &self.mime
    }

    pub fn size_bytes(&self) -> usize {
        self.content.len()
    }

    pub fn uploader_ip(&self) -> Option<&str> {
        self.uploader_ip.as_deref()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        Ok(bytes)
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub assets: AssetStorage,
    pub connection_tracker: RateLimiter,
    pub log_file: LogFile,
}

#[derive(Clone, Debug, Default)]
pub struct AssetStorage {
    assets: Arc<Mutex<Vec<Asset>>>,
}

#[allow(dead_code)]
impl AssetStorage {
    pub fn new() -> Self {
        Self {
            assets: Arc::new(Mutex::new(Vec::with_capacity(MAX_ASSETS))),
        }
    }

    pub async fn add_asset(&self, asset: Asset, log: &LogFile) -> Result<()> {
        let now = chrono::Utc::now();

        let (removed, result) = {
            let mut assets = self.assets.lock().await;
            let removed: Vec<Asset> = assets.extract_if(.., |a| a.is_expired()).collect();

            let used_bytes: usize = assets.iter().map(Asset::size_bytes).sum();
            let result = if assets.len() >= MAX_ASSETS
                || used_bytes + asset.size_bytes() > MAX_TOTAL_STORAGE_BYTES
            {
                Err(anyhow::anyhow!("Asset storage full"))
            } else {
                println!("[{}] Adding asset: {}", now.to_rfc3339(), asset.id());
                assets.push(asset);
                Ok(())
            };
            (removed, result)
        };

        log_removed_assets(&removed, log).await;
        result
    }

    async fn push_asset(&self, asset: Asset) {
        let mut assets = self.assets.lock().await;
        assets.push(asset);
    }
    pub async fn remove_expired(&self, log: &LogFile) {
        let removed: Vec<Asset> = {
            let mut assets = self.assets.lock().await;
            assets.extract_if(.., |asset| asset.is_expired()).collect()
        };
        log_removed_assets(&removed, log).await;
    }

    pub async fn active_assets(&self) -> usize {
        self.assets.lock().await.len()
    }

    pub async fn stats_summary(&self) -> (usize, u64, usize, usize) {
        let assets = self.assets.lock().await;
        let mut active_assets = 0;
        let mut storage_bytes: u64 = 0;
        let mut image_count = 0;
        let mut text_count = 0;

        for asset in assets.iter() {
            if asset.is_expired() {
                continue;
            }
            active_assets += 1;
            storage_bytes += asset.size_bytes() as u64;
            if asset.mime().starts_with("image/") {
                image_count += 1;
            } else if asset.mime().starts_with("text/") {
                text_count += 1;
            }
        }

        (active_assets, storage_bytes, image_count, text_count)
    }

    pub async fn show_assets(&self) {
        for asset in self.assets.lock().await.iter() {
            println!(
                "[{}] Asset ID: {}, Expires At: {}, Mime: {}, Size: {} bytes",
                chrono::Local::now().to_rfc3339(),
                asset.id(),
                asset.expires_at(),
                asset.mime(),
                asset.size_bytes()
            );
        }
    }

    pub async fn get_asset(&self, id: &str) -> Option<Asset> {
        let assets = self.assets.lock().await;
        assets
            .iter()
            .find(|asset| asset.id == id && !asset.is_expired())
            .cloned()
    }

    pub async fn assets_len(&self) -> usize {
        self.assets.lock().await.len()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RateLimiter {
    pub clients: Arc<Mutex<HashMap<String, Vec<i64>>>>,
}

impl RateLimiter {
    pub async fn check(&self, client_ip: &str, asset_exp_time: i64) -> (bool, Option<i64>) {
        self.clear_expired().await;
        let now = Utc::now().timestamp_millis();
        let mut clients = self.clients.lock().await;
        let entry = clients
            .entry(client_ip.to_string())
            .or_insert_with(Vec::new);

        if entry.len() < MAX_UPLOADS_PER_USER {
            entry.push(asset_exp_time);
            (true, None)
        } else {
            println!(
                "[{}] Rate limit exceeded for IP: {}",
                chrono::Local::now().to_rfc3339(),
                client_ip
            );
            let first_to_expire = entry.iter().min().copied().unwrap();
            let retry_after_ms = (first_to_expire - now).max(1);
            (false, Some(retry_after_ms))
        }
    }

    /// Gives back a slot taken by `check` when the asset could not be stored.
    pub async fn release(&self, client_ip: &str, asset_exp_time: i64) {
        let mut clients = self.clients.lock().await;
        if let Some(entry) = clients.get_mut(client_ip)
            && let Some(index) = entry.iter().position(|&time| time == asset_exp_time)
        {
            entry.swap_remove(index);
        }
    }

    pub async fn clear_expired(&self) {
        let mut clients = self.clients.lock().await;
        let now = Utc::now().timestamp_millis();

        clients.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| timestamp > now);
            !timestamps.is_empty()
        });
    }
}

/// A log failure must never stop cleanup: expired assets have to go away regardless.
async fn log_removed_assets(removed: &[Asset], log: &LogFile) {
    for asset in removed {
        println!(
            "[{}] Removing asset: {}",
            chrono::Local::now().to_rfc3339(),
            asset.id()
        );
        if let Err(e) = log
            .write_event(LogEventType::AssetDeleted(asset.to_value()))
            .await
        {
            eprintln!("Failed to log asset deletion: {}", e);
        }
    }
}

pub async fn clear_app_data(app_state: &AppState) -> Result<()> {
    app_state.assets.remove_expired(&app_state.log_file).await;
    app_state.connection_tracker.clear_expired().await;
    Ok(())
}
