use actix_web::{HttpRequest, HttpResponse, get, post, web};
use base64::{Engine, engine::general_purpose};

use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::{ALLOWED_CONTENT_TYPES, CONTENT_CSP, MAX_ASSET_DURATION, MIN_ASSET_DURATION};
use crate::{
    MAX_ASSET_SIZE_BYTES,
    data_mgt::{AppState, Asset},
    logs::LogEventType,
};

#[derive(Deserialize, Debug)]
pub struct UploadRequest {
    duration: u32,
    content_type: String,
    content: String, // text or base64 string
}

#[post("/api/upload")]
async fn api_upload(
    req: HttpRequest,
    body: web::Json<UploadRequest>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    // Check for rate limiting
    let now = Utc::now().timestamp_millis();

    let uploader_ip = crate::client_ip(&req)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Cannot determine client ip"))?;

    if !ALLOWED_CONTENT_TYPES.contains(&body.content_type.as_str()) {
        return Ok(HttpResponse::UnsupportedMediaType()
            .json(json!({ "error": "Unsupported content type" })));
    }

    // Convert to bytes
    let content_bytes = if body.content_type == "text/plain" {
        body.content.as_bytes().to_vec()
    } else {
        match general_purpose::STANDARD.decode(&body.content) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(
                    HttpResponse::BadRequest().json(json!({ "error": "Invalid base64 content" }))
                );
            }
        }
    };

    if content_bytes.len() > MAX_ASSET_SIZE_BYTES {
        let error = json!({"error": "Asset too large"});
        app_state
            .log_file
            .write_event(LogEventType::Error(error.clone()))
            .await
            .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));

        return Ok(HttpResponse::PayloadTooLarge().json(json!({
            "error": "Asset too large"
        })));
    }

    let clamped_duration = body.duration.clamp(MIN_ASSET_DURATION, MAX_ASSET_DURATION);
    let asset_expiration_time = now + (clamped_duration as i64 * 60 * 1000);
    let (allowed, retry_after_ms) = app_state
        .connection_tracker
        .check(&uploader_ip, asset_expiration_time)
        .await;
    if !allowed {
        let retry_after_seconds = retry_after_ms.map(|ms| ((ms + 999) / 1000).max(1));
        let response_body = match retry_after_seconds {
            Some(seconds) => {
                json!({ "error": "Upload limit exceeded", "retry_after_seconds": seconds })
            }
            None => json!({ "error": "Upload limit exceeded" }),
        };
        // return Ok(HttpResponse::TooManyRequests().body("Upload limit exceeded"));
        return Ok(HttpResponse::TooManyRequests().json(response_body));
    }

    let asset = crate::data_mgt::Asset::new(
        clamped_duration,
        body.content_type.clone(),
        content_bytes,
        Some(uploader_ip.clone()),
    );

    let id = asset.id();

    match app_state
        .assets
        .add_asset(asset.clone(), &app_state.log_file)
        .await
    {
        Ok(_) => {
            app_state
                .log_file
                .write_event(LogEventType::AssetUploaded(asset.to_value()))
                .await
                .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
            let response_body = json!({ "link": format!("/bhs/{}", id) });
            Ok(HttpResponse::Ok().json(response_body))
        }
        Err(e) => {
            app_state
                .connection_tracker
                .release(&uploader_ip, asset_expiration_time)
                .await;
            let error = json!({"error": format!("Failed to store asset: {}", e)});
            app_state
                .log_file
                .write_event(LogEventType::Error(error.clone()))
                .await
                .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
            Ok(HttpResponse::ServiceUnavailable().json(error))
        }
    }
}

#[get("/api/content/{id}")]
async fn api_get_asset(
    req: HttpRequest,
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    match app_state.assets.get_asset(&path.into_inner()).await {
        None => Ok(HttpResponse::NotFound().body("Asset not found")),
        Some(asset) => Ok(HttpResponse::Ok()
            .content_type(asset.mime())
            .insert_header(("Content-Security-Policy", CONTENT_CSP))
            .body(asset.content())),
    }
}

#[derive(serde::Serialize)]
struct StatsResponse {
    active_assets: usize,
    total_uploads: usize,
    total_deleted: usize,
    storage_bytes: u64,
    image_count: usize,
    text_count: usize,
    total_requests: usize,
    recent_activity: Vec<ActivityItem>,
}

#[derive(serde::Serialize)]
struct ActivityItem {
    action: String,
    mime: String,
    share_duration: u32,
    timestamp: String,
}

#[get("/api/stats")]
async fn api_stats(app_state: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error> {
    let (active_assets, storage_bytes, image_count, text_count) =
        app_state.assets.stats_summary().await;

    let log_stats = app_state.log_file.stats().await;

    // Most recent first
    let recent_activity = log_stats
        .recent_activity
        .into_iter()
        .rev()
        .filter_map(|line| {
            let (action, asset) = match line.event {
                LogEventType::AssetUploaded(asset) => ("upload", asset),
                LogEventType::AssetDeleted(asset) => ("delete", asset),
                LogEventType::HttpRequest(_) | LogEventType::Error(_) => return None,
            };
            let asset = serde_json::from_value::<Asset>(asset).unwrap_or_default();
            Some(ActivityItem {
                action: action.to_string(),
                mime: asset.mime(),
                share_duration: asset.share_duration(),
                timestamp: line.time,
            })
        })
        .collect();

    let response = StatsResponse {
        active_assets,
        total_uploads: log_stats.total_uploads,
        total_deleted: log_stats.total_deleted,
        storage_bytes,
        image_count,
        text_count,
        total_requests: log_stats.total_requests,
        recent_activity,
    };

    Ok(HttpResponse::Ok().json(response))
}
