use actix_web::{HttpRequest, HttpResponse, get, http::header, mime, post, web};
use base64::{Engine, engine::general_purpose};
use futures::StreamExt;

use serde::Deserialize;
use serde_json::json;

use crate::{ALLOWED_CONTENT_TYPES, CONTENT_CSP};
use crate::{
    crypto::{ChunkCipher, FileKey, TAG_BYTES, chunk_count, plain_chunk_len, wrap_file_key},
    data_mgt::{AppState, Asset},
    files::{
        Decryption, Download, FileEncryption, FileError, KeyCheck, NewFile, Received, SharedFile,
    },
    logs::LogEventType,
    requests::{SlotError, clean_uploader},
};

/// Room for the JSON fields around the content (`duration`, `content_type`, ...).
const UPLOAD_JSON_OVERHEAD_BYTES: usize = 1024;

#[derive(Deserialize, Debug)]
pub struct UploadRequest {
    duration: u32,
    content_type: String,
    content: String, // text or base64 string
}

/// Reads the request body, stopping as soon as it grows past `limit` bytes.
/// `None` means the body was too large.
async fn read_body_limited(
    mut payload: web::Payload,
    limit: usize,
) -> Result<Option<web::BytesMut>, actix_web::Error> {
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

#[post("/api/upload")]
async fn api_upload(
    req: HttpRequest,
    payload: web::Payload,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let uploader_ip = crate::client_ip(&req)
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Cannot determine client ip"))?;
    // One snapshot for the whole request, so a concurrent settings change cannot mix limits.
    let settings = app_state.settings.get();

    // The body is read by hand instead of with `web::Json`, because the JSON size limit
    // of `JsonConfig` is fixed at startup while the asset size limit can change at runtime.
    let is_json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .is_some_and(|mime| mime.essence_str() == mime::APPLICATION_JSON.essence_str());
    if !is_json {
        return Ok(HttpResponse::UnsupportedMediaType()
            .json(json!({ "error": "Content-Type must be application/json" })));
    }
    // Base64 and JSON escaping make the body larger than the decoded asset.
    let body_limit = settings
        .max_asset_size_bytes
        .saturating_mul(2)
        .saturating_add(UPLOAD_JSON_OVERHEAD_BYTES);
    let Some(raw_body) = read_body_limited(payload, body_limit).await? else {
        return Ok(HttpResponse::PayloadTooLarge().json(json!({ "error": "Asset too large" })));
    };
    let body: UploadRequest = match serde_json::from_slice(&raw_body) {
        Ok(body) => body,
        Err(_) => {
            return Ok(
                HttpResponse::BadRequest().json(json!({ "error": "Invalid upload request" }))
            );
        }
    };

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

    if content_bytes.len() > settings.max_asset_size_bytes {
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

    let clamped_duration = body.duration.clamp(
        settings.min_asset_duration_minutes,
        settings.max_asset_duration_minutes,
    );
    let asset = crate::data_mgt::Asset::new(
        clamped_duration,
        body.content_type.clone(),
        content_bytes,
        Some(uploader_ip.clone()),
    );
    // The limiter slot is keyed by the asset's own expiry, so deleting the asset early
    // (admin panel) or failing to store it can give back exactly this slot.
    let asset_expiration_time = asset.expires_at();
    let (allowed, retry_after_ms) = app_state
        .connection_tracker
        .check(
            &uploader_ip,
            asset_expiration_time,
            settings.max_uploads_per_ip,
        )
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

    let id = asset.id();

    match app_state
        .assets
        .add_asset(asset.clone(), &settings, &app_state.log_file)
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

    let uuid = uuid::Uuid::parse_str(&path.into_inner())
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid format"))?;

    match app_state.assets.get_asset(&uuid).await {
        None => Ok(HttpResponse::NotFound().body("Asset not found")),
        Some(asset) => Ok(HttpResponse::Ok()
            .content_type(asset.mime())
            .insert_header(("Content-Security-Policy", CONTENT_CSP))
            .body(asset.content())),
    }
}

/// Public upload limits, so the upload page can build its controls from the settings.
#[get("/api/limits")]
async fn api_limits(app_state: web::Data<AppState>) -> HttpResponse {
    let settings = app_state.settings.get();
    HttpResponse::Ok().json(json!({
        "min_duration_minutes": settings.min_asset_duration_minutes,
        "max_duration_minutes": settings.max_asset_duration_minutes,
        "max_asset_size_bytes": settings.max_asset_size_bytes,
    }))
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
                LogEventType::HttpRequest(_)
                | LogEventType::Error(_)
                | LogEventType::Admin(_)
                | LogEventType::File(_) => {
                    return None;
                }
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

/// Public facts about a shared file, for its download page.
#[get("/api/files/{id}/info")]
async fn api_file_info(
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Ok(id) = uuid::Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    let Some(file) = app_state.files.get(&id).await else {
        return Ok(HttpResponse::NotFound().json(json!({ "error": "File not found" })));
    };
    let now = chrono::Utc::now().timestamp_millis();
    Ok(HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(json!({
            "name": file.name,
            "size": file.size,
            "expires_at": file.expires_at,
            "valid_from": file.valid_from,
            "available": file.is_available(now),
            "downloads_left": file.downloads_left(),
            "encrypted": file.is_encrypted(),
        })))
}

/// The key of an encrypted file, sent in a form body so it never appears in a URL, a
/// browser history or an access log.
#[derive(Deserialize)]
struct FileKeyForm {
    key: String,
}

fn parse_file_id(raw: &str) -> Option<uuid::Uuid> {
    uuid::Uuid::parse_str(raw).ok()
}

fn invalid_key_response() -> HttpResponse {
    HttpResponse::BadRequest()
        .json(json!({ "error": "The key is not valid: it is 43 characters long" }))
}

/// Tells whether a key opens an encrypted file, without counting a download.
#[post("/api/files/{id}/check")]
async fn api_file_check_key(
    path: web::Path<String>,
    form: web::Form<FileKeyForm>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(id) = parse_file_id(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    let Some(key) = FileKey::decode(&form.key) else {
        return Ok(invalid_key_response());
    };
    let check = app_state.files.check_key(&id, &key).await.map_err(|e| {
        eprintln!("Cannot check the key of {id}: {e:#}");
        actix_web::error::ErrorInternalServerError("Cannot read the file")
    })?;
    Ok(match check {
        KeyCheck::Valid => HttpResponse::NoContent().finish(),
        KeyCheck::WrongKey => wrong_key_response(),
        KeyCheck::NotEncrypted => {
            HttpResponse::BadRequest().json(json!({ "error": "This file is not encrypted" }))
        }
        KeyCheck::NotFound => file_not_found_response(),
        KeyCheck::NotYetAvailable { valid_from } => not_yet_available_response(valid_from),
    })
}

/// Download of an encrypted file: the key comes in the form body, and the file is
/// decrypted while it is sent.
#[post("/api/files/{id}")]
async fn api_file_download_with_key(
    req: HttpRequest,
    path: web::Path<String>,
    form: web::Form<FileKeyForm>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(key) = FileKey::decode(&form.key) else {
        return Ok(invalid_key_response());
    };
    serve_download(req, &path.into_inner(), Some(&key), app_state).await
}

fn file_not_found_response() -> HttpResponse {
    HttpResponse::NotFound().json(json!({ "error": "File not found" }))
}

fn not_yet_available_response(valid_from: i64) -> HttpResponse {
    HttpResponse::Forbidden()
        .json(json!({ "error": "File not available yet", "valid_from": valid_from }))
}

fn wrong_key_response() -> HttpResponse {
    HttpResponse::Forbidden().json(json!({ "error": "Wrong key" }))
}

/// Sends the whole file as an attachment. Range requests are not supported on purpose:
/// every GET is one counted download, so a download limit cannot be bypassed in pieces.
/// An encrypted file is refused here: its key must come through the POST route.
#[get("/api/files/{id}")]
async fn api_file_download(
    req: HttpRequest,
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    serve_download(req, &path.into_inner(), None, app_state).await
}

async fn serve_download(
    req: HttpRequest,
    raw_id: &str,
    key: Option<&FileKey>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.clone().into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));

    let Some(id) = parse_file_id(raw_id) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    let download = app_state
        .files
        .start_download(&id, key)
        .await
        .map_err(|e| {
            eprintln!("Cannot start download of {id}: {e:#}");
            actix_web::error::ErrorInternalServerError("Cannot read the file")
        })?;
    let (file, handle, decryption) = match download {
        Download::NotFound => return Ok(file_not_found_response()),
        Download::NotYetAvailable { valid_from } => {
            return Ok(not_yet_available_response(valid_from));
        }
        Download::KeyRequired => {
            return Ok(HttpResponse::Forbidden().json(json!({
                "error": "This file is encrypted: open its link and enter the key",
                "encrypted": true,
            })));
        }
        Download::WrongKey => return Ok(wrong_key_response()),
        Download::Ready {
            file,
            handle,
            decryption,
        } => (file, handle, decryption),
    };

    let event = json!({
        "action": "downloaded",
        "id": file.id,
        "name": file.name,
        "downloads": file.downloads,
        "max_downloads": file.max_downloads,
        "encrypted": file.is_encrypted(),
        "ip": crate::client_ip(&req).unwrap_or_else(|| "-".to_string()),
    });
    app_state
        .log_file
        .write_event(LogEventType::File(event))
        .await
        .unwrap_or_else(|e| println!("Failed to log file download: {}", e));

    Ok(attachment_response(&file, handle, decryption))
}

/// The whole file as a download that a browser saves and never renders, decrypted on the
/// way when `decryption` is given.
pub(crate) fn attachment_response(
    file: &SharedFile,
    handle: tokio::fs::File,
    decryption: Option<Box<Decryption>>,
) -> HttpResponse {
    let mut response = HttpResponse::Ok();
    response
        .content_type(mime::APPLICATION_OCTET_STREAM)
        .insert_header(attachment_header(&file.name))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("Content-Security-Policy", CONTENT_CSP))
        .no_chunking(file.size);
    match decryption {
        Some(decryption) => response.streaming(decrypted_chunks(handle, file.size, decryption)),
        None => response.streaming(file_chunks(handle).boxed_local()),
    }
}

/// What the upload page of a request shows.
#[get("/api/requests/{id}")]
async fn api_request_info(
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(id) = parse_file_id(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid request id" })));
    };
    let Some(request) = app_state.requests.get(&id).await else {
        return Ok(request_not_found_response());
    };
    // The settings may have lowered the per-file limit since the request was created.
    let max_file_size = request
        .max_file_size_bytes
        .min(app_state.settings.get().max_file_size_bytes);
    Ok(HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .json(json!({
            "title": request.title,
            "message": request.message,
            "max_file_size_bytes": max_file_size,
            "extensions": request.extensions,
            "files_left": request.files_left(),
            "require_name": request.require_name,
        })))
}

#[derive(Deserialize)]
struct RequestUploadQuery {
    name: String,
    uploader: Option<String>,
}

fn request_not_found_response() -> HttpResponse {
    HttpResponse::NotFound()
        .json(json!({ "error": "This upload link does not exist or was closed" }))
}

/// Upload of one file to a request: the raw bytes are the body, the file name and the
/// uploader's name are in the query string. The file is encrypted for the admin and only
/// the admin can download it.
#[post("/api/requests/{id}/files")]
async fn api_request_upload(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Payload,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(id) = parse_file_id(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid request id" })));
    };
    let slot = match app_state.requests.begin_upload(&id).await {
        Ok(slot) => slot,
        Err(SlotError::NotFound) => return Ok(request_not_found_response()),
        Err(SlotError::Full) => {
            return Ok(HttpResponse::Gone().json(
                json!({ "error": "This upload link has received all the files it accepts" }),
            ));
        }
    };
    let request = slot.request().clone();

    let query = match web::Query::<RequestUploadQuery>::from_query(req.query_string()) {
        Ok(query) => query.into_inner(),
        Err(e) => return Ok(HttpResponse::BadRequest().json(json!({ "error": format!("{e}") }))),
    };
    let uploader = match clean_uploader(query.uploader.as_deref(), request.require_name) {
        Ok(uploader) => uploader,
        Err(message) => return Ok(HttpResponse::BadRequest().json(json!({ "error": message }))),
    };
    let Some(name) = crate::files::clean_file_name(&query.name) else {
        return Ok(
            HttpResponse::BadRequest().json(json!({ "error": "File name is missing or too long" }))
        );
    };
    if !request.allows(&name) {
        return Ok(HttpResponse::UnsupportedMediaType().json(json!({
            "error": format!("This file type is not accepted. Allowed: {}", request.extensions.join(", "))
        })));
    }
    let Some(length) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Ok(
            HttpResponse::LengthRequired().json(json!({ "error": "Content-Length is required" }))
        );
    };
    let settings = app_state.settings.get();
    let max_file_size = request
        .max_file_size_bytes
        .min(settings.max_file_size_bytes);
    if length > max_file_size {
        return Ok(HttpResponse::PayloadTooLarge()
            .json(json!({ "error": format!("The file is larger than {max_file_size} bytes") })));
    }

    // Every received file is encrypted for the admin: the uploader never sees a key.
    let Some(public_key) = app_state.admin.public_key().await else {
        eprintln!("Upload request {id}: the admin has no encryption keys yet");
        return Ok(HttpResponse::ServiceUnavailable()
            .json(json!({ "error": "This upload link cannot accept files right now" })));
    };
    let key = match FileKey::generate()
        .and_then(|key| wrap_file_key(&public_key, &key).map(|wrapped| (key, wrapped)))
    {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("Cannot create a file key: {e:#}");
            return Ok(
                HttpResponse::InternalServerError().json(json!({ "error": "Upload failed" }))
            );
        }
    };
    let ip = crate::client_ip(&req);
    let new = NewFile {
        name,
        duration_minutes: 0,
        valid_from: None,
        max_downloads: None,
        received: Some(Received {
            request_id: request.id,
            request_title: request.title.clone(),
            uploader: uploader.clone(),
            ip: ip.clone(),
        }),
    };
    let encryption = Some(FileEncryption {
        key: &key.0,
        wrapped: key.1.clone(),
    });
    let file = match app_state
        .files
        .add(new, length, payload, &settings, encryption)
        .await
    {
        Ok(file) => file,
        Err(FileError::InvalidInput(message)) => {
            return Ok(HttpResponse::BadRequest().json(json!({ "error": message })));
        }
        Err(FileError::TooLarge) => {
            return Ok(HttpResponse::PayloadTooLarge().json(
                json!({ "error": format!("The file is larger than {max_file_size} bytes") }),
            ));
        }
        Err(FileError::StorageFull) => {
            return Ok(HttpResponse::InsufficientStorage()
                .json(json!({ "error": "There is no space left for this file" })));
        }
        Err(FileError::LengthMismatch) => {
            return Ok(HttpResponse::BadRequest().json(
                json!({ "error": "The upload was interrupted or does not match its size" }),
            ));
        }
        Err(FileError::Internal(e)) => {
            eprintln!("Request upload failed: {e:#}");
            return Ok(
                HttpResponse::InternalServerError().json(json!({ "error": "Upload failed" }))
            );
        }
    };
    if let Err(e) = slot.complete().await {
        // The file is stored; only the counter could not be saved.
        eprintln!("Cannot count the upload to request {id}: {e:#}");
    }

    let event = json!({
        "action": "received",
        "id": file.id,
        "name": file.name,
        "size": file.size,
        "request_id": request.id,
        "uploader": uploader,
        "ip": ip.unwrap_or_else(|| "-".to_string()),
    });
    app_state
        .log_file
        .write_event(LogEventType::File(event))
        .await
        .unwrap_or_else(|e| println!("Failed to log a received file: {}", e));

    Ok(HttpResponse::Created().json(json!({ "name": file.name, "size": file.size })))
}

/// `attachment` with an ASCII fallback name plus the exact UTF-8 name (RFC 6266), so every
/// browser saves the file instead of showing it, under a sensible name.
fn attachment_header(name: &str) -> header::ContentDisposition {
    let ascii: String =
        name.chars()
            .map(|c| {
                if c.is_ascii() && !c.is_ascii_control() && c != '"' && c != '\\' { c } else { '_' }
            })
            .collect();
    header::ContentDisposition {
        disposition: header::DispositionType::Attachment,
        parameters: vec![
            header::DispositionParam::Filename(ascii),
            header::DispositionParam::FilenameExt(header::ExtendedValue {
                charset: header::Charset::Ext("UTF-8".to_string()),
                language_tag: None,
                value: name.as_bytes().to_vec(),
            }),
        ],
    }
}

const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

/// Reads the file in chunks. After a read error the stream ends, which aborts the response.
fn file_chunks(
    file: tokio::fs::File,
) -> impl futures::Stream<Item = Result<web::Bytes, std::io::Error>> + 'static {
    futures::stream::unfold(Some(file), |file| async move {
        let mut file = file?;
        let mut buffer = vec![0; DOWNLOAD_CHUNK_BYTES];
        match tokio::io::AsyncReadExt::read(&mut file, &mut buffer).await {
            Ok(0) => None,
            Ok(read) => {
                buffer.truncate(read);
                Some((Ok(web::Bytes::from(buffer)), Some(file)))
            }
            Err(e) => Some((Err(e), None)),
        }
    })
}

struct DecryptState {
    file: tokio::fs::File,
    cipher: ChunkCipher,
    plain_size: u64,
    /// Index of the next chunk to read from disk.
    next: u64,
    first_chunk: Option<Vec<u8>>,
}

/// Decrypts an encrypted file chunk by chunk, starting with the first chunk that was
/// decrypted to check the key. A chunk that fails to decrypt (the file was changed on disk)
/// ends the stream with an error, which aborts the response: the downloader never gets a
/// silently corrupted file.
fn decrypted_chunks(
    file: tokio::fs::File,
    plain_size: u64,
    decryption: Box<Decryption>,
) -> futures::stream::LocalBoxStream<'static, Result<web::Bytes, std::io::Error>> {
    let state = DecryptState {
        file,
        cipher: decryption.cipher,
        plain_size,
        next: 1,
        first_chunk: Some(decryption.first_chunk),
    };
    futures::stream::unfold(Some(state), |state| async move {
        let mut state = state?;
        if let Some(first) = state.first_chunk.take() {
            return Some((Ok(web::Bytes::from(first)), Some(state)));
        }
        let count = chunk_count(state.plain_size);
        if state.next >= count {
            return None;
        }
        let index = state.next;
        let mut chunk = vec![0; plain_chunk_len(state.plain_size, index) + TAG_BYTES];
        if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut state.file, &mut chunk).await {
            return Some((Err(e), None));
        }
        if state
            .cipher
            .open(index, index + 1 == count, &mut chunk)
            .is_err()
        {
            eprintln!("Chunk {index} of an encrypted file does not decrypt: the file is damaged");
            return Some((
                Err(std::io::Error::other("encrypted file is damaged")),
                None,
            ));
        }
        state.next += 1;
        Some((Ok(web::Bytes::from(chunk)), Some(state)))
    })
    .boxed_local()
}
