//! Admin control panel API. Every route here lives under `/api/admin` and, except for
//! status, setup and login, requires an authenticated admin session.

use std::collections::HashMap;

use actix_session::{
    Session, SessionMiddleware, config::PersistentSession, storage::CookieSessionStore,
};
use actix_web::{
    HttpRequest, HttpResponse,
    cookie::{Key, SameSite, time::Duration},
    delete,
    error::{ErrorInternalServerError, ErrorUnauthorized},
    get,
    middleware::DefaultHeaders,
    post, put, web,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    auth::AuthError,
    crypto::{FileKey, unwrap_file_key, wrap_file_key},
    data_mgt::{AppState, log_removed_assets},
    files::{FileEncryption, FileError, NewFile, SharedFile},
    logs::{LogEventType, LogLimits},
    requests::{CreateError, NewRequest, UploadRequest},
    settings::{FieldError, Settings, UpdateError},
    throttle::{client_key, retry_after_secs},
};

pub const SESSION_COOKIE_NAME: &str = "bhs_admin";

/// Settings read only at startup: a new value needs a restart.
const RESTART_FIELDS: &[&str] = &[
    "bind_addr",
    "bind_port",
    "admin_session_max_age_minutes",
    "tls_mode",
    "tls_cert_path",
    "tls_key_path",
    "https_port",
];

const SESSION_USER: &str = "admin_user";
const SESSION_VERSION: &str = "admin_version";
const SESSION_ISSUED_AT: &str = "admin_issued_at";

#[derive(Clone)]
pub struct SessionSettings {
    pub key: Key,
    /// Send the cookie only over HTTPS. Disable only for plain-HTTP setups.
    pub cookie_secure: bool,
    /// Hard limit on a login. The cookie store cannot revoke a cookie, so the server
    /// checks the issue time itself instead of trusting the cookie's Max-Age.
    pub max_age_secs: i64,
}

/// Registers the admin API. The session middleware wraps only this scope, so public
/// routes never set or read a session cookie.
pub fn configure(cfg: &mut web::ServiceConfig, settings: &SessionSettings) {
    let sessions = SessionMiddleware::builder(CookieSessionStore::default(), settings.key.clone())
        .cookie_name(SESSION_COOKIE_NAME.to_string())
        .cookie_path("/api/admin".to_string())
        .cookie_secure(settings.cookie_secure)
        .cookie_http_only(true)
        // Strict keeps the cookie off every cross-site request, which blocks CSRF.
        .cookie_same_site(SameSite::Strict)
        .session_lifecycle(
            PersistentSession::default().session_ttl(Duration::seconds(settings.max_age_secs)),
        )
        .build();

    cfg.service(
        web::scope("/api/admin")
            .wrap(sessions)
            // Responses carry private data (IPs, session state): never cache them.
            .wrap(DefaultHeaders::new().add(("Cache-Control", "no-store")))
            .service(status)
            .service(setup)
            .service(login)
            .service(logout)
            .service(change_password)
            .service(list_assets)
            .service(delete_asset)
            .service(stats)
            .service(get_settings)
            .service(update_settings)
            .service(upload_file)
            .service(list_files)
            .service(reveal_file_key)
            .service(restart_server)
            .service(create_request)
            .service(list_requests)
            .service(delete_request)
            .service(list_received)
            .service(check_received_password)
            .service(download_received)
            .service(delete_received)
            .service(delete_file),
    );
}

#[derive(Deserialize)]
struct CredentialsRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct PasswordChangeRequest {
    current_password: String,
    new_password: String,
}

#[get("/status")]
async fn status(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = current_admin(&session, &app_state).await?;
    Ok(HttpResponse::Ok().json(json!({
        "configured": app_state.admin.is_configured().await,
        "authenticated": username.is_some(),
        "username": username,
        "started_at": *crate::STARTED_AT,
    })))
}

#[post("/setup")]
async fn setup(
    req: HttpRequest,
    session: Session,
    body: web::Json<CredentialsRequest>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    match app_state.admin.setup(&body.username, &body.password).await {
        Ok(version) => {
            start_session(&session, &body.username, version)?;
            log_admin(
                &app_state,
                &req,
                "setup",
                json!({ "username": body.username }),
            )
            .await;
            Ok(HttpResponse::Ok().json(json!({ "username": body.username })))
        }
        Err(e) => Ok(auth_error_response(e)),
    }
}

#[post("/login")]
async fn login(
    req: HttpRequest,
    session: Session,
    body: web::Json<CredentialsRequest>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    if let Some(response) = locked_out(&app_state, &req) {
        return Ok(response);
    }
    match app_state.admin.verify(&body.username, &body.password).await {
        Ok(version) => {
            right_password(&app_state, &req);
            start_session(&session, &body.username, version)?;
            log_admin(
                &app_state,
                &req,
                "login",
                json!({ "username": body.username }),
            )
            .await;
            Ok(HttpResponse::Ok().json(json!({ "username": body.username })))
        }
        Err(e) => {
            if matches!(e, AuthError::InvalidCredentials) {
                log_admin(
                    &app_state,
                    &req,
                    "login_failed",
                    json!({ "username": body.username }),
                )
                .await;
                if let Some(response) = wrong_password(&app_state, &req) {
                    return Ok(response);
                }
            }
            Ok(auth_error_response(e))
        }
    }
}

#[post("/logout")]
async fn logout(
    req: HttpRequest,
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    // Only a valid session may revoke sessions; otherwise anyone could log the admin out.
    if let Some(username) = current_admin(&session, &app_state).await? {
        session.purge();
        if let Err(e) = app_state.admin.revoke_sessions().await {
            return Ok(auth_error_response(e));
        }
        log_admin(&app_state, &req, "logout", json!({ "username": username })).await;
    } else {
        session.purge();
    }
    Ok(HttpResponse::NoContent().finish())
}

#[post("/password")]
async fn change_password(
    req: HttpRequest,
    session: Session,
    body: web::Json<PasswordChangeRequest>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    if let Some(response) = locked_out(&app_state, &req) {
        return Ok(response);
    }
    match app_state
        .admin
        .change_password(&body.current_password, &body.new_password)
        .await
    {
        Ok(version) => {
            right_password(&app_state, &req);
            // Every other session now carries an old version and is rejected;
            // this one is reissued so the admin who changed it stays logged in.
            start_session(&session, &username, version)?;
            log_admin(
                &app_state,
                &req,
                "password_changed",
                json!({ "username": username }),
            )
            .await;
            Ok(HttpResponse::NoContent().finish())
        }
        Err(AuthError::InvalidCredentials) => {
            if let Some(response) = wrong_password(&app_state, &req) {
                return Ok(response);
            }
            Ok(HttpResponse::Forbidden().json(json!({ "error": "Current password is incorrect" })))
        }
        Err(e) => Ok(auth_error_response(e)),
    }
}

#[derive(Serialize)]
struct AdminAssetItem {
    id: Uuid,
    mime: String,
    size_bytes: usize,
    created_at: i64,
    expires_at: i64,
    uploader_ip: Option<String>,
}

#[get("/assets")]
async fn list_assets(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    let items: Vec<AdminAssetItem> = app_state
        .assets
        .active_list()
        .await
        .iter()
        .map(|asset| AdminAssetItem {
            id: asset.id(),
            mime: asset.mime(),
            size_bytes: asset.size_bytes(),
            created_at: asset.created_at(),
            expires_at: asset.expires_at(),
            uploader_ip: asset.uploader_ip().map(str::to_string),
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

#[delete("/assets/{id}")]
async fn delete_asset(
    req: HttpRequest,
    session: Session,
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let Ok(id) = Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid asset id" })));
    };
    let Some(asset) = app_state.assets.remove_asset(&id).await else {
        return Ok(HttpResponse::NotFound().json(json!({ "error": "Asset not found" })));
    };

    // The upload no longer counts against its uploader's limit.
    if let Some(ip) = asset.uploader_ip() {
        app_state
            .connection_tracker
            .release(ip, asset.expires_at())
            .await;
    }
    log_removed_assets(std::slice::from_ref(&asset), &app_state.log_file).await;
    log_admin(
        &app_state,
        &req,
        "asset_deleted",
        json!({ "username": username, "asset_id": id }),
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}

#[derive(Serialize, Default)]
struct UploaderStats {
    ip: String,
    active_assets: usize,
    bytes: usize,
}

#[get("/stats")]
async fn stats(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    let assets = app_state.assets.active_list().await;
    let log_stats = app_state.log_file.stats().await;
    let settings = app_state.settings.get();
    let (file_count, file_bytes) = app_state.files.usage().await;
    let file_usage = app_state.files.usage_by_kind().await;
    let requests = app_state.requests.list().await;
    let now = chrono::Utc::now().timestamp_millis();
    let open_requests = requests.iter().filter(|r| r.is_open(now)).count();

    let mut by_ip: HashMap<String, UploaderStats> = HashMap::new();
    for asset in &assets {
        let ip = asset.uploader_ip().unwrap_or("unknown").to_string();
        let entry = by_ip.entry(ip.clone()).or_insert_with(|| UploaderStats {
            ip,
            ..Default::default()
        });
        entry.active_assets += 1;
        entry.bytes += asset.size_bytes();
    }
    let mut uploaders: Vec<UploaderStats> = by_ip.into_values().collect();
    uploaders.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.ip.cmp(&b.ip)));

    Ok(HttpResponse::Ok().json(json!({
        "active_assets": assets.len(),
        "storage_bytes": assets.iter().map(|a| a.size_bytes()).sum::<usize>(),
        "max_assets": settings.max_assets,
        "max_storage_bytes": settings.max_total_storage_bytes,
        "max_uploads_per_ip": settings.max_uploads_per_ip,
        "files": file_count,
        "files_bytes": file_bytes,
        "max_files_bytes": settings.max_files_total_bytes,
        "shared_files": file_usage.shared_files,
        "shared_bytes": file_usage.shared_bytes,
        "received_files": file_usage.received_files,
        "received_bytes": file_usage.received_bytes,
        "requests": requests.len(),
        "open_requests": open_requests,
        "total_uploads": log_stats.total_uploads,
        "total_deleted": log_stats.total_deleted,
        "total_requests": log_stats.total_requests,
        "uploaders": uploaders,
    })))
}

#[derive(Deserialize)]
struct FileUploadQuery {
    name: String,
    duration_minutes: u32,
    max_downloads: Option<u32>,
    /// Unix time in milliseconds.
    valid_from: Option<i64>,
    /// Encrypt the file with a new random key, returned once in the response.
    #[serde(default)]
    encrypt: bool,
}

/// A shared file as the admin sees it. The wrapped key stays on the server.
#[derive(Serialize)]
struct AdminFileItem {
    id: Uuid,
    name: String,
    size: u64,
    created_at: i64,
    valid_from: Option<i64>,
    expires_at: i64,
    max_downloads: Option<u32>,
    downloads: u32,
    encrypted: bool,
    link: String,
    /// Only in the upload response of an encrypted file.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

impl From<SharedFile> for AdminFileItem {
    fn from(file: SharedFile) -> Self {
        Self {
            id: file.id,
            link: format!("/f/{}", file.id),
            encrypted: file.is_encrypted(),
            name: file.name,
            size: file.size,
            created_at: file.created_at,
            valid_from: file.valid_from,
            expires_at: file.expires_at,
            max_downloads: file.max_downloads,
            downloads: file.downloads,
            key: None,
        }
    }
}

#[derive(Deserialize)]
struct RevealKeyRequest {
    password: String,
}

/// Upload of one file: the raw bytes are the body, the details are in the query string.
/// Content-Length is required, so the disk space can be reserved before writing.
#[post("/files")]
async fn upload_file(
    req: HttpRequest,
    session: Session,
    payload: web::Payload,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let query = match web::Query::<FileUploadQuery>::from_query(req.query_string()) {
        Ok(query) => query.into_inner(),
        Err(e) => {
            return Ok(HttpResponse::BadRequest().json(json!({ "error": format!("{e}") })));
        }
    };
    let Some(length) = req
        .headers()
        .get(actix_web::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return Ok(
            HttpResponse::LengthRequired().json(json!({ "error": "Content-Length is required" }))
        );
    };

    // The key exists only in memory until the response; on disk it is stored wrapped for
    // the admin's public key.
    let key = if query.encrypt {
        let Some(public_key) = app_state.admin.public_key().await else {
            return Ok(HttpResponse::Conflict().json(json!({
                "error": "Encryption keys are not set up yet: log out and log in again"
            })));
        };
        let wrapped = FileKey::generate()
            .and_then(|key| wrap_file_key(&public_key, &key).map(|wrapped| (key, wrapped)));
        match wrapped {
            Ok(pair) => Some(pair),
            Err(e) => {
                eprintln!("Cannot create a file key: {e:#}");
                return Ok(HttpResponse::InternalServerError()
                    .json(json!({ "error": "Cannot create the encryption key" })));
            }
        }
    } else {
        None
    };
    let encryption = key.as_ref().map(|(key, wrapped)| FileEncryption {
        key,
        wrapped: wrapped.clone(),
    });

    let settings = app_state.settings.get();
    let new = NewFile {
        name: query.name,
        duration_minutes: query.duration_minutes,
        valid_from: query.valid_from,
        max_downloads: query.max_downloads,
        received: None,
    };
    match app_state
        .files
        .add(new, length, payload, &settings, encryption)
        .await
    {
        Ok(file) => {
            log_admin(
                &app_state,
                &req,
                "file_uploaded",
                json!({
                    "username": username,
                    "file_id": file.id,
                    "name": file.name,
                    "size": file.size,
                    "encrypted": file.is_encrypted(),
                }),
            )
            .await;
            let mut item = AdminFileItem::from(file);
            item.key = key.map(|(key, _)| key.encode());
            Ok(HttpResponse::Created().json(item))
        }
        Err(FileError::InvalidInput(message)) => {
            Ok(HttpResponse::BadRequest().json(json!({ "error": message })))
        }
        Err(FileError::TooLarge) => Ok(HttpResponse::PayloadTooLarge().json(json!({
            "error": format!("File is larger than {} bytes", settings.max_file_size_bytes)
        }))),
        Err(FileError::StorageFull) => Ok(HttpResponse::InsufficientStorage()
            .json(json!({ "error": "Not enough space left in the file storage budget" }))),
        Err(FileError::LengthMismatch) => Ok(HttpResponse::BadRequest()
            .json(json!({ "error": "The body does not match its Content-Length" }))),
        Err(FileError::Internal(e)) => {
            eprintln!("File upload failed: {e:#}");
            Ok(HttpResponse::InternalServerError().json(json!({ "error": "Upload failed" })))
        }
    }
}

#[get("/files")]
async fn list_files(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    let items: Vec<AdminFileItem> = app_state
        .files
        .list()
        .await
        .into_iter()
        .map(AdminFileItem::from)
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// Shows the key of an encrypted file again. Needs the admin password, which decrypts the
/// admin's private key: a stolen session cookie alone does not reveal any key.
#[post("/files/{id}/key")]
async fn reveal_file_key(
    req: HttpRequest,
    session: Session,
    path: web::Path<String>,
    body: web::Json<RevealKeyRequest>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let Ok(id) = Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    let Some(file) = app_state.files.get(&id).await else {
        return Ok(HttpResponse::NotFound().json(json!({ "error": "File not found" })));
    };
    let Some(wrapped) = file.wrapped_key.as_ref() else {
        return Ok(
            HttpResponse::BadRequest().json(json!({ "error": "This file is not encrypted" }))
        );
    };
    if let Some(response) = locked_out(&app_state, &req) {
        return Ok(response);
    }
    let secret = match app_state.admin.unlock(&body.password).await {
        Ok(secret) => {
            right_password(&app_state, &req);
            secret
        }
        Err(AuthError::InvalidCredentials) => {
            log_admin(
                &app_state,
                &req,
                "file_key_reveal_failed",
                json!({ "username": username, "file_id": file.id }),
            )
            .await;
            if let Some(response) = wrong_password(&app_state, &req) {
                return Ok(response);
            }
            return Ok(HttpResponse::Forbidden().json(json!({ "error": "Password is incorrect" })));
        }
        Err(e) => return Ok(auth_error_response(e)),
    };
    match unwrap_file_key(&secret, wrapped) {
        Ok(key) => {
            log_admin(
                &app_state,
                &req,
                "file_key_revealed",
                json!({ "username": username, "file_id": file.id, "name": file.name }),
            )
            .await;
            Ok(HttpResponse::Ok().json(json!({ "key": key.encode() })))
        }
        Err(e) => {
            eprintln!("Cannot unwrap the key of file {id}: {e:#}");
            Ok(HttpResponse::InternalServerError()
                .json(json!({ "error": "Cannot read the file key" })))
        }
    }
}

/// Restarts the server, to apply settings read at startup. The response is sent before the
/// server stops: the stop waits for requests in progress.
#[post("/restart")]
async fn restart_server(
    req: HttpRequest,
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    log_admin(
        &app_state,
        &req,
        "server_restart",
        json!({ "username": username, "restart_pending": settings_response(&app_state)["restart_pending"] }),
    )
    .await;
    app_state.restart.request();
    Ok(HttpResponse::Accepted().json(json!({ "restarting": true })))
}

#[derive(Serialize)]
struct AdminRequestItem {
    #[serde(flatten)]
    request: UploadRequest,
    files_left: Option<u32>,
    link: String,
}

impl From<UploadRequest> for AdminRequestItem {
    fn from(request: UploadRequest) -> Self {
        Self {
            files_left: request.files_left(),
            link: format!("/r/{}", request.id),
            request,
        }
    }
}

#[post("/requests")]
async fn create_request(
    req: HttpRequest,
    session: Session,
    body: web::Json<NewRequest>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let settings = app_state.settings.get();
    match app_state
        .requests
        .create(
            body.into_inner(),
            settings.max_file_size_bytes,
            settings.max_files_total_bytes,
        )
        .await
    {
        Ok(request) => {
            log_admin(
                &app_state,
                &req,
                "request_created",
                json!({ "username": username, "request_id": request.id, "title": request.title }),
            )
            .await;
            Ok(HttpResponse::Created().json(AdminRequestItem::from(request)))
        }
        Err(CreateError::Invalid(message)) => {
            Ok(HttpResponse::BadRequest().json(json!({ "error": message })))
        }
        Err(CreateError::Internal(e)) => {
            eprintln!("Cannot create an upload request: {e:#}");
            Ok(HttpResponse::InternalServerError()
                .json(json!({ "error": "Cannot create the request" })))
        }
    }
}

#[get("/requests")]
async fn list_requests(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    let items: Vec<AdminRequestItem> = app_state
        .requests
        .list()
        .await
        .into_iter()
        .map(AdminRequestItem::from)
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

/// Closes a request: its link stops accepting files. Files already received stay.
#[delete("/requests/{id}")]
async fn delete_request(
    req: HttpRequest,
    session: Session,
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let Ok(id) = Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid request id" })));
    };
    match app_state.requests.remove(&id).await {
        Ok(Some(request)) => {
            log_admin(
                &app_state,
                &req,
                "request_closed",
                json!({ "username": username, "request_id": request.id, "title": request.title }),
            )
            .await;
            Ok(HttpResponse::NoContent().finish())
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(json!({ "error": "Request not found" }))),
        Err(e) => {
            eprintln!("Cannot delete request {id}: {e:#}");
            Ok(HttpResponse::InternalServerError().json(json!({ "error": "Delete failed" })))
        }
    }
}

/// A file received through a request, as the admin sees it.
#[derive(Serialize)]
struct ReceivedItem {
    id: Uuid,
    name: String,
    size: u64,
    received_at: i64,
    request_id: Uuid,
    request_title: String,
    uploader: Option<String>,
    ip: Option<String>,
}

#[get("/received")]
async fn list_received(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    let items: Vec<ReceivedItem> = app_state
        .files
        .list_received()
        .await
        .into_iter()
        .filter_map(|file| {
            let received = file.received?;
            Some(ReceivedItem {
                id: file.id,
                name: file.name,
                size: file.size,
                received_at: file.created_at,
                request_id: received.request_id,
                request_title: received.request_title,
                uploader: received.uploader,
                ip: received.ip,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(items))
}

#[derive(Deserialize)]
struct PasswordForm {
    password: String,
}

/// Checks the password before a download, so a wrong one shows a message in the page
/// instead of an error page.
#[post("/received/check")]
async fn check_received_password(
    req: HttpRequest,
    session: Session,
    body: web::Json<PasswordForm>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    if let Some(response) = locked_out(&app_state, &req) {
        return Ok(response);
    }
    match app_state.admin.unlock(&body.password).await {
        Ok(_) => {
            right_password(&app_state, &req);
            Ok(HttpResponse::NoContent().finish())
        }
        Err(AuthError::InvalidCredentials) => {
            if let Some(response) = wrong_password(&app_state, &req) {
                return Ok(response);
            }
            Ok(HttpResponse::Forbidden().json(json!({ "error": "Password is incorrect" })))
        }
        Err(e) => Ok(auth_error_response(e)),
    }
}

/// Downloads a received file, decrypted on the way. The password comes in a form body, so
/// the browser can save the file straight to disk: it decrypts the admin's private key,
/// which unwraps the file key.
#[post("/received/{id}/download")]
async fn download_received(
    req: HttpRequest,
    session: Session,
    path: web::Path<String>,
    form: web::Form<PasswordForm>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let Ok(id) = Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    let Some(wrapped) = app_state
        .files
        .list_received()
        .await
        .into_iter()
        .find(|file| file.id == id)
        .and_then(|file| file.wrapped_key)
    else {
        return Ok(HttpResponse::NotFound().json(json!({ "error": "File not found" })));
    };
    if let Some(response) = locked_out(&app_state, &req) {
        return Ok(response);
    }
    let secret = match app_state.admin.unlock(&form.password).await {
        Ok(secret) => {
            right_password(&app_state, &req);
            secret
        }
        Err(AuthError::InvalidCredentials) => {
            if let Some(response) = wrong_password(&app_state, &req) {
                return Ok(response);
            }
            return Ok(HttpResponse::Forbidden().json(json!({ "error": "Password is incorrect" })));
        }
        Err(e) => return Ok(auth_error_response(e)),
    };
    let opened = unwrap_file_key(&secret, &wrapped).map_err(|e| e.context("cannot unwrap the key"));
    let opened = match opened {
        Ok(key) => app_state.files.open_received(&id, &key).await,
        Err(e) => Err(e),
    };
    match opened {
        Ok(Some((file, handle, decryption))) => {
            log_admin(
                &app_state,
                &req,
                "received_downloaded",
                json!({ "username": username, "file_id": file.id, "name": file.name }),
            )
            .await;
            Ok(crate::api::attachment_response(
                &file,
                handle,
                Some(decryption),
            ))
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(json!({ "error": "File not found" }))),
        Err(e) => {
            eprintln!("Cannot open received file {id}: {e:#}");
            Ok(
                HttpResponse::InternalServerError()
                    .json(json!({ "error": "Cannot read the file" })),
            )
        }
    }
}

#[delete("/received/{id}")]
async fn delete_received(
    req: HttpRequest,
    session: Session,
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let Ok(id) = Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    match app_state.files.remove(&id, true).await {
        Ok(Some(file)) => {
            log_admin(
                &app_state,
                &req,
                "received_deleted",
                json!({ "username": username, "file_id": file.id, "name": file.name }),
            )
            .await;
            Ok(HttpResponse::NoContent().finish())
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(json!({ "error": "File not found" }))),
        Err(e) => {
            eprintln!("Cannot delete received file {id}: {e:#}");
            Ok(HttpResponse::InternalServerError().json(json!({ "error": "Delete failed" })))
        }
    }
}

#[delete("/files/{id}")]
async fn delete_file(
    req: HttpRequest,
    session: Session,
    path: web::Path<String>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let Ok(id) = Uuid::parse_str(&path.into_inner()) else {
        return Ok(HttpResponse::BadRequest().json(json!({ "error": "Invalid file id" })));
    };
    match app_state.files.remove(&id, false).await {
        Ok(Some(file)) => {
            log_admin(
                &app_state,
                &req,
                "file_deleted",
                json!({ "username": username, "file_id": file.id, "name": file.name }),
            )
            .await;
            Ok(HttpResponse::NoContent().finish())
        }
        Ok(None) => Ok(HttpResponse::NotFound().json(json!({ "error": "File not found" }))),
        Err(e) => {
            eprintln!("Cannot delete file {id}: {e:#}");
            Ok(HttpResponse::InternalServerError().json(json!({ "error": "Delete failed" })))
        }
    }
}

#[get("/settings")]
async fn get_settings(
    session: Session,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    require_admin(&session, &app_state).await?;
    Ok(HttpResponse::Ok().json(settings_response(&app_state)))
}

/// Replaces every setting at once. The body must list all fields: a missing one is an
/// error instead of a silent reset to its default.
#[put("/settings")]
async fn update_settings(
    req: HttpRequest,
    session: Session,
    body: web::Json<Value>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let username = require_admin(&session, &app_state).await?;
    let new = match parse_settings(body.into_inner()) {
        Ok(settings) => settings,
        Err(errors) => return Ok(invalid_settings_response(errors)),
    };

    match app_state.settings.update(new.clone()).await {
        Ok(previous) => {
            app_state.log_file.set_limits(LogLimits::from(&new)).await;
            log_admin(
                &app_state,
                &req,
                "settings_changed",
                json!({ "username": username, "changes": setting_changes(&previous, &new) }),
            )
            .await;
            Ok(HttpResponse::Ok().json(settings_response(&app_state)))
        }
        Err(UpdateError::Invalid(errors)) => Ok(invalid_settings_response(errors)),
        Err(UpdateError::Internal(e)) => {
            eprintln!("Cannot save settings: {e:#}");
            Ok(
                HttpResponse::InternalServerError()
                    .json(json!({ "error": "Cannot save settings" })),
            )
        }
    }
}

/// Checks every field on its own, so one bad value (say, a malformed IP) does not hide
/// the errors of the others, and each error names its field.
fn parse_settings(body: Value) -> Result<Settings, Vec<FieldError>> {
    let error = |field: &str, message: String| FieldError {
        field: field.to_string(),
        message,
    };
    let Value::Object(body) = body else {
        return Err(vec![error("body", "must be a JSON object".into())]);
    };
    let names = setting_names();
    let mut errors: Vec<FieldError> = body
        .keys()
        .filter(|name| !names.contains(name))
        .map(|name| error(name, "is not a known setting".into()))
        .collect();

    let mut valid = serde_json::Map::new();
    for name in &names {
        let Some(value) = body.get(name) else {
            errors.push(error(name, "is required".into()));
            continue;
        };
        // Missing fields take their default, so this checks only the type of `name`.
        let single = Value::Object([(name.clone(), value.clone())].into_iter().collect());
        match serde_json::from_value::<Settings>(single) {
            Ok(_) => {
                valid.insert(name.clone(), value.clone());
            }
            Err(e) => errors.push(error(name, e.to_string())),
        }
    }

    let settings: Settings = serde_json::from_value(Value::Object(valid))
        .map_err(|e| vec![error("body", e.to_string())])?;
    // Range rules for fields that already failed the type check would only repeat it.
    let failed: Vec<String> = errors.iter().map(|e| e.field.clone()).collect();
    errors.extend(
        settings
            .validate()
            .into_iter()
            .filter(|e| !failed.contains(&e.field)),
    );
    if errors.is_empty() { Ok(settings) } else { Err(errors) }
}

fn invalid_settings_response(errors: Vec<FieldError>) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({ "error": "Invalid settings", "fields": errors }))
}

/// `current` is what the file holds, `running` what the server started with, `defaults` what
/// a fresh install uses. Restart-only fields that differ between `current` and `running` are
/// listed in `restart_pending`.
fn settings_response(app_state: &AppState) -> Value {
    let current = app_state.settings.get();
    let running = app_state.settings.running();
    let current_value = settings_value(&current);
    let running_value = settings_value(running);
    let restart_pending: Vec<&str> = RESTART_FIELDS
        .iter()
        .copied()
        .filter(|name| current_value.get(*name) != running_value.get(*name))
        .collect();
    json!({
        "current": current_value,
        "running": running_value,
        "defaults": settings_value(&Settings::default()),
        "restart_fields": RESTART_FIELDS,
        "restart_pending": restart_pending,
        "locked": app_state.settings.locked(),
        "tls": *app_state.tls_status,
    })
}

fn settings_value(settings: &Settings) -> Value {
    serde_json::to_value(settings).unwrap_or(Value::Null)
}

/// Field names as they appear in JSON, taken from the serialized struct so the list
/// cannot drift from `Settings`.
fn setting_names() -> Vec<String> {
    match settings_value(&Settings::default()) {
        Value::Object(map) => map.into_iter().map(|(name, _)| name).collect(),
        _ => Vec::new(),
    }
}

/// `{field: {from, to}}` for every field that changed, for the admin log.
fn setting_changes(previous: &Settings, new: &Settings) -> Value {
    let (Value::Object(before), Value::Object(after)) =
        (settings_value(previous), settings_value(new))
    else {
        return Value::Null;
    };
    let changes: serde_json::Map<String, Value> = after
        .into_iter()
        .filter(|(name, value)| before.get(name) != Some(value))
        .map(|(name, value)| {
            let from = before.get(&name).cloned().unwrap_or(Value::Null);
            (name, json!({ "from": from, "to": value }))
        })
        .collect();
    Value::Object(changes)
}

fn start_session(session: &Session, username: &str, version: u64) -> actix_web::Result<()> {
    // A fresh session at login prevents session fixation.
    session.renew();
    session
        .insert(SESSION_USER, username)
        .and_then(|_| session.insert(SESSION_VERSION, version))
        .and_then(|_| session.insert(SESSION_ISSUED_AT, Utc::now().timestamp()))
        .map_err(ErrorInternalServerError)
}

/// The logged-in admin, or `None`. A session that is too old or predates a password
/// change is purged so the browser drops the cookie.
async fn current_admin(
    session: &Session,
    app_state: &AppState,
) -> actix_web::Result<Option<String>> {
    let read = || -> Result<Option<(String, u64, i64)>, actix_session::SessionGetError> {
        Ok(
            match (
                session.get::<String>(SESSION_USER)?,
                session.get::<u64>(SESSION_VERSION)?,
                session.get::<i64>(SESSION_ISSUED_AT)?,
            ) {
                (Some(user), Some(version), Some(issued_at)) => Some((user, version, issued_at)),
                _ => None,
            },
        )
    };
    let Some((username, version, issued_at)) = read().map_err(ErrorInternalServerError)? else {
        return Ok(None);
    };

    let age = Utc::now().timestamp() - issued_at;
    let max_age = app_state.settings.running().admin_session_max_age_secs();
    let fresh = (0..max_age).contains(&age);
    if fresh && app_state.admin.session_is_current(&username, version).await {
        Ok(Some(username))
    } else {
        session.purge();
        Ok(None)
    }
}

async fn require_admin(session: &Session, app_state: &AppState) -> actix_web::Result<String> {
    current_admin(session, app_state)
        .await?
        .ok_or_else(|| ErrorUnauthorized("Login required"))
}

fn auth_error_response(error: AuthError) -> HttpResponse {
    match error {
        AuthError::AlreadyConfigured => {
            HttpResponse::Conflict().json(json!({ "error": "Admin credentials already exist" }))
        }
        AuthError::NotConfigured => {
            HttpResponse::Conflict().json(json!({ "error": "Admin setup required" }))
        }
        AuthError::InvalidCredentials => {
            HttpResponse::Unauthorized().json(json!({ "error": "Invalid username or password" }))
        }
        AuthError::InvalidInput(message) => {
            HttpResponse::BadRequest().json(json!({ "error": message }))
        }
        AuthError::Internal(e) => {
            eprintln!("Admin credential error: {e:#}");
            HttpResponse::InternalServerError().json(json!({ "error": "Internal error" }))
        }
    }
}

// ------------------------------------------------------------------ wrong passwords

/// Wrong passwords are counted per client (IPv6 per /64) on every route that checks the
/// admin password; after `max_login_failures` the client waits `login_lockout_minutes`.
fn password_client(req: &HttpRequest) -> String {
    client_key(&crate::client_ip(req).unwrap_or_else(|| "-".to_string()))
}

fn too_many_attempts(ms_left: i64) -> HttpResponse {
    let secs = retry_after_secs(ms_left);
    let minutes = (secs + 59) / 60;
    HttpResponse::TooManyRequests()
        .insert_header((actix_web::http::header::RETRY_AFTER, secs.to_string()))
        .json(json!({
            "error": format!("Too many wrong passwords. Try again in {minutes} minute(s)."),
            "retry_after_secs": secs,
        }))
}

/// `Some(429)` while this client is locked out: the password is not even checked.
fn locked_out(app_state: &AppState, req: &HttpRequest) -> Option<HttpResponse> {
    let now = Utc::now().timestamp_millis();
    app_state
        .login_throttle
        .check(&password_client(req), now)
        .err()
        .map(too_many_attempts)
}

/// Counts a wrong password. `Some(429)` when this one reached the limit.
fn wrong_password(app_state: &AppState, req: &HttpRequest) -> Option<HttpResponse> {
    let settings = app_state.settings.get();
    let now = Utc::now().timestamp_millis();
    let window = i64::from(settings.login_lockout_minutes) * 60_000;
    let client = password_client(req);
    let result = app_state
        .login_throttle
        .record(&client, now, settings.max_login_failures, window);
    match result {
        Ok(()) => None,
        Err(ms_left) => {
            eprintln!("Too many wrong admin passwords from {client}; locked out");
            Some(too_many_attempts(ms_left))
        }
    }
}

fn right_password(app_state: &AppState, req: &HttpRequest) {
    app_state.login_throttle.reset(&password_client(req));
}

async fn log_admin(app_state: &AppState, req: &HttpRequest, action: &str, details: Value) {
    let event = json!({
        "action": action,
        "ip": crate::client_ip(req).unwrap_or_else(|| "-".to_string()),
        "details": details,
    });
    if let Err(e) = app_state
        .log_file
        .write_event(LogEventType::Admin(event))
        .await
    {
        eprintln!("Failed to log admin action: {e}");
    }
}
