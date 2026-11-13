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
    post, web,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    MAX_ASSETS, MAX_TOTAL_STORAGE_BYTES, MAX_UPLOADS_PER_USER,
    auth::AuthError,
    data_mgt::{AppState, log_removed_assets},
    logs::LogEventType,
};

pub const SESSION_COOKIE_NAME: &str = "bhs_admin";
/// Hard limit on a login. The cookie store cannot revoke a cookie, so the server checks
/// the issue time itself instead of trusting the cookie's Max-Age.
pub const SESSION_MAX_AGE_SECS: i64 = 8 * 60 * 60;

const SESSION_USER: &str = "admin_user";
const SESSION_VERSION: &str = "admin_version";
const SESSION_ISSUED_AT: &str = "admin_issued_at";

#[derive(Clone)]
pub struct SessionSettings {
    pub key: Key,
    /// Send the cookie only over HTTPS. Disable only for plain-HTTP setups.
    pub cookie_secure: bool,
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
            PersistentSession::default().session_ttl(Duration::seconds(SESSION_MAX_AGE_SECS)),
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
            .service(stats),
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
    match app_state.admin.verify(&body.username, &body.password).await {
        Ok(version) => {
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
    match app_state
        .admin
        .change_password(&body.current_password, &body.new_password)
        .await
    {
        Ok(version) => {
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
        "max_assets": MAX_ASSETS,
        "max_storage_bytes": MAX_TOTAL_STORAGE_BYTES,
        "max_uploads_per_ip": MAX_UPLOADS_PER_USER,
        "total_uploads": log_stats.total_uploads,
        "total_deleted": log_stats.total_deleted,
        "total_requests": log_stats.total_requests,
        "uploaders": uploaders,
    })))
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
    let fresh = (0..SESSION_MAX_AGE_SECS).contains(&age);
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
