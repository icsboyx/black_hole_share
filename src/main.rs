mod admin;
mod crypto;
mod requests;
mod api;
mod auth;
mod data_mgt;
mod files;
mod logs;
mod settings;
#[cfg(test)]
mod tests;

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, get,
    http::StatusCode,
    middleware::DefaultHeaders,
    mime, route,
    web::{self},
};

use anyhow::Result;
use mime_guess::from_path;
use serde_json::Value;
use std::{
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub static HTML_DIR: &str = "data/html/";
pub static LOG_DIR: &str = "data/logs/";
// Admin secrets live outside data/html/ so they can never be served as static files.
pub static ADMIN_CREDENTIALS_FILE: &str = "data/admin/credentials.json";
pub static SESSION_KEY_FILE: &str = "data/admin/session.key";
pub static SETTINGS_FILE: &str = "data/admin/settings.json";
pub static STORAGE_DIR: &str = "data/storage/";
pub static REQUESTS_FILE: &str = "data/storage/requests.json";
pub static LOG_FILE_NAME: &str = "log.txt";
// Limits and bind address now live in SETTINGS_FILE; these variables are no longer read.
static IGNORED_ENV_VARS: &[&str] = &["BIND_ADDR", "BIND_PORT", "TRUSTED_PROXIES"];

// SVG and HTML are excluded on purpose: both can run scripts when opened directly.
pub static ALLOWED_CONTENT_TYPES: &[&str] = &[
    "text/plain",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
];

// Uploaded content is never a page: block scripts even if a browser tries to render it.
pub static CONTENT_CSP: &str = "default-src 'none'; sandbox";

// 'unsafe-inline' is required by the inline scripts and styles in data/html/.
pub static PAGE_CSP: &str = "default-src 'self'; \
    script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; \
    style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; \
    img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; \
    frame-ancestors 'none'; form-action 'self'";
pub static FOOTER_HTML: LazyLock<String> = LazyLock::new(|| {
    fs::read_to_string(Path::new(HTML_DIR).join("footer.html")).unwrap_or_default()
});

pub static HTML_VARS: LazyLock<Vec<(&str, &str)>> = LazyLock::new(|| {
    vec![
        ("{{FOOTER}}", (*FOOTER_HTML).as_str()),
        ("{{VERSION}}", env!("CARGO_PKG_VERSION")),
    ]
});

pub static STATIC_PAGES: LazyLock<Vec<String>> = LazyLock::new(|| {
    fs::read_dir(HTML_DIR)
        .unwrap()
        .filter_map(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().to_str().map(|s| s.to_string()))
        })
        .collect()
});

use crate::{
    api::{
        api_file_check_key, api_file_download, api_file_download_with_key, api_file_info,
        api_get_asset, api_limits, api_request_info, api_request_upload, api_stats, api_upload,
    },
    data_mgt::AppState,
    logs::{LogEventType, LogFile},
};

#[get("/")]
async fn index(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "index.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/stats")]
async fn stats(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "stats.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/admin")]
async fn admin_page(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "admin.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/bhs/{id}")]
async fn view_asset(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "view.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/files")]
async fn files_page(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "files.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/f/{id}")]
async fn file_page(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "file.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

/// The page where someone uploads files for an upload request.
#[get("/r/{id}")]
async fn request_page(
    req: HttpRequest,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "request.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[route("/{tail:.*}", method = "GET", method = "POST")]
async fn catch_all(
    req: HttpRequest,
    _payload: Option<web::Json<Value>>,
    app_state: web::Data<AppState>,
) -> actix_web::Result<HttpResponse> {
    let response = match req.uri().path() {
        path if STATIC_PAGES.contains(&path[1..].into()) => {
            let file_path = HTML_DIR.to_string() + path;
            get_static_file(file_path).await
        }
        _ => {
            let file_path = PathBuf::from(HTML_DIR.to_string() + "error.html");
            get_static_file(file_path).await.map(|mut response| {
                *response.status_mut() = StatusCode::NOT_FOUND;
                response
            })
        }
    };

    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    response
}

#[tokio::main]
async fn main() -> Result<()> {
    warn_ignored_env_vars();
    let settings = settings::SettingsStore::load(SETTINGS_FILE).await?;
    let startup = settings.running().clone();

    let log_file = LogFile::with_limits(
        format!("{}{}", LOG_DIR, LOG_FILE_NAME),
        logs::LogLimits::from(&startup),
    )
    .await
    .expect("Failed to create or open log file");

    let admin = auth::CredentialStore::load(ADMIN_CREDENTIALS_FILE).await?;
    if !admin.is_configured().await {
        println!("Admin credentials not set: the first visitor of /admin can create them.");
    }
    let session_settings = admin::SessionSettings {
        key: auth::load_or_create_session_key(Path::new(SESSION_KEY_FILE)).await?,
        cookie_secure: admin_cookie_secure()?,
        max_age_secs: startup.admin_session_max_age_secs(),
    };

    let app_state = data_mgt::AppState {
        assets: data_mgt::AssetStorage::new(),
        connection_tracker: data_mgt::RateLimiter::default(),
        log_file,
        admin,
        settings,
        files: files::FileStore::load(STORAGE_DIR).await?,
        requests: requests::RequestStore::load(REQUESTS_FILE).await?,
    };

    let bind = (startup.bind_addr, startup.bind_port);
    println!("Starting server at http://{}/", SocketAddr::from(bind));

    let inner_app_state = app_state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if let Err(e) = data_mgt::clear_app_data(&inner_app_state).await {
                eprintln!("Error clearing assets: {}", e);
            }
        }
    });
    HttpServer::new(move || {
        App::new()
            .wrap(security_headers())
            .app_data(web::Data::new(app_state.clone()))
            .configure(|cfg| configure_routes(cfg, &session_settings))
    })
    .bind(bind)?
    .run()
    .await?;
    Ok(())
}

fn security_headers() -> DefaultHeaders {
    // DefaultHeaders keeps a header already set by a handler, such as CONTENT_CSP.
    DefaultHeaders::new()
        .add(("Content-Security-Policy", PAGE_CSP))
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("Referrer-Policy", "no-referrer"))
}

fn configure_routes(cfg: &mut web::ServiceConfig, session_settings: &admin::SessionSettings) {
    cfg.service(index)
        .service(stats)
        .service(admin_page)
        .service(view_asset)
        .service(files_page)
        .service(file_page)
        .service(request_page)
        .service(api_request_info)
        .service(api_request_upload)
        .service(api_file_info)
        .service(api_file_download)
        .service(api_file_check_key)
        .service(api_file_download_with_key)
        .service(api_get_asset)
        .service(api_upload)
        .service(api_limits)
        .service(api_stats);
    // Must be registered before the catch-all, which matches every path.
    admin::configure(cfg, session_settings);
    cfg.service(catch_all);
}

/// `ADMIN_COOKIE_SECURE=false` lets the admin cookie work over plain HTTP. Any value other
/// than `true` or `false` stops the server instead of silently weakening the cookie.
fn admin_cookie_secure() -> Result<bool> {
    match env::var("ADMIN_COOKIE_SECURE") {
        Err(env::VarError::NotPresent) => Ok(true),
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(value) => anyhow::bail!("ADMIN_COOKIE_SECURE must be 'true' or 'false', got '{value}'"),
        Err(e) => anyhow::bail!("ADMIN_COOKIE_SECURE is not valid UTF-8: {e}"),
    }
}

fn warn_ignored_env_vars() {
    for name in IGNORED_ENV_VARS {
        if env::var_os(name).is_some() {
            eprintln!("Warning: {name} is ignored; set it in the admin panel ({SETTINGS_FILE}).");
        }
    }
}

/// Client address for rate limiting and logs. Forwarding headers count only when the
/// TCP peer is a trusted proxy, because any other client can set them to anything.
pub fn client_ip(req: &HttpRequest) -> Option<String> {
    // Without the app state no proxy is trusted, so headers can never be spoofed.
    let trusted = req
        .app_data::<web::Data<AppState>>()
        .map(|state| state.settings.get().trusted_proxies)
        .unwrap_or_default();
    resolve_client_ip(req, &trusted)
}

fn resolve_client_ip(req: &HttpRequest, trusted: &[IpAddr]) -> Option<String> {
    let peer = req.peer_addr()?.ip();
    if !trusted.contains(&peer) {
        return Some(peer.to_string());
    }

    // Proxies append to the right, so the last untrusted entry is the real client.
    let forwarded: Vec<IpAddr> = req
        .headers()
        .get_all("x-forwarded-for")
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|entry| entry.trim().parse().ok())
        .collect();

    let client = forwarded
        .into_iter()
        .rev()
        .find(|ip| !trusted.contains(ip))
        .unwrap_or(peer);
    Some(client.to_string())
}

pub async fn get_static_file<P: AsRef<Path>>(path: P) -> actix_web::Result<HttpResponse> {
    let path = path.as_ref();
    let mime = from_path(path).first_or_octet_stream();

    // HTML → text + replace
    if mime.type_() == mime::TEXT && mime.subtype() == mime::HTML {
        let mut html = tokio::fs::read_to_string(path)
            .await
            .map_err(actix_web::error::ErrorInternalServerError)?;

        for (k, v) in HTML_VARS.iter() {
            html = html.replace(k, v);
        }

        return Ok(HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html));
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().content_type(mime.as_ref()).body(bytes))
}
