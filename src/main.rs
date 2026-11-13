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
mod throttle;
mod tls;

use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    get,
    http::{StatusCode, header},
    middleware::{DefaultHeaders, Next, from_fn},
    mime, route,
    web::{self},
};

use anyhow::Result;
use mime_guess::from_path;
use serde_json::{Value, json};
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
pub static TLS_DIR: &str = "data/admin/tls/";
pub static STORAGE_DIR: &str = "data/storage/";
pub static REQUESTS_FILE: &str = "data/storage/requests.json";
pub static LOG_FILE_NAME: &str = "log.txt";
// Set on the process started by a restart from the admin panel.
const RESTARTED_ENV: &str = "BHS_RESTARTED";
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

/// When this process started, Unix ms: the admin page sees it change after a restart.
pub static STARTED_AT: LazyLock<i64> = LazyLock::new(|| chrono::Utc::now().timestamp_millis());

// Read once: a missing html directory leaves no static pages instead of a panic in a request.
pub static STATIC_PAGES: LazyLock<Vec<String>> = LazyLock::new(|| match fs::read_dir(HTML_DIR) {
    Ok(entries) => entries
        .filter_map(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().to_str().map(|s| s.to_string()))
        })
        .collect(),
    Err(e) => {
        eprintln!("Cannot list {HTML_DIR}: {e}; no static files will be served");
        Vec::new()
    }
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
    LazyLock::force(&STARTED_AT);
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

    // HTTPS is optional and must never lock the admin out: when it cannot start, the
    // server runs on plain HTTP and the admin panel shows the error.
    let mut tls_status = tls::TlsStatus {
        mode: startup.tls_mode,
        ..Default::default()
    };
    let mut https = None;
    match tls::prepare(&startup, Path::new(TLS_DIR)).await {
        Ok(None) => {}
        Ok(Some(setup)) => {
            let addr = (startup.bind_addr, startup.https_port);
            match std::net::TcpListener::bind(addr) {
                Ok(listener) => {
                    tls_status.active = true;
                    tls_status.https_port = Some(startup.https_port);
                    tls_status.fingerprint = Some(setup.fingerprint);
                    tls_status.names = setup.names;
                    https = Some((listener, setup.config));
                }
                Err(e) => {
                    tls_status.error = Some(format!(
                        "cannot listen on port {}: {e}",
                        startup.https_port
                    ))
                }
            }
        }
        Err(e) => tls_status.error = Some(format!("{e:#}")),
    }
    if let Some(error) = &tls_status.error {
        eprintln!("HTTPS is not running, serving plain HTTP only: {error}");
    }

    // Secure when this server serves HTTPS, or when a TLS proxy in front of it does (TLS off
    // here, https public URL). If this server's own TLS failed, it only speaks HTTP: a
    // Secure cookie would lock the admin out of the panel that can fix it.
    let cookie_secure = match admin_cookie_secure_override()? {
        Some(secure) => secure,
        None => {
            tls_status.active
                || (startup.tls_mode == settings::TlsMode::Off && startup.public_url_is_https())
        }
    };
    if !cookie_secure {
        println!(
            "The admin cookie works over plain HTTP: set an https public URL or enable HTTPS in the admin panel."
        );
    }
    let session_settings = admin::SessionSettings {
        key: auth::load_or_create_session_key(Path::new(SESSION_KEY_FILE)).await?,
        cookie_secure,
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
        login_throttle: Default::default(),
        request_throttle: Default::default(),
        tls_status: std::sync::Arc::new(tls_status),
        restart: Default::default(),
    };
    let restart = app_state.restart.clone();

    let bind = (startup.bind_addr, startup.bind_port);
    println!("Starting server at http://{}/", SocketAddr::from(bind));
    if app_state.tls_status.active {
        println!(
            "Serving HTTPS at https://{}/ (plain HTTP redirects there)",
            SocketAddr::from((startup.bind_addr, startup.https_port))
        );
    }

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
    // Written once the listeners are bound, so the new log file shows that the server came
    // (back) up and how; after a restart from the panel it is the first line.
    let started = json!({
        "action": "started",
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "restarted": env::var_os(RESTARTED_ENV).is_some(),
        "http": SocketAddr::from(bind).to_string(),
        "https": app_state
            .tls_status
            .active
            .then(|| SocketAddr::from((startup.bind_addr, startup.https_port)).to_string()),
        "tls_mode": app_state.tls_status.mode,
        "tls_error": app_state.tls_status.error,
    });
    let log_file = app_state.log_file.clone();
    let mut server = HttpServer::new(move || {
        App::new()
            .wrap(from_fn(redirect_plain_http))
            .wrap(security_headers())
            .app_data(web::Data::new(app_state.clone()))
            .configure(|cfg| configure_routes(cfg, &session_settings))
    })
    .bind(bind)?;
    if let Some((listener, config)) = https {
        server = server.listen_rustls_0_23(listener, config)?;
    }
    let server = server.run();
    log_file
        .write_event(LogEventType::Server(started))
        .await
        .unwrap_or_else(|e| eprintln!("Failed to log the server start: {e}"));


    // The restart button stops the server gracefully: no new connections, and requests in
    // progress (downloads included) get up to the shutdown timeout to finish.
    let handle = server.handle();
    let waiter = restart.clone();
    tokio::spawn(async move {
        waiter.wait().await;
        println!("Restart requested from the admin panel: stopping the server");
        handle.stop(true).await;
    });
    server.await?;

    if restart.is_requested() {
        restart_process()?;
    }
    Ok(())
}

/// Replaces this process with a fresh start of the same program and arguments. The PID
/// stays the same, so a container keeps running without a restart policy.
#[cfg(unix)]
fn restart_process() -> Result<()> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    // After a rebuild the running file may be gone; argv[0] then finds the new one.
    let program = env::current_exe()
        .ok()
        .filter(|path| path.exists())
        .map(std::ffi::OsString::from)
        .or_else(|| env::args_os().next())
        .ok_or_else(|| anyhow::anyhow!("cannot find the program to restart"))?;
    println!("Restarting {}", program.to_string_lossy());
    std::io::stdout().flush().ok();
    // `exec` returns only when it fails.
    let error = std::process::Command::new(&program)
        .args(env::args_os().skip(1))
        .env(RESTARTED_ENV, "1")
        .exec();
    Err(anyhow::anyhow!(
        "cannot restart {}: {error}",
        program.to_string_lossy()
    ))
}

#[cfg(not(unix))]
fn restart_process() -> Result<()> {
    anyhow::bail!("restarting from the admin panel is supported on Unix only; start the server again")
}

/// While HTTPS is running, sends every plain-HTTP request to the HTTPS port (308 keeps the
/// method and body).
pub(crate) async fn redirect_plain_http<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, actix_web::Error> {
    let target = match req.app_data::<web::Data<AppState>>() {
        Some(state) if state.tls_status.active && !req.app_config().secure() => {
            let host = req.connection_info().host().to_string();
            let path = req
                .uri()
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_string();
            let port = state.tls_status.https_port.unwrap_or(443);
            Some(tls::https_redirect_target(
                &state.settings.get(),
                port,
                &host,
                &path,
            ))
        }
        _ => None,
    };
    match target {
        Some(target) => Ok(req
            .into_response(
                HttpResponse::PermanentRedirect()
                    .insert_header((header::LOCATION, target))
                    .finish(),
            )
            .map_into_right_body()),
        None => next
            .call(req)
            .await
            .map(ServiceResponse::map_into_left_body),
    }
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
/// `ADMIN_COOKIE_SECURE` forces the cookie's `Secure` flag; unset, it follows the HTTPS
/// setup. It stays as an emergency switch for a broken configuration.
fn admin_cookie_secure_override() -> Result<Option<bool>> {
    match env::var("ADMIN_COOKIE_SECURE") {
        Err(env::VarError::NotPresent) => Ok(None),
        Ok(value) if value == "true" => Ok(Some(true)),
        Ok(value) if value == "false" => Ok(Some(false)),
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
