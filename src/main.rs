mod api;
mod data_mgt;
mod logs;
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
    net::IpAddr,
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub static HTML_DIR: &str = "data/html/";
pub static LOG_DIR: &str = "data/logs/";
pub static LOG_FILE_NAME: &str = "log.txt";
pub static MAX_LOG_FILE_BYTES: u64 = 50 * 1024 * 1024; // 50 MB, then rotate while running
pub static MAX_ROTATED_LOGS: usize = 10; // older rotated logs are deleted
pub static MIN_ASSET_DURATION: u32 = 1; // in minutes
pub static MAX_ASSET_DURATION: u32 = 60; // in minutes
pub static MAX_ASSETS: usize = 1000;
pub static MAX_ASSET_SIZE_BYTES: usize = 3 * 1024 * 1024; // 3 MB
pub static MAX_TOTAL_STORAGE_BYTES: usize = 512 * 1024 * 1024; // 512 MB across all assets
pub static MAX_UPLOADS_PER_USER: usize = 10;
// SVG and HTML are excluded on purpose: both can run scripts when opened directly.
pub static ALLOWED_CONTENT_TYPES: [&str; 7] = [
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
pub static FOOTER_HTML: LazyLock<String> =
    LazyLock::new(|| fs::read_to_string(Path::new(HTML_DIR).join("footer.html")).unwrap_or_default());
pub static HTML_VARS: LazyLock<Vec<(&str, &str)>> = LazyLock::new(|| {
    vec![
        ("{{FOOTER}}", (*FOOTER_HTML).as_str()),
        ("{{VERSION}}", env!("CARGO_PKG_VERSION")),
    ]
});

pub static BIND_ADDR: LazyLock<String> = LazyLock::new(|| match env::var("BIND_ADDR") {
    Ok(addr) => {
        println!("Binding to address: {}", addr);
        addr.parse().unwrap_or("127.0.0.1".to_string())
    }
    Err(_) => {
        println!("Binding to default address: 0.0.0.0");
        "0.0.0.0".to_string()
    }
});
pub static BIND_PORT: LazyLock<u16> = LazyLock::new(|| match env::var("BIND_PORT") {
    Ok(port_str) => {
        println!("Binding to port: {}", port_str);
        port_str.parse().unwrap_or(8080)
    }
    Err(_) => {
        println!("Binding to default port: 8080");
        8080
    }
});

// Comma-separated proxy IPs allowed to report the client address via X-Forwarded-For.
pub static TRUSTED_PROXIES: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    parse_trusted_proxies(&env::var("TRUSTED_PROXIES").unwrap_or_default())
});

pub static STATIC_PAGES: LazyLock<Vec<String>> = LazyLock::new(|| {
    fs::read_dir(HTML_DIR)
        .unwrap()
        .filter_map(|entry| entry.ok().and_then(|e| e.file_name().to_str().map(|s| s.to_string())))
        .collect()
});

use crate::{
    api::{api_get_asset, api_stats, api_upload},
    data_mgt::AppState,
    logs::{LogEventType, LogFile},
};

#[get("/")]
async fn index(req: HttpRequest, app_state: web::Data<AppState>) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "index.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/stats")]
async fn stats(req: HttpRequest, app_state: web::Data<AppState>) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "stats.html");
    app_state
        .log_file
        .write_event(LogEventType::HttpRequest(req.into()))
        .await
        .unwrap_or_else(|e| println!("Failed to log HTTP request: {}", e));
    get_static_file(path).await
}

#[get("/bhs/{id}")]
async fn view_asset(req: HttpRequest, app_state: web::Data<AppState>) -> actix_web::Result<HttpResponse> {
    let path: PathBuf = PathBuf::from(HTML_DIR.to_string() + "view.html");
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
    let log_file = LogFile::new(format!("{}{}", LOG_DIR, LOG_FILE_NAME))
        .await
        .expect("Failed to create or open log file");

    let app_state = data_mgt::AppState {
        assets: data_mgt::AssetStorage::new(),
        connection_tracker: data_mgt::RateLimiter::default(),
        log_file,
    };

    println!("Starting server at http://{}:{}/", *BIND_ADDR, *BIND_PORT);

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
            .configure(configure_routes)
    })
    .bind((BIND_ADDR.clone(), *BIND_PORT))?
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

fn configure_routes(cfg: &mut web::ServiceConfig) {
    // Uploaded images are sent as base64 inside JSON, which is larger than the decoded asset.
    cfg.app_data(web::JsonConfig::default().limit(MAX_ASSET_SIZE_BYTES * 2))
        .service(index)
        .service(stats)
        .service(view_asset)
        .service(api_get_asset)
        .service(api_upload)
        .service(api_stats)
        .service(catch_all);
}

fn parse_trusted_proxies(value: &str) -> Vec<IpAddr> {
    value
        .split(',')
        .filter_map(|entry| entry.trim().parse().ok())
        .collect()
}

/// Client address for rate limiting and logs. Forwarding headers count only when the
/// TCP peer is a trusted proxy, because any other client can set them to anything.
pub fn client_ip(req: &HttpRequest) -> Option<String> {
    resolve_client_ip(req, &TRUSTED_PROXIES)
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

        return Ok(HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html));
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().content_type(mime.as_ref()).body(bytes))
}
