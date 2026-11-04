use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use actix_web::{
    App,
    http::{StatusCode, header},
    test::{self, TestRequest},
    web,
};
use serde_json::{Value, json};

use crate::{
    CONTENT_CSP, MAX_ASSET_SIZE_BYTES, MAX_TOTAL_STORAGE_BYTES, MAX_UPLOADS_PER_USER, PAGE_CSP,
    configure_routes,
    data_mgt::{AppState, Asset, AssetStorage, RateLimiter},
    logs::{LogEventType, LogFile},
    resolve_client_ip, security_headers,
};

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bhs-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

async fn test_state() -> AppState {
    AppState {
        assets: AssetStorage::new(),
        connection_tracker: RateLimiter::default(),
        log_file: LogFile::new(temp_dir().join("log.txt")).await.unwrap(),
    }
}

fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), 40000)
}

fn upload_request(content_type: &str, content: &str) -> TestRequest {
    TestRequest::post()
        .uri("/api/upload")
        .peer_addr(peer("192.0.2.1"))
        .set_json(json!({ "duration": 1, "content_type": content_type, "content": content }))
}

macro_rules! test_app {
    ($state:expr) => {
        test::init_service(
            App::new()
                .wrap(security_headers())
                .app_data(web::Data::new($state))
                .configure(configure_routes),
        )
        .await
    };
}

macro_rules! upload_text {
    ($app:expr) => {{
        let request = upload_request("text/plain", "hello").to_request();
        let response: Value = test::call_and_read_body_json($app, request).await;
        response["link"].as_str().unwrap().replace("/bhs/", "")
    }};
}

#[actix_web::test]
async fn upload_rejects_content_that_can_run_scripts() {
    let app = test_app!(test_state().await);
    for mime in ["text/html", "image/svg+xml", "<img src=x onerror=alert(1)>", "bad\nvalue"] {
        let response = test::call_service(&app, upload_request(mime, "aGk=").to_request()).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{mime}");
    }
}

#[actix_web::test]
async fn content_is_served_with_sandbox_csp_and_nosniff() {
    let app = test_app!(test_state().await);
    let id = upload_text!(&app);
    let request = TestRequest::get().uri(&format!("/api/content/{id}")).to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers.get("content-security-policy").unwrap(), CONTENT_CSP);
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
}

#[actix_web::test]
async fn pages_carry_security_headers() {
    let app = test_app!(test_state().await);
    let response = test::call_service(&app, TestRequest::get().uri("/").to_request()).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-security-policy").unwrap(), PAGE_CSP);
    assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(response.headers().get(header::REFERRER_POLICY).unwrap(), "no-referrer");
}

#[actix_web::test]
async fn unknown_path_returns_404() {
    let app = test_app!(test_state().await);
    let request = TestRequest::get().uri("/does-not-exist").to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn forged_forwarding_headers_do_not_bypass_upload_limit() {
    let app = test_app!(test_state().await);
    for _ in 0..MAX_UPLOADS_PER_USER {
        let _ = upload_text!(&app);
    }
    let forged = [("x-forwarded-for", "203.0.113.9"), ("forwarded", "for=203.0.113.9")];
    for header_pair in forged {
        let request = upload_request("text/plain", "x")
            .insert_header(header_pair)
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[actix_web::test]
async fn client_ip_trusts_forwarded_for_only_from_known_proxies() {
    let proxy: IpAddr = "10.0.0.1".parse().unwrap();
    let forged_then_real = ("x-forwarded-for", "198.51.100.7, 203.0.113.9");

    let via_proxy = TestRequest::default()
        .peer_addr(peer("10.0.0.1"))
        .insert_header(forged_then_real)
        .to_http_request();
    assert_eq!(resolve_client_ip(&via_proxy, &[proxy]).unwrap(), "203.0.113.9");

    let direct = TestRequest::default()
        .peer_addr(peer("192.0.2.1"))
        .insert_header(forged_then_real)
        .to_http_request();
    assert_eq!(resolve_client_ip(&direct, &[proxy]).unwrap(), "192.0.2.1");
}

#[actix_web::test]
async fn expired_asset_is_not_served() {
    let state = test_state().await;
    let asset = Asset::new(0, "text/plain".into(), b"secret".to_vec(), None);
    let id = asset.id();
    state.assets.add_asset(asset, &state.log_file).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    assert!(state.assets.get_asset(&id).await.is_none());
}

#[actix_web::test]
async fn storage_budget_rejects_uploads_over_the_total() {
    let state = test_state().await;
    let fits = MAX_TOTAL_STORAGE_BYTES / MAX_ASSET_SIZE_BYTES;
    let new_asset = || Asset::new(5, "text/plain".into(), vec![0; MAX_ASSET_SIZE_BYTES], None);
    for _ in 0..fits {
        state.assets.add_asset(new_asset(), &state.log_file).await.unwrap();
    }
    assert!(state.assets.add_asset(new_asset(), &state.log_file).await.is_err());
}

#[actix_web::test]
async fn cleanup_keeps_working_when_the_log_cannot_be_written() {
    let dir = temp_dir();
    let log = LogFile::with_limits(dir.join("logs/log.txt"), 1, 1).await.unwrap();
    let assets = AssetStorage::new();
    for _ in 0..3 {
        let asset = Asset::new(0, "text/plain".into(), b"x".to_vec(), None);
        assets.add_asset(asset, &log).await.unwrap();
    }
    fs::remove_dir_all(dir.join("logs")).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    assets.remove_expired(&log).await;
    assert_eq!(assets.assets_len().await, 0);
}

#[actix_web::test]
async fn limiter_slot_can_be_released() {
    let limiter = RateLimiter::default();
    let expires = chrono::Utc::now().timestamp_millis() + 60_000;
    for _ in 0..MAX_UPLOADS_PER_USER {
        assert!(limiter.check("192.0.2.1", expires).await.0);
    }
    assert!(!limiter.check("192.0.2.1", expires).await.0);

    limiter.release("192.0.2.1", expires).await;
    assert!(limiter.check("192.0.2.1", expires).await.0);
}

#[actix_web::test]
async fn limiter_forgets_clients_with_no_active_uploads() {
    let limiter = RateLimiter::default();
    limiter.check("192.0.2.1", chrono::Utc::now().timestamp_millis() - 1).await;
    limiter.clear_expired().await;
    assert!(limiter.clients.lock().await.is_empty());
}

#[actix_web::test]
async fn stats_come_from_memory_not_from_the_log_file() {
    let dir = temp_dir();
    let state = AppState {
        assets: AssetStorage::new(),
        connection_tracker: RateLimiter::default(),
        log_file: LogFile::new(dir.join("log.txt")).await.unwrap(),
    };
    let app = test_app!(state);
    let _ = upload_text!(&app);
    fs::remove_file(dir.join("log.txt")).unwrap();

    let request = TestRequest::get().uri("/api/stats").to_request();
    let stats: Value = test::call_and_read_body_json(&app, request).await;
    assert_eq!(stats["total_uploads"], 1);
    assert_eq!(stats["recent_activity"][0]["action"], "upload");
    assert_eq!(stats["recent_activity"][0]["mime"], "text/plain");
}

#[actix_web::test]
async fn log_rotates_by_size_and_keeps_a_bounded_history() {
    let dir = temp_dir();
    let log = LogFile::with_limits(dir.join("log.txt"), 100, 2).await.unwrap();
    for _ in 0..20 {
        log.write_event(LogEventType::Error(json!({ "error": "x" }))).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let rotated = names.iter().filter(|name| name.ends_with("_log.txt")).count();
    assert_eq!(rotated, 2, "{names:?}");
    assert!(names.iter().all(|name| !name.contains(' ')), "{names:?}");
}

#[actix_web::test]
async fn log_file_creates_a_missing_directory() {
    let path = temp_dir().join("missing/logs/log.txt");
    LogFile::new(&path).await.unwrap();
    assert!(path.exists());
}
