use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use actix_web::{
    App,
    cookie::{Cookie, Key, SameSite},
    dev::ServiceResponse,
    http::{StatusCode, header},
    test::{self, TestRequest},
    web,
};
use serde_json::{Value, json};

use crate::{
    CONTENT_CSP, PAGE_CSP,
    admin::{SESSION_COOKIE_NAME, SessionSettings},
    auth::{CredentialStore, load_or_create_session_key},
    configure_routes,
    data_mgt::{AppState, Asset, AssetStorage, RateLimiter},
    logs::{LogEventType, LogFile, LogLimits},
    resolve_client_ip, security_headers,
    settings::{Settings, SettingsStore},
};

fn defaults() -> Settings {
    Settings::default()
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bhs-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

async fn test_state() -> AppState {
    state_in(&temp_dir()).await
}

async fn state_in(dir: &std::path::Path) -> AppState {
    AppState {
        assets: AssetStorage::new(),
        connection_tracker: RateLimiter::default(),
        log_file: LogFile::new(dir.join("log.txt")).await.unwrap(),
        admin: CredentialStore::load(dir.join("admin/credentials.json"))
            .await
            .unwrap(),
        settings: SettingsStore::with_values(dir.join("admin/settings.json"), defaults()),
    }
}

fn test_session_settings() -> SessionSettings {
    SessionSettings {
        key: Key::generate(),
        cookie_secure: true,
        max_age_secs: defaults().admin_session_max_age_secs(),
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
                .configure(|cfg| configure_routes(cfg, &test_session_settings())),
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
    for _ in 0..defaults().max_uploads_per_ip {
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
    state.assets.add_asset(asset, &defaults(), &state.log_file).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    assert!(state.assets.get_asset(&id).await.is_none());
}

#[actix_web::test]
async fn storage_budget_rejects_uploads_over_the_total() {
    let state = test_state().await;
    let limits = defaults();
    let fits = limits.max_total_storage_bytes / limits.max_asset_size_bytes;
    let new_asset =
        || Asset::new(5, "text/plain".into(), vec![0; limits.max_asset_size_bytes], None);
    for _ in 0..fits {
        state.assets.add_asset(new_asset(), &limits, &state.log_file).await.unwrap();
    }
    assert!(state.assets.add_asset(new_asset(), &limits, &state.log_file).await.is_err());
}

#[actix_web::test]
async fn cleanup_keeps_working_when_the_log_cannot_be_written() {
    let dir = temp_dir();
    let limits = LogLimits { max_bytes: 1, max_rotated: 1, ..LogLimits::default() };
    let log = LogFile::with_limits(dir.join("logs/log.txt"), limits).await.unwrap();
    let assets = AssetStorage::new();
    for _ in 0..3 {
        let asset = Asset::new(0, "text/plain".into(), b"x".to_vec(), None);
        assets.add_asset(asset, &defaults(), &log).await.unwrap();
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
    let max = defaults().max_uploads_per_ip;
    for _ in 0..max {
        assert!(limiter.check("192.0.2.1", expires, max).await.0);
    }
    assert!(!limiter.check("192.0.2.1", expires, max).await.0);

    limiter.release("192.0.2.1", expires).await;
    assert!(limiter.check("192.0.2.1", expires, max).await.0);
}

#[actix_web::test]
async fn limiter_forgets_clients_with_no_active_uploads() {
    let limiter = RateLimiter::default();
    limiter.check("192.0.2.1", chrono::Utc::now().timestamp_millis() - 1, 1).await;
    limiter.clear_expired().await;
    assert!(limiter.clients.lock().await.is_empty());
}

#[actix_web::test]
async fn stats_come_from_memory_not_from_the_log_file() {
    let dir = temp_dir();
    let state = state_in(&dir).await;
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
    let limits = LogLimits { max_bytes: 100, max_rotated: 2, ..LogLimits::default() };
    let log = LogFile::with_limits(dir.join("log.txt"), limits).await.unwrap();
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

// ---------------------------------------------------------------- admin panel

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "correct horse battery";

fn admin_cookie<B>(response: &ServiceResponse<B>) -> Cookie<'static> {
    response
        .response()
        .cookies()
        .find(|cookie| cookie.name() == SESSION_COOKIE_NAME)
        .expect("response sets the admin session cookie")
        .into_owned()
}

fn admin_post(path: &str, body: Value) -> TestRequest {
    TestRequest::post()
        .uri(path)
        .peer_addr(peer("192.0.2.50"))
        .set_json(body)
}

fn admin_get(path: &str, cookie: &Cookie<'static>) -> TestRequest {
    TestRequest::get().uri(path).cookie(cookie.clone())
}

macro_rules! admin_setup {
    ($app:expr) => {{
        let body = json!({ "username": ADMIN_USER, "password": ADMIN_PASSWORD });
        let response = test::call_service($app, admin_post("/api/admin/setup", body).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        admin_cookie(&response)
    }};
}

macro_rules! admin_login {
    ($app:expr, $password:expr) => {{
        let body = json!({ "username": ADMIN_USER, "password": $password });
        let response = test::call_service($app, admin_post("/api/admin/login", body).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        admin_cookie(&response)
    }};
}

#[actix_web::test]
async fn admin_setup_starts_a_session_and_happens_only_once() {
    let app = test_app!(test_state().await);
    let anonymous = TestRequest::get().uri("/api/admin/status").to_request();
    let status: Value = test::call_and_read_body_json(&app, anonymous).await;
    assert_eq!(status["configured"], false);
    assert_eq!(status["authenticated"], false);

    let cookie = admin_setup!(&app);
    let status: Value =
        test::call_and_read_body_json(&app, admin_get("/api/admin/status", &cookie).to_request())
            .await;
    assert_eq!(status["configured"], true);
    assert_eq!(status["authenticated"], true);
    assert_eq!(status["username"], ADMIN_USER);

    let intruder = json!({ "username": "intruder", "password": "another password" });
    let response = test::call_service(&app, admin_post("/api/admin/setup", intruder).to_request()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[actix_web::test]
async fn admin_setup_rejects_weak_input() {
    let app = test_app!(test_state().await);
    for body in [
        json!({ "username": "admin", "password": "short" }),
        json!({ "username": "", "password": ADMIN_PASSWORD }),
        json!({ "username": " admin", "password": ADMIN_PASSWORD }),
    ] {
        let response = test::call_service(&app, admin_post("/api/admin/setup", body.clone()).to_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
}

#[actix_web::test]
async fn admin_routes_require_login() {
    let app = test_app!(test_state().await);
    let _ = admin_setup!(&app);
    let change = json!({ "current_password": ADMIN_PASSWORD, "new_password": "something else" });
    let requests = [
        TestRequest::get().uri("/api/admin/assets"),
        TestRequest::get().uri("/api/admin/stats"),
        TestRequest::delete().uri(&format!("/api/admin/assets/{}", uuid::Uuid::new_v4())),
        admin_post("/api/admin/password", change),
        TestRequest::get().uri("/api/admin/settings"),
        TestRequest::put().uri("/api/admin/settings").set_json(json!(defaults())),
    ];
    for request in requests {
        let response = test::call_service(&app, request.to_request()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[actix_web::test]
async fn admin_login_rejects_wrong_credentials() {
    let app = test_app!(test_state().await);
    let _ = admin_setup!(&app);
    for (username, password) in [(ADMIN_USER, "wrong password"), ("someone", ADMIN_PASSWORD)] {
        let body = json!({ "username": username, "password": password });
        let response = test::call_service(&app, admin_post("/api/admin/login", body).to_request()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{username}");
        assert!(
            response
                .response()
                .cookies()
                .all(|cookie| cookie.name() != SESSION_COOKIE_NAME)
        );
    }
}

#[actix_web::test]
async fn admin_session_cookie_is_locked_down() {
    let app = test_app!(test_state().await);
    let cookie = admin_setup!(&app);
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Strict));
    assert_eq!(cookie.path(), Some("/api/admin"));

    let response = test::call_service(&app, admin_get("/api/admin/status", &cookie).to_request()).await;
    assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
}

#[actix_web::test]
async fn logout_revokes_the_session_cookie() {
    let app = test_app!(test_state().await);
    let cookie = admin_setup!(&app);
    let logout = admin_post("/api/admin/logout", json!({})).cookie(cookie.clone());
    let response = test::call_service(&app, logout.to_request()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // A copy of the cookie taken before logout must not work anymore.
    let response = test::call_service(&app, admin_get("/api/admin/assets", &cookie).to_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn password_change_revokes_other_sessions() {
    let app = test_app!(test_state().await);
    let first = admin_setup!(&app);
    let second = admin_login!(&app, ADMIN_PASSWORD);

    let wrong = json!({ "current_password": "not the password", "new_password": "a brand new password" });
    let request = admin_post("/api/admin/password", wrong).cookie(first.clone());
    let response = test::call_service(&app, request.to_request()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let change = json!({ "current_password": ADMIN_PASSWORD, "new_password": "a brand new password" });
    let request = admin_post("/api/admin/password", change).cookie(first);
    let response = test::call_service(&app, request.to_request()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let renewed = admin_cookie(&response);

    let response = test::call_service(&app, admin_get("/api/admin/assets", &second).to_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = test::call_service(&app, admin_get("/api/admin/assets", &renewed).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);

    let old = json!({ "username": ADMIN_USER, "password": ADMIN_PASSWORD });
    let response = test::call_service(&app, admin_post("/api/admin/login", old).to_request()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let _ = admin_login!(&app, "a brand new password");
}

#[actix_web::test]
async fn admin_can_delete_an_asset_and_free_the_upload_slot() {
    let app = test_app!(test_state().await);
    let cookie = admin_setup!(&app);
    let mut ids = Vec::new();
    for _ in 0..defaults().max_uploads_per_ip {
        ids.push(upload_text!(&app));
    }
    let blocked = test::call_service(&app, upload_request("text/plain", "x").to_request()).await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

    let list: Value =
        test::call_and_read_body_json(&app, admin_get("/api/admin/assets", &cookie).to_request())
            .await;
    assert_eq!(list.as_array().unwrap().len(), defaults().max_uploads_per_ip);
    assert_eq!(list[0]["uploader_ip"], "192.0.2.1");

    let delete = TestRequest::delete()
        .uri(&format!("/api/admin/assets/{}", ids[0]))
        .cookie(cookie.clone());
    let response = test::call_service(&app, delete.to_request()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let content = TestRequest::get().uri(&format!("/api/content/{}", ids[0]));
    let response = test::call_service(&app, content.to_request()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = test::call_service(&app, upload_request("text/plain", "x").to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn admin_stats_group_active_uploads_by_ip() {
    let app = test_app!(test_state().await);
    let cookie = admin_setup!(&app);
    let _ = upload_text!(&app);
    let _ = upload_text!(&app);

    let stats: Value =
        test::call_and_read_body_json(&app, admin_get("/api/admin/stats", &cookie).to_request())
            .await;
    assert_eq!(stats["active_assets"], 2);
    assert_eq!(stats["max_uploads_per_ip"], defaults().max_uploads_per_ip);
    assert_eq!(stats["uploaders"][0]["ip"], "192.0.2.1");
    assert_eq!(stats["uploaders"][0]["active_assets"], 2);
    assert_eq!(stats["uploaders"][0]["bytes"], 2 * "hello".len());
}

#[actix_web::test]
async fn credentials_survive_a_restart_and_a_corrupt_file_is_rejected() {
    let path = temp_dir().join("admin/credentials.json");
    let store = CredentialStore::load(path.clone()).await.unwrap();
    store.setup(ADMIN_USER, ADMIN_PASSWORD).await.unwrap();

    let reloaded = CredentialStore::load(path.clone()).await.unwrap();
    assert!(reloaded.is_configured().await);
    assert!(reloaded.verify(ADMIN_USER, ADMIN_PASSWORD).await.is_ok());

    let contents = fs::read_to_string(&path).unwrap();
    assert!(!contents.contains(ADMIN_PASSWORD));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // A broken file must stop startup, not reopen the first-login setup.
    fs::write(&path, b"not json").unwrap();
    assert!(CredentialStore::load(path).await.is_err());
}

#[actix_web::test]
async fn session_key_is_created_once_and_reused() {
    let path = temp_dir().join("admin/session.key");
    let first = load_or_create_session_key(&path).await.unwrap();
    let second = load_or_create_session_key(&path).await.unwrap();
    assert_eq!(first.master(), second.master());
}

// ---------------------------------------------------------------- settings

fn admin_put_settings(cookie: &Cookie<'static>, body: Value) -> TestRequest {
    TestRequest::put()
        .uri("/api/admin/settings")
        .peer_addr(peer("192.0.2.50"))
        .cookie(cookie.clone())
        .set_json(body)
}

/// Default settings as JSON with `changes` applied on top.
fn settings_with(changes: Value) -> Value {
    let mut body = json!(defaults());
    for (name, value) in changes.as_object().unwrap() {
        body[name] = value.clone();
    }
    body
}

#[actix_web::test]
async fn settings_file_is_created_with_defaults_and_reloaded() {
    let path = temp_dir().join("admin/settings.json");
    let store = SettingsStore::load(path.clone()).await.unwrap();
    assert_eq!(store.get(), defaults());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let changed = Settings {
        max_assets: 7,
        ..defaults()
    };
    store.update(changed.clone()).await.unwrap();
    assert_eq!(SettingsStore::load(path).await.unwrap().get(), changed);
}

#[actix_web::test]
async fn settings_file_missing_fields_take_defaults() {
    let path = temp_dir().join("settings.json");
    fs::write(&path, br#"{ "max_assets": 5 }"#).unwrap();
    let settings = SettingsStore::load(path).await.unwrap().get();
    assert_eq!(
        settings,
        Settings {
            max_assets: 5,
            ..defaults()
        }
    );
}

#[actix_web::test]
async fn bad_settings_file_stops_startup() {
    let dir = temp_dir();
    for (name, contents) in [
        ("corrupt", "not json"),
        ("unknown field", r#"{ "max_asset": 5 }"#),
        ("invalid value", r#"{ "max_uploads_per_ip": 0 }"#),
        ("wrong type", r#"{ "bind_addr": "not an ip" }"#),
    ] {
        let path = dir.join(format!("{}.json", name.replace(' ', "_")));
        fs::write(&path, contents).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(SettingsStore::load(path.clone()).await.is_err(), "{name}");
        // The broken file is left for the admin to fix, never replaced by defaults.
        assert_eq!(fs::read(&path).unwrap(), before, "{name}");
    }
}

#[actix_web::test]
async fn validation_reports_every_broken_field() {
    let settings = Settings {
        min_asset_duration_minutes: 10,
        max_asset_duration_minutes: 5,
        max_asset_size_bytes: 10,
        max_total_storage_bytes: 5,
        bind_port: 0,
        ..defaults()
    };
    let fields: Vec<String> = settings.validate().into_iter().map(|e| e.field).collect();
    assert_eq!(
        fields,
        [
            "max_asset_duration_minutes",
            "max_total_storage_bytes",
            "bind_port"
        ]
    );
    assert!(defaults().validate().is_empty());
}

#[actix_web::test]
async fn admin_settings_change_applies_without_restart() {
    let dir = temp_dir();
    let state = state_in(&dir).await;
    let app = test_app!(state.clone());
    let cookie = admin_setup!(&app);

    let body = settings_with(json!({ "max_uploads_per_ip": 1 }));
    let response = test::call_service(&app, admin_put_settings(&cookie, body).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let saved: Value =
        serde_json::from_slice(&fs::read(dir.join("admin/settings.json")).unwrap()).unwrap();
    assert_eq!(saved["max_uploads_per_ip"], 1);

    let _ = upload_text!(&app);
    let blocked = test::call_service(&app, upload_request("text/plain", "x").to_request()).await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

    let log = fs::read_to_string(dir.join("log.txt")).unwrap();
    assert!(log.contains("settings_changed"), "{log}");
    assert!(
        log.contains(r#""max_uploads_per_ip":{"from":10,"to":1}"#),
        "{log}"
    );
}

#[actix_web::test]
async fn restart_only_settings_are_reported_as_pending() {
    let app = test_app!(test_state().await);
    let cookie = admin_setup!(&app);

    let body = settings_with(json!({ "bind_port": 9090 }));
    let response: Value =
        test::call_and_read_body_json(&app, admin_put_settings(&cookie, body).to_request()).await;
    assert_eq!(response["current"]["bind_port"], 9090);
    assert_eq!(response["running"]["bind_port"], 8080);
    assert_eq!(response["restart_pending"], json!(["bind_port"]));

    let fetched: Value =
        test::call_and_read_body_json(&app, admin_get("/api/admin/settings", &cookie).to_request())
            .await;
    assert_eq!(fetched, response);
}

#[actix_web::test]
async fn invalid_or_partial_settings_are_rejected_and_nothing_changes() {
    let dir = temp_dir();
    let state = state_in(&dir).await;
    let app = test_app!(state.clone());
    let cookie = admin_setup!(&app);

    let invalid = settings_with(json!({ "max_assets": 0, "max_recent_activity": 0 }));
    let response =
        test::call_service(&app, admin_put_settings(&cookie, invalid).to_request()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(response).await;
    let fields: Vec<&str> = body["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, ["max_assets", "max_recent_activity"]);

    // A missing field must not silently fall back to its default.
    let mut partial = settings_with(json!({ "max_assets": 5 }));
    partial.as_object_mut().unwrap().remove("bind_port");
    let response =
        test::call_service(&app, admin_put_settings(&cookie, partial).to_request()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["fields"][0]["field"], "bind_port");

    // Type errors and range errors are reported together, each on its own field.
    let mixed = settings_with(json!({
        "max_assets": "many",
        "trusted_proxies": ["10.0.0.2", "nope"],
        "min_asset_duration_minutes": 10,
        "max_asset_duration_minutes": 5,
        "unknown": 1,
    }));
    let response = test::call_service(&app, admin_put_settings(&cookie, mixed).to_request()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = test::read_body_json(response).await;
    let mut fields: Vec<&str> =
        body["fields"].as_array().unwrap().iter().map(|e| e["field"].as_str().unwrap()).collect();
    fields.sort();
    assert_eq!(
        fields,
        ["max_asset_duration_minutes", "max_assets", "trusted_proxies", "unknown"]
    );

    assert_eq!(state.settings.get(), defaults());
    assert!(!dir.join("admin/settings.json").exists());
}

#[actix_web::test]
async fn upload_size_limit_follows_the_settings() {
    let state = test_state().await;
    let app = test_app!(state.clone());
    let cookie = admin_setup!(&app);
    let body = settings_with(json!({ "max_asset_size_bytes": 4, "max_total_storage_bytes": 4 }));
    let response = test::call_service(&app, admin_put_settings(&cookie, body).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);

    let ok = test::call_service(&app, upload_request("text/plain", "abcd").to_request()).await;
    assert_eq!(ok.status(), StatusCode::OK);
    // Decoded content over the limit, and a body over twice the limit, are both refused.
    for content in ["abcde", &"x".repeat(2 * 4 + 1024)] {
        let response =
            test::call_service(&app, upload_request("text/plain", content).to_request()).await;
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{content}"
        );
    }
}

#[actix_web::test]
async fn upload_requires_a_json_body() {
    let app = test_app!(test_state().await);
    let form = TestRequest::post()
        .uri("/api/upload")
        .peer_addr(peer("192.0.2.1"))
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload(r#"{"duration":1,"content_type":"text/plain","content":"x"}"#);
    let response = test::call_service(&app, form.to_request()).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let broken = TestRequest::post()
        .uri("/api/upload")
        .peer_addr(peer("192.0.2.1"))
        .insert_header((header::CONTENT_TYPE, "application/json; charset=utf-8"))
        .set_payload("{not json");
    let response = test::call_service(&app, broken.to_request()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn public_limits_follow_the_settings() {
    let state = test_state().await;
    let app = test_app!(state.clone());
    let changed = Settings {
        max_asset_duration_minutes: 120,
        ..defaults()
    };
    state.settings.update(changed).await.unwrap();

    let limits: Value =
        test::call_and_read_body_json(&app, TestRequest::get().uri("/api/limits").to_request())
            .await;
    assert_eq!(
        limits,
        json!({
            "min_duration_minutes": 1,
            "max_duration_minutes": 120,
            "max_asset_size_bytes": defaults().max_asset_size_bytes,
        })
    );
}

#[actix_web::test]
async fn trusted_proxies_apply_without_restart() {
    let state = test_state().await;
    let app = test_app!(state.clone());
    let cookie = admin_setup!(&app);
    let forwarded = || {
        upload_request("text/plain", "x")
            .insert_header(("x-forwarded-for", "203.0.113.9"))
            .to_request()
    };

    let _ = test::call_service(&app, forwarded()).await;
    let body = settings_with(json!({ "trusted_proxies": ["192.0.2.1"] }));
    let response = test::call_service(&app, admin_put_settings(&cookie, body).to_request()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = test::call_service(&app, forwarded()).await;

    let list: Value =
        test::call_and_read_body_json(&app, admin_get("/api/admin/assets", &cookie).to_request())
            .await;
    let ips: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["uploader_ip"].as_str().unwrap())
        .collect();
    assert_eq!(ips, ["192.0.2.1", "203.0.113.9"]);
}

#[actix_web::test]
async fn lower_recent_activity_limit_trims_the_list() {
    let log = LogFile::new(temp_dir().join("log.txt")).await.unwrap();
    for _ in 0..5 {
        log.write_event(LogEventType::AssetUploaded(json!({})))
            .await
            .unwrap();
    }
    assert_eq!(log.stats().await.recent_activity.len(), 5);
    log.set_limits(LogLimits {
        max_recent: 2,
        ..LogLimits::default()
    })
    .await;
    assert_eq!(log.stats().await.recent_activity.len(), 2);
}
