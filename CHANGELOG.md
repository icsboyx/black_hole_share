# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.1] - 2026-11-13

### Changed

- The admin overview has two sections, **Public sharing** and **File services**, each with its own cards and tables. File services shows shared files, received files, disk used against the budget, a table of shared files, and a table of upload requests with their status; both tables have a **Delete** button, as the active assets do. The HTTP request count moved to a line above the sections.
- `GET /api/admin/stats` also returns `shared_files`, `shared_bytes`, `received_files`, `received_bytes`, `requests`, and `open_requests`.

### Fixed

- The overview counted files received through upload requests as shared files.
- Stat cards are stacked on phone screens instead of overflowing the page.

## [2.1.0] - 2026-11-13

### Added

- Settings from environment variables, for containers: `BIND_ADDR`, `BIND_PORT_HTTP`, `BIND_PORT_HTTPS`, `TRUSTED_PROXIES`, and `EXTERNAL_FQDN` (the public host name, which becomes `https://<name>`). Each one set is applied at every start and saved to `settings.json`; the admin panel shows its field as read-only and refuses to change it. A value that cannot be parsed stops startup and names the variable.

### Changed

- `BIND_ADDR` and `TRUSTED_PROXIES` are read again, as in 1.x. `BIND_PORT` is renamed `BIND_PORT_HTTP`; the old name only prints a warning.

### Fixed

- Every log line is flushed to the file before the write returns, so the last events are in the file when a restart replaces the process.

## [2.0.1] - 2026-11-13

### Added

- A `Server` log event at every start, written as the first line of the new log file and to standard output: version, process ID, `restarted` (true after **Restart server**), the HTTP and HTTPS addresses, the TLS mode, and the HTTPS error, if any. After a restart from the panel, the log now shows that the server came back up.

### Changed

- `docker-compose.yaml` restarts the container after a crash or a host reboot (`restart: unless-stopped`).
- The documentation moved from the README to `docs/` (configuration, admin panel, API, architecture); the README keeps the overview and how to start the server.

## [2.0.0] - 2026-11-13

### Breaking changes

- `BIND_ADDR`, `BIND_PORT`, and `TRUSTED_PROXIES` are no longer read. Settings live in `data/admin/settings.json` and are edited in the admin panel; the server warns at startup when these variables are still set.
- The per-IP limit of public uploads counts an IPv6 client per /64 instead of per address.
- `GET /api/content/{id}` returns `400` instead of `404` when `{id}` is not a valid UUID.
- `POST /api/upload` answers `415` to a body that is not `application/json` and `400` to invalid JSON.

### Added

**Admin panel**

- `/admin` with a first-login setup of a single admin account (Argon2id hash in `data/admin/credentials.json`), tabs Overview, Settings, Account, and an admin bar on every page (Upload · Files · Stats · Admin), shown only to the logged-in admin.
- Encrypted `HttpOnly`, `SameSite=Strict` session cookie limited to `/api/admin`, at most 8 hours by default; logout and password change end every session.
- Overview: active assets, uploads per IP, usage against limits; early deletion of assets.
- Admin actions, including failed logins, are logged.

**Settings**

- Every limit and server option in `data/admin/settings.json`, edited from the panel in one section per type, each saved on its own, with per-field errors, "Restore defaults", and a notice when a restart is needed. Every change is logged.
- `GET /api/limits` returns the upload limits; the upload page builds its duration slider from them.
- **Restart server** button: a graceful stop and a restart in the same process, so restart-only settings apply without touching the container.

**File sharing** (`/files`, tabs Share · Requests · Received)

- Files of any type stored on disk in `data/storage/`, shared through `/f/{id}` with an expiry, an optional download limit, and an optional opening time. Uploads stream to disk with progress and cancel; downloads are whole-file attachments, each one counted. Files survive restarts; orphaned or partial files are cleaned up at startup.
- Optional encryption per file: a random 256-bit key, AES-256-GCM in 64 KiB chunks while uploading and downloading. The key is sent to the downloader apart from the link and entered on the download page, in a POST body, never in a URL; a wrong key does not use up a download. The admin can show a key again with the password: keys are wrapped for the admin's X25519 key pair, whose private key is encrypted with a key derived from the password.
- Upload requests: links (`/r/{id}`) that let anyone send files to the admin, with a title, message, total size (100 MB by default), largest file, accepted extensions, optional number of files, optional expiry, and an optional required uploader name. Received files are encrypted on arrival for the admin, never get a public link, and are downloaded from the **Received** tab with the password.
- Limits in the settings: largest file, disk budget, longest duration.

**HTTPS and abuse limits**

- `public_url`, used for every copied link.
- HTTPS served by the server itself, for setups without a TLS proxy: a generated self-signed certificate or PEM files, chosen in the panel. While HTTPS runs, plain HTTP redirects to it; if it cannot start, the server falls back to HTTP and the panel shows why.
- The admin cookie is `Secure` when HTTPS runs in the server or when the public URL is `https://` behind a TLS proxy; `ADMIN_COOKIE_SECURE` overrides that rule.
- Wrong admin passwords lock a client out (5 attempts, 15 minutes by default) on login and every password prompt.
- Request links accept at most 30 files per client per hour by default.

**Other**

- Log events are also printed to standard output, for `docker logs` / `podman logs`.
- Pages fit phone screens.
- Uploaded text is served as `text/plain; charset=utf-8`.
- New dependencies: `actix-session`, `argon2`, `aes-gcm`, `x25519-dalek`, `hkdf`, `sha2`, `getrandom`, `zeroize`, `rustls` (ring backend), `rcgen`.

### Removed

- The unused `actix-files` dependency.

### Fixed

- On every page only the content area scrolls; the footer stays below it and no longer covers the end of long pages.
- The per-IP upload limit is keyed by the asset's own expiry time, so releasing a slot always frees the right one.
- A failed log rotation no longer makes every later log write fail; logging continues in the current file.
- A missing `data/html/` directory no longer panics on the first request.

## [1.3.0] - 2026-11-04

### Security

- Uploads are limited to `text/plain` and raster image types; HTML and SVG are rejected with 415.
- The stats page escapes activity fields, closing a stored XSS through `content_type`.
- Uploaded content is served with a sandbox CSP, and all responses carry security headers.
- `Forwarded` and `X-Forwarded-For` are ignored unless the peer is listed in `TRUSTED_PROXIES`.
- `highlight.js` is loaded with Subresource Integrity.
- Dependencies are updated, resolving 6 of the 7 RustSec advisories reported by `cargo audit`.

### Added

- `TRUSTED_PROXIES` environment variable for running behind Traefik, Caddy, or another reverse proxy.
- Automated tests.

### Changed

- The container image is a multi-stage build that runs as UID 1000 and listens on port 8080. Update proxy targets to port 8080 and make `./data` writable by UID 1000.
- Total in-memory storage is capped at 512 MB; a full store now returns 503 instead of 500.
- `/api/stats` uses in-memory counters instead of reading the log file.
- Logs rotate at 50 MB while running, and only the 10 most recent rotated logs are kept.

### Fixed

- Log write failures no longer stop the cleanup task.
- Expired assets are never served, even before cleanup removes them.
- Asset reads no longer copy every stored asset.
- The rate limiter forgets idle clients and returns the slot when storing fails.
- `data/logs/` is created at startup if missing.
- Unknown paths return 404 instead of 200.
- Rotated log names no longer contain a space.

## [1.2.1] - 2026-09-11

### Fixed

- Pasted images are now accepted from both clipboard files and clipboard items, improving browser compatibility.
- The upload UI now preserves the original image MIME type instead of forcing pasted and selected images to `image/png`.
- JSON upload payloads now allow for base64 expansion while still enforcing the decoded 3 MB asset limit.
- Clipboard paste failures now show a user-facing error instead of failing silently.

## [1.1.0] - 2026-01-25

### Added

- Shared HTML footer template injected into all pages.
- Structured log file handler with rotation, append-only writes, and stats parsing support.
- Upload size guard using `MAX_ASSET_SIZE_BYTES`.
- Unit tests for core storage and rate limiting behavior.

### Changed

- Asset storage cleanup and capacity checks are now race-safe.
- Stats aggregation now reads from the structured log file helper.

## [1.0.1] - 2026-01-16

### Fixed

- Asset addition logging now displays immediately instead of being buffered (changed `print!` to `println!`).
- Upload functionality blocked after first successful upload - users can now only upload once per page session.
- Paste, drag & drop, and file selection disabled after successful upload to prevent confusion.
- JavaScript syntax errors in event listener registration that prevented copy/paste functionality.
- Removed nested and duplicated event listeners that caused unexpected behavior.

### Changed

- Added `uploadCompleted` flag to track upload state and prevent multiple uploads per session.
- Reset button now properly clears the `uploadCompleted` flag to allow new uploads.

## [1.0.0] - 2026-01-14

### Added

- UI error banner for failed uploads, including retry timing.
- `retry_after_seconds` in the upload error response to inform clients when to retry.
- Server-side duration clamping for uploads (1-60 minutes).

### Changed

- Upload throttling now tracks active assets per user using asset expiration times.
- Upload error responses are consistently JSON.

### Removed

- `Retry-After` response header on upload limit errors.

## [0.3.0] - 2026-01-13

### Added

- Favicon set and web manifest for site branding.
- Syntax-highlighted rendering for code-like text content in the viewer.
- Startup log rotation that archives the previous log with a timestamp.

### Changed

- Access logs now write to `data/logs/log.txt` instead of `access.log`.

## [0.2.0] - 2026-01-11

### Added

- Default implementation for the asset model to simplify log parsing fallbacks.
- Basic UI polish for the stats page (background glow and hover highlight on recent activity).

### Changed

- Asset logging now records serialized values without cloning asset content.
- Release workflow uses tag-based versioning and caches Rust/toolchain artifacts.

## [0.1.1] - 2026-01-09



## [0.1.0] - 2026-01-09

### Added

- **Statistics Dashboard** (`/stats.html`) with real-time metrics:
  - Active assets count
  - Total uploads and deletions
  - Storage usage
  - Image vs text breakdown
  - Average server response time
  - Total request count
  - Recent activity feed (last 20 events)
  - Auto-refresh every 30 seconds
- **Statistics API** (`GET /api/stats`) returning JSON metrics
- **Enhanced logging** for asset events:
  - Upload events with uploader IP, MIME type, size, duration, timestamps
  - Delete events with full asset metadata
  - Request timing (`dur_ms`) in access logs
- **Uploader IP tracking** stored with each asset for audit purposes
- Stats link in index page footer
- Ephemeral image and text sharing with configurable TTL (1-60 minutes)
- Drag/drop, paste, and file picker upload support
- Base64 encoding for images, raw text for plain text
- UUID-based asset storage as JSON files
- Background cleanup task (every 60 seconds)
- Dark theme UI with zoom overlay
- View page for shared content
- Access logging with timing, IPs, and user agent
- Docker and docker-compose support with Traefik labels
- Environment variables for bind address and port
- Access logging with timing, IPs, and user agent
- Docker and docker-compose support with Traefik labels
- Environment variables for bind address and port
