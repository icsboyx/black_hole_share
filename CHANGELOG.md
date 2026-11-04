# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
