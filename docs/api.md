# Web Endpoints and API

[README](../README.md) · [Configuration](configuration.md) · [Admin](admin.md) · [API](api.md) · [Architecture](architecture.md)

## Web Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Upload page |
| `GET` | `/bhs/{id}` | View a shared asset |
| `GET` | `/stats` | Statistics dashboard |
| `GET` | `/admin` | Admin control panel (login required) |
| `GET` | `/files` | File sharing for the admin (login required) |
| `GET` | `/f/{id}` | Download page of a shared file |
| `GET` | `/r/{id}` | Upload page of an upload request |

Unknown paths return the error page with status `404`.

## API

### Upload

`POST /api/upload`

Request body:

```json
{
  "duration": 5,
  "content_type": "text/plain",
  "content": "hello world"
}
```

For images, `content` must be a base64-encoded payload string and `content_type` must be one of `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `image/avif`, or `image/bmp`. The only accepted text type is `text/plain`. SVG and HTML are rejected because they can run scripts.

Successful response:

```json
{
  "link": "/bhs/550e8400-e29b-41d4-a716-446655440000"
}
```

Possible error responses include:

- `400 Bad Request` for invalid JSON or invalid base64 input
- `413 Payload Too Large` for assets above `max_asset_size_bytes`
- `415 Unsupported Media Type` for a body that is not `application/json`, or a `content_type` that is not allowed
- `429 Too Many Requests` when the active upload limit is exceeded
- `503 Service Unavailable` when the in-memory storage is full

The requested duration is clamped to the configured range, `1..=60` minutes by default.

### Limits

`GET /api/limits`

Returns the current upload limits, which the upload page uses for its duration slider:

```json
{
  "min_duration_minutes": 1,
  "max_duration_minutes": 60,
  "max_asset_size_bytes": 3145728
}
```

### Fetch Shared Content

`GET /api/content/{id}`

Returns the raw content with the stored MIME type and a sandbox `Content-Security-Policy`. Returns `400` if `{id}` is not a valid UUID, or `404` if the asset has expired or does not exist.

### Shared Files

`GET /api/files/{id}/info`

Public details of a shared file: `name`, `size`, `expires_at`, `valid_from` (or `null`), `available`, `downloads_left` (or `null` when unlimited), and `encrypted`. Times are Unix milliseconds. Returns `404` when the file does not exist, has expired, or reached its download limit.

`GET /api/files/{id}`

Sends the whole file as `application/octet-stream` with `Content-Disposition: attachment` and a sandbox `Content-Security-Policy`, so a browser always saves it and never renders it.

- Every request is one counted download. `Range` requests are not supported on purpose: a download limit could otherwise be bypassed by fetching the file in pieces, so an interrupted download restarts from the beginning.
- When the last allowed download starts, the file is deleted; that download still completes.
- `403` with `valid_from` before the opening time, `404` as above, `400` for an invalid id.
- An encrypted file is refused with `403` and `"encrypted": true`: use the POST route below.

`POST /api/files/{id}` with the form body `key=<file key>`

Downloads an encrypted file, decrypted while it is sent; the response is the same as for the GET route. The key goes in the body so it never appears in a URL, a browser history, or an access log. The key is checked on the first chunk before the download is counted: a wrong key gets `403` and does not use up a download; a key that is not 43 base64url characters gets `400`. If the stored file was changed on disk, the decryption fails and the response is cut short instead of delivering a corrupted file.

`POST /api/files/{id}/check` with the form body `key=<file key>`

Checks a key without downloading: `204` when it opens the file, `403` for a wrong key, `400` for a file that is not encrypted or a malformed key, `404` and `403` (opening time) as above. The download page calls it before starting the download.

### Upload Requests

`GET /api/requests/{id}`

What the upload page of a request shows: `title`, `message`, `max_file_size_bytes` (the request's limit, or the per-file limit in the settings if lower), `max_total_bytes` and `bytes_left` (all files together), `extensions` (empty means any type), `files_left` (or `null` when unlimited), `require_name`, and `expires_at` (or `null`). `400` for an invalid id, `404` when the request does not exist or was closed, `410` when it has expired.

`POST /api/requests/{id}/files?name=&uploader=`

Raw file bytes as the body, `Content-Length` required (`411` without it). No login: the request id is the permission. The file is encrypted for the admin as it arrives and never gets a public link.

- `201` with `name` and `size`.
- `400` for an invalid id, a missing name, a missing uploader name when the request requires one, or a body that does not match its length.
- `410` when the request has expired or has received all the files it accepts, `404` when it does not exist or was closed.
- `413` over the request's per-file limit, or over what is left of its total (with `bytes_left`); `415` for an extension the request does not accept; `507` when the storage budget is full.
- `429` with `Retry-After` when the client sent `max_request_uploads_per_ip_per_hour` files in the last hour.
- `503` while the admin has no encryption keys yet (they are created at the admin's next login).

### Stats

`GET /api/stats`

Returns counters and recent activity kept in memory since the last startup, including:

- active assets
- total uploads
- total deleted
- storage bytes
- image count
- text count
- total requests
- recent upload and delete events

## Admin API

All routes are under `/api/admin`, take and return JSON, and are never cached.

| Method | Path | Login | Description |
| --- | --- | --- | --- |
| `GET` | `/status` | no | `configured`, `authenticated`, `username`, `started_at` (when the server process started, Unix ms) |
| `POST` | `/restart` | yes | `202`, then the server stops gracefully and starts again in the same process (see [Restart](admin.md#restart)). Logged |
| `POST` | `/setup` | no | `{ "username", "password" }`; only while no account exists, otherwise `409` |
| `POST` | `/login` | no | `{ "username", "password" }`; `401` on wrong credentials |
| `POST` | `/logout` | yes | Ends every admin session |
| `POST` | `/password` | yes | `{ "current_password", "new_password" }`; `403` if the current password is wrong |
| `GET` | `/assets` | yes | Active assets |
| `DELETE` | `/assets/{id}` | yes | Delete an asset now; `204`, `400` for an invalid id, `404` if missing |
| `GET` | `/stats` | yes | Usage, limits, and active uploads per IP |
| `GET` | `/settings` | yes | `current` (saved), `running` (in use since startup), and `defaults` settings, `restart_fields`, and `restart_pending` |
| `POST` | `/files?name=&duration_minutes=&max_downloads=&valid_from=&encrypt=` | yes | Raw file bytes as the body, `Content-Length` required (`411` without it). `duration_minutes` counts from `valid_from` (Unix ms) when given. With `encrypt=true` the file is encrypted and the response includes its `key`, returned only here. `201` with the file and its `link`; `400` invalid input or a body that does not match its length, `413` over `max_file_size_bytes`, `507` over `max_files_total_bytes` (encrypted files count 16 bytes more per 64 KiB), `409` when the encryption keys do not exist yet (log in again) |
| `GET` | `/files` | yes | Shared files that have not expired, with downloads, `encrypted`, and `link` |
| `POST` | `/files/{id}/key` | yes | `{ "password" }`; `200` with the `key` of an encrypted file, `403` if the password is wrong, `400` if the file is not encrypted, `404` if missing. Logged |
| `DELETE` | `/files/{id}` | yes | Delete a shared file now; `204`, `400` for an invalid id, `404` if missing |
| `POST` | `/requests` | yes | `{ "title", "message", "max_total_bytes", "max_file_size_bytes", "extensions": [], "max_files", "require_name", "expires_in_minutes" }`. `max_total_bytes` defaults to 100 MiB and may not exceed `max_files_total_bytes`; `max_file_size_bytes` defaults to the total, may not exceed it nor the per-file limit. `201` with the request, `files_left`, and its `link`; `400` with an `error` when invalid |
| `GET` | `/requests` | yes | Upload requests, newest first, with `uploads`, `files_left`, and `link` |
| `DELETE` | `/requests/{id}` | yes | Close a request: its link stops accepting files; received files stay. `204`, `404` if missing |
| `GET` | `/received` | yes | Received files, newest first: `id`, `name`, `size`, `received_at`, `request_id`, `request_title`, `uploader`, `ip` |
| `POST` | `/received/check` | yes | `{ "password" }`; `204` if it unlocks the admin key, `403` if not. The page calls it before a download |
| `POST` | `/received/{id}/download` | yes | Form body `password=`; the decrypted file as an attachment. `403` wrong password, `404` if missing. Logged |
| `DELETE` | `/received/{id}` | yes | Delete a received file; `204`, `404` if missing |
| `PUT` | `/settings` | yes | Every setting, all fields required; `400` with `fields: [{ field, message }]` when invalid. Saves and applies them, and returns the same body as `GET` |

Usernames are 1 to 64 characters without control characters or surrounding spaces; passwords are 8 to 256 characters. Routes that need a login return `401` without a valid session.
