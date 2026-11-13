# Admin Panel

[README](../README.md) · [Configuration](configuration.md) · [Admin](admin.md) · [API](api.md) · [Architecture](architecture.md)

Open `/admin`. Uploading, viewing, and the public stats stay open to everyone; only the panel requires a login.

## First login

While no admin account exists, `/admin` shows a form that creates it, and the server prints `Admin credentials not set` at startup. **Whoever opens `/admin` first becomes the admin**, so create the account right after the first start, before exposing the service.

There is a single admin account. Its credentials are stored in `data/admin/credentials.json` (username, an Argon2id password hash, and the key pair for [encrypted files](#encrypted-files), file mode `0600`). To reset them, stop the server, delete that file, and start again: the setup form appears again. A credentials file that cannot be read stops startup instead of reopening the setup.

## Sessions

- Login sets the `bhs_admin` cookie: encrypted with the key in `data/admin/session.key`, `HttpOnly`, `SameSite=Strict`, limited to `/api/admin`, and `Secure` as described in [HTTPS](configuration.md#https).
- A session lasts at most `admin_session_max_age_minutes` (8 hours by default).
- Logging out or changing the password ends every admin session, on every device.
- Browsers accept `Secure` cookies on `http://localhost` and `http://127.0.0.1` only. Once the cookie is `Secure`, log in through the HTTPS address.
- Too many wrong passwords from one client return `429` with `Retry-After` until the lockout ends.

## Features

- Usage cards: active assets, storage, totals since startup
- Active uploads grouped by uploader IP
- Active assets with type, size, uploader IP, and time left, with early deletion (the uploader's slot in the per-IP limit is freed)
- Tabs: **Overview** (usage, uploads by IP, active assets, shared file storage), **Settings**, **Account** (password change); the tab is kept in the URL (`/admin#settings`)
- Settings: one section per type (Public uploads, Files, Logs, Network, Address & HTTPS, Abuse limits, Admin session), each saved on its own, with per-field errors, a "Restore defaults" button, and a notice when a restart is needed
- **Server** card with the [Restart](#restart) button
- The admin bar on every page links the services first (Upload, Files) and then Stats and Admin

## File sharing page

`/files` is a service page, separate from the panel's management tabs. Without an admin session it only shows a link to the login; the file API refuses every request without a session anyway.

- Drag and drop or pick a file, set its name, how long it stays available, an optional download limit, and an optional opening time
- Upload with progress, speed, and cancel
- Tabs: **Share** (your files with a public link), **Requests** (links that let others send you files), **Received** (what they sent)
- Optional encryption with a new random key per file; the key is shown once after the upload (hidden behind dots, with Show and Copy) and can be shown again later with the admin password
- List of shared files with downloads, status, key, copy link, and delete
- Copied links start with `public_url` when it is set

## Encrypted files

Encryption is chosen per file at upload time. It happens on the server: the downloader only needs a browser and the key.

- Each file gets its own random 256-bit key. The content is encrypted with AES-256-GCM in 64 KiB chunks while it is uploaded, so neither the upload nor the download holds the file in memory and no plaintext copy is ever written to disk. Each chunk's nonce encodes its position and whether it is the last one, so chunks cannot be reordered, dropped, or appended.
- The key is returned once, as 43 base64url characters. Send it to the downloader separately from the link; the download page asks for it.
- So the admin can show the key again, it is also stored in `data/storage/index.json` encrypted for the admin's X25519 public key. The matching private key is kept in `data/admin/credentials.json`, encrypted with a key derived from the admin password (Argon2id). Showing a key needs the password, not only a session.
- Without the admin password, nothing on disk reveals a file key: a copy of the `data/` volume does not expose encrypted files.
- Changing the password re-encrypts the private key; keys of files shared before still open. Credentials created before encryption existed get their key pair at the next login.
- **If the credentials file is deleted** (password reset), stored keys can no longer be shown; downloaders who already have a key can still download.
- The server sees the content and the key while it encrypts and decrypts. Over plain HTTP the key travels unencrypted on the network: use HTTPS.

## Upload requests

A request is a link (`/r/{id}`) that lets someone without an account send you files.

- You set a title, an optional message, the total size of all files (100 MB by default), the largest single file (the total when empty), the accepted extensions (empty: any), an optional number of files, an optional time the link stays open, and whether the uploader's name is required. The link closes when it is full (files or bytes), expires, or you close it.
- Uploads in progress count against the total too, so files sent at the same time cannot go over it together.
- The extension is checked on the file name only. It is what the uploader called the file, not proof of its content.
- Every received file is encrypted on arrival for your X25519 public key (the same key pair as for [encrypted files](#encrypted-files)): nothing on disk can be read without your password. Downloading one asks for the password; the file is decrypted while it is sent.
- Received files never have a public link and do not expire; they count against `max_files_total_bytes` until you delete them. Closing a request keeps the files it received.
- Each received file records the request, the uploader's name, and the uploader's IP address.

## Restart

**Settings → Server → Restart server** applies the fields marked *restart* without touching the container:

- The server stops accepting connections; requests in progress, downloads included, get up to 30 seconds to finish.
- It then replaces itself with a fresh start of the same program (`exec`). The PID stays the same, so a container keeps running without a restart policy, and admin sessions stay valid.
- The page waits for the new process and reloads; when HTTPS turns on or off, it goes to the new address.
- If the saved address or ports cannot be used, the server does not come back and has to be started by hand, as after any start with that configuration. A failing HTTPS setup still falls back to plain HTTP.
