# Black Hole Share

<p align="center">
  <img src="./data/html/logo.png" alt="Black Hole Share logo" width="220">
</p>

Black Hole Share is a lightweight temporary sharing service built with Rust and Actix Web. Anyone can share images or plain text, kept in memory for a short time behind a unique URL. The admin can also share files of any size from disk, optionally encrypted, and create upload links that let others send files back, encrypted on arrival.

## Features

- **Public sharing**: text and images by drag and drop, paste, or file picker; links that expire after 1 to 60 minutes by default; kept in memory only
- **Admin panel** (`/admin`): usage, active assets, every setting editable from the browser, restart button
- **File sharing**: any file type stored on disk, with expiry, download limit, opening time, and optional encryption with a key per file
- **Upload requests**: links that let anyone send files to the admin, with size, type, and count limits, encrypted on arrival
- **HTTPS**: behind a TLS proxy (Caddy, Traefik, nginx), or served directly with a self-signed certificate or your own
- **Safety**: upload type allowlist, sandboxed content, security headers, per-IP limits, lockout after wrong admin passwords
- Stats page, JSON logs with rotation, also on standard output; pages that fit phone screens

## Quick Start

### Docker Compose

```bash
docker compose up --build
```

The compose file builds the image, publishes ports `8080` (HTTP) and `8443` (HTTPS, used only once enabled in the panel), and mounts `./data` at `/data`. The container runs as UID `1000`, so `./data` must be writable by that UID.

### Podman

```bash
podman build -t bhs .
podman run -d --name bhs -p 8080:8080 -p 8443:8443 --userns=keep-id -v ./data:/data bhs
podman logs -f bhs
```

`--userns=keep-id` maps UID `1000` to your user with rootless Podman (`userns_mode: keep-id` in a compose file).

### Without a container

Requirements: a Rust toolchain, the `data/html/` directory from this repository, and write access to `data/`.

```bash
cargo run --release
```

### First start

1. Open `http://127.0.0.1:8080/admin` and **create the admin account right away**: until it exists, whoever opens `/admin` first becomes the admin.
2. In **Settings → Address & HTTPS**, set the **Public URL** people use (for example `https://share.example.com`). Behind a reverse proxy, also add its IP to **Trusted proxies**.
3. To serve HTTPS from the server itself, choose a self-signed certificate or your own files, then press **Restart server**. Port `8443` must be published.

**Back up `data/`**: it holds the admin credentials and the key that decrypts received files. Without `data/admin/credentials.json`, those files cannot be read again.

### Environment variables

Address, ports, trusted proxies, and the public host name can also be fixed from the container environment; the panel then shows them as read-only:

```yaml
    environment:
      - BIND_ADDR=0.0.0.0
      - BIND_PORT_HTTP=8080
      - BIND_PORT_HTTPS=8443
      - TRUSTED_PROXIES=192.168.250.100
      - EXTERNAL_FQDN=share.example.com
```

See [Environment variables](docs/configuration.md#environment-variables). Upgrading from 1.x: `BIND_PORT` is now `BIND_PORT_HTTP`; see [Upgrading from 1.x](docs/configuration.md#upgrading-from-1x).

## Documentation

| Document | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Every setting, limits, HTTPS, reverse proxy, upgrading from 1.x |
| [Admin panel](docs/admin.md) | Login and sessions, file sharing, encryption, upload requests, restart |
| [API](docs/api.md) | Web endpoints, public API, admin API |
| [Architecture](docs/architecture.md) | How it works, runtime behavior, logging, project layout, development |
| [Block diagram](docs/block-diagram.md) | Component diagram |
| [Changelog](CHANGELOG.md) | Release notes |
