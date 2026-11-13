# Configuration

[README](../README.md) · [Configuration](configuration.md) · [Admin](admin.md) · [API](api.md) · [Architecture](architecture.md)

## Settings

Settings live in `data/admin/settings.json` and are edited in the **Settings** section of the admin panel. The file is created with the defaults on first start. A file that cannot be parsed, has an unknown field, or holds a value outside the allowed range stops startup and names the problem; a missing field takes its default.

| Setting | Default | Allowed | Applies |
| --- | --- | --- | --- |
| `min_asset_duration_minutes` | `1` | 1 or more, not above the maximum | immediately |
| `max_asset_duration_minutes` | `60` | up to 1440 | immediately |
| `max_assets` | `1000` | 1 to 100000 | immediately |
| `max_asset_size_bytes` | `3145728` (3 MiB) | 1 to 104857600 (100 MiB) | immediately |
| `max_total_storage_bytes` | `536870912` (512 MiB) | not below `max_asset_size_bytes` | immediately |
| `max_uploads_per_ip` | `10` | 1 to 10000 | immediately |
| `max_file_size_bytes` | `1073741824` (1 GiB) | 1 to 107374182400 (100 GiB) | next file upload |
| `max_files_total_bytes` | `10737418240` (10 GiB) | not below `max_file_size_bytes` | next file upload |
| `max_file_duration_minutes` | `10080` (7 days) | 1 to 525600 (365 days) | next file upload |
| `max_log_file_bytes` | `52428800` (50 MiB) | at least 1048576 (1 MiB) | next write |
| `max_rotated_logs` | `10` | 0 to 1000 | next rotation |
| `max_recent_activity` | `20` | 1 to 1000 | immediately |
| `trusted_proxies` | `[]` | up to 64 IP addresses | immediately |
| `admin_session_max_age_minutes` | `480` | 5 to 10080 | after restart |
| `bind_addr` | `0.0.0.0` | an IP address | after restart |
| `bind_port` | `8080` | 1 to 65535 | after restart |
| `public_url` | `""` | empty, or `http(s)://host[:port]` without a path | immediately (links); the cookie flag after restart |
| `tls_mode` | `"off"` | `"off"`, `"self_signed"`, `"files"` | after restart |
| `tls_cert_path` | `""` | PEM certificate chain; required for `"files"` | after restart |
| `tls_key_path` | `""` | PEM private key; required for `"files"` | after restart |
| `https_port` | `8443` | 1 to 65535, not `bind_port` while TLS is on | after restart |
| `max_login_failures` | `5` | 1 to 100 | immediately |
| `login_lockout_minutes` | `15` | 1 to 1440 | immediately |
| `max_request_uploads_per_ip_per_hour` | `30` | 1 to 10000 | immediately |

When the server runs in a container, changing `bind_addr`, `bind_port`, or `https_port` also needs a matching port mapping (for example `-p 8443:8443`), or the server is unreachable after the restart.

One environment variable is still read:

| Environment Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_COOKIE_SECURE` | unset | Forces the admin cookie's `Secure` flag (`true` or `false`); any other value stops startup. Unset, the flag follows the HTTPS setup (see [HTTPS](#https)). Keep it for emergencies |

`BIND_ADDR`, `BIND_PORT`, and `TRUSTED_PROXIES` are no longer read; the server prints a warning if they are set.

## Limits

Defaults; all of them can be changed in the admin panel (see [Configuration](#settings)).

| Item | Default |
| --- | --- |
| Asset TTL | 1 to 60 minutes |
| Max decoded asset size | 3 MiB |
| Max in-memory assets | 1000 |
| Max total in-memory size | 512 MiB |
| Max active uploads per IP | 10 |

The per-IP limit is released as that client's shared items expire. Image uploads are sent as base64 in JSON, so the HTTP request body may be larger than the decoded asset; the server accepts a body of up to twice the asset size limit plus 1 KiB.

## HTTPS

The first start serves plain HTTP. HTTPS is set up in **Address & HTTPS** in the admin panel:

- **Public URL** (`public_url`): the address people use, like `https://share.example.com`. Every link copied from `/files` uses it, so a link copied while you work from a LAN address still works outside.
- **HTTPS in this server** (`tls_mode`, after a restart):
  - **Off**: plain HTTP. The right choice behind a reverse proxy that does TLS (Caddy, Traefik, nginx); the proxy gets and renews the certificate with ACME.
  - **Self-signed**: a certificate generated in `data/admin/tls/` for the public URL's host, `localhost`, and `127.0.0.1`, regenerated when those names change. Browsers warn about it; the panel shows its SHA-256 fingerprint to compare.
  - **Own certificate files**: PEM chain and key by path (inside the container, for example under `/data/admin/tls/`).
- While HTTPS runs on `https_port`, the HTTP port answers every request with a `308` redirect to it.
- If HTTPS cannot start (missing or mismatched files, port in use), the server serves plain HTTP and the panel shows the error, so the configuration can be fixed from the browser.

The admin cookie is `Secure` when this server serves HTTPS, or when its TLS is off and the public URL starts with `https://` (a proxy in front does TLS). Browsers do not send `Secure` cookies over plain HTTP except to `localhost`, so after that restart log in through the HTTPS address. `ADMIN_COOKIE_SECURE` overrides the rule.

**Behind Caddy**: keep HTTPS off here, set the public URL to the `https://` address, and add Caddy's IP to the trusted proxies.

## Reverse Proxy

Behind a reverse proxy, add the proxy IP to **Trusted proxies** in the admin panel (`trusted_proxies` in `settings.json`). Separate multiple proxies with commas. CIDR ranges are not supported, so give the proxy a fixed IP.

```json
"trusted_proxies": ["10.89.77.2"]
```

The client address used for upload limits and logs is resolved as follows:

| Request comes from | Address used |
| --- | --- |
| A proxy in `trusted_proxies` | The last untrusted entry in `X-Forwarded-For`, or the proxy IP if there is none |
| Any other peer | The connection IP; forwarding headers are ignored |

Without `trusted_proxies`, every client appears to come from the proxy and all of them share one upload limit.

Do not enable an option that makes the proxy trust incoming forwarding headers, such as `forwardedHeaders.trustedIPs` in Traefik or `trusted_proxies` in Caddy, unless another proxy sits in front of it.

Traefik labels:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.bhs.rule=Host(`bhs.example.com`)"
  - "traefik.http.services.bhs.loadbalancer.server.port=8080"
```

Caddyfile:

```text
bhs.example.com {
    reverse_proxy bhs:8080
}
```

## Upgrading from 1.x

- `BIND_ADDR`, `BIND_PORT`, and `TRUSTED_PROXIES` are no longer read: after the first start, set them in **Settings** in the admin panel. The server warns while they are still set.
- Open `/admin` right after the first start and create the admin account: until then, whoever opens `/admin` first becomes the admin.
- Behind a TLS proxy, set **Public URL** to the `https://` address and add the proxy to **Trusted proxies**, then restart: the admin cookie becomes `Secure`.
- `data/` gains `admin/` and `storage/`; mount the whole directory and back it up.
