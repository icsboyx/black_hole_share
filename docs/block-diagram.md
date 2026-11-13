# Block Diagram

[README](../README.md) · [Configuration](configuration.md) · [Admin](admin.md) · [API](api.md) · [Architecture](architecture.md)

```mermaid
%%{init: {"theme": "base", "themeVariables": {"lineColor": "#33ccff", "fontFamily": "JetBrains Mono, Fira Code, monospace"}, "flowchart": {"wrappingWidth": 400}}}%%
flowchart TD
    subgraph Overview["Black Hole Share"]
        Client["Browser or API client"]
        Proxy["Reverse proxy (optional)"]
        HtmlFiles[("data/html/")]
        LogFiles[("data/logs/ + stdout")]
        AdminFiles[("data/admin/<br/>credentials, session key,<br/>settings, tls/")]
        StorageFiles[("data/storage/<br/>files, index.json,<br/>requests.json")]

        subgraph Process["Application"]
            subgraph Listeners["Listeners"]
                Http["HTTP (bind_port)"]
                Https["HTTPS (https_port, optional)<br/>self-signed or PEM files"]
            end

            subgraph Web["Actix Web server"]
                Headers["Security headers<br/>+ HTTP to HTTPS redirect"]
                Pages["Pages and static files"]
                PublicApi["Public assets<br/>/api/upload, /api/content/{id},<br/>/api/limits, /api/stats"]
                FileApi["Shared files<br/>/api/files/{id} (+ key)"]
                RequestApi["Upload requests<br/>/api/requests/{id}"]
                Admin["/api/admin/* (session cookie)<br/>settings, files, requests,<br/>received, restart"]
            end

            subgraph Background["Background tasks"]
                Cleanup["Cleanup loop, every second"]
                Restart["Restart: graceful stop + exec"]
            end

            subgraph Memory["In-memory state, lost on restart"]
                Store["In-memory asset store"]
                Limit["Per-IP upload limiter"]
                Throttle["Throttles: password lockout,<br/>request uploads per hour"]
                Counters["Stats counters"]
                Logger["Log writer"]
            end

            subgraph Persistent["Stores kept on disk"]
                Creds["Admin credentials<br/>+ X25519 key pair"]
                Settings["Settings store"]
                Files["File store<br/>(shared + received, AES-GCM)"]
                Requests["Upload request store"]
            end
        end
    end

    Client --> Proxy
    Proxy --> Http
    Client --> Http
    Client --> Https
    Http --> Headers
    Https --> Headers

    Headers --> Pages
    Headers --> PublicApi
    Headers --> FileApi
    Headers --> RequestApi
    Headers --> Admin

    Pages --> HtmlFiles
    Headers -. "every request and event" .-> Logger

    PublicApi --> Store
    PublicApi --> Limit
    PublicApi --> Settings

    FileApi --> Files

    RequestApi --> Requests
    RequestApi --> Throttle
    RequestApi --> Creds
    RequestApi --> Files

    Admin --> Creds
    Admin --> Throttle
    Admin --> Settings
    Admin --> Store
    Admin --> Files
    Admin --> Requests
    Admin --> Restart

    Cleanup --> Store
    Cleanup --> Limit
    Cleanup --> Files

    Creds --> AdminFiles
    Settings --> AdminFiles
    Https --> AdminFiles
    Files --> StorageFiles
    Requests --> StorageFiles
    Logger --> Counters
    Logger --> LogFiles

    classDef external fill:#1e1e2e,stroke:#a6adc8,stroke-width:2px,color:#cdd6f4
    classDef web fill:#1a1a1a,stroke:#33ccff,stroke-width:2px,color:#cdd6f4
    classDef task fill:#1a1a1a,stroke:#a6adc8,stroke-width:2px,color:#cdd6f4
    classDef state fill:#1a1a1a,stroke:#00ff99,stroke-width:2px,color:#cdd6f4

    class Client,Proxy,HtmlFiles,LogFiles,AdminFiles,StorageFiles external
    class Http,Https,Headers,Pages,PublicApi,FileApi,RequestApi,Admin web
    class Cleanup,Restart task
    class Store,Limit,Throttle,Logger,Counters,Creds,Settings,Files,Requests state

    style Overview fill:#1a1a1a,stroke:#33ccff,stroke-width:2px,color:#33ccff
    style Process fill:#1e1e2e,stroke:#a6adc8,stroke-width:2px,color:#cdd6f4
    style Listeners fill:#1e1e2e,stroke:#33ccff,stroke-width:2px,color:#33ccff
    style Web fill:#1e1e2e,stroke:#33ccff,stroke-width:2px,color:#33ccff
    style Background fill:#1e1e2e,stroke:#a6adc8,stroke-width:2px,color:#a6adc8
    style Memory fill:#1e1e2e,stroke:#00ff99,stroke-width:2px,color:#00ff99
    style Persistent fill:#1e1e2e,stroke:#00ff99,stroke-width:2px,color:#00ff99

    linkStyle default stroke:#33ccff,stroke-width:2px
```

- The Actix Web server handles all HTTP traffic, including the pages and the API calls made by their JavaScript. Every route writes to the log writer, which also prints each event to standard output.
- HTTPS is optional and set at startup from the settings (`tls.rs`): off (the choice behind a TLS proxy), a self-signed certificate kept in `data/admin/tls/`, or PEM files. While it runs, plain HTTP is redirected to it with `308`; if it cannot start, the server serves plain HTTP only and the panel shows the error.
- The cleanup loop runs without any HTTP request and deletes expired assets and expired shared files.
- `POST /api/admin/restart` stops the server gracefully and replaces the process with a fresh start of the same binary (`exec`, same PID).
- Assets, upload limits, throttles, and stats counters live only in memory and are lost on restart. `/api/stats` reads memory only; the log files are written but never read back.
- The client address comes from `X-Forwarded-For` only when the request arrives from a proxy listed in `trusted_proxies`. Limits and throttles count an IPv6 client per /64.
- Settings are loaded from `data/admin/settings.json` at startup and changed through `/api/admin/settings`; uploads, limits, and the log writer read the current values.
- Shared files and their index live in `data/storage/`; the store reconciles the index with the directory at startup.
- Upload requests live in `data/storage/requests.json`. Files received through them are stored with the shared files, always encrypted for the admin, and excluded from every public route.
- Encrypted files are stored as AES-256-GCM chunks; their keys are wrapped for the admin's X25519 public key, whose private key in `data/admin/credentials.json` is protected by the admin password.
- Wrong admin passwords (login and every password prompt) and uploads to request links are limited per client by `throttle.rs`.
- On disk, besides the logs: admin credentials, the session key, the settings, and the self-signed certificate in `data/admin/`; shared and received files, their index, and the upload requests in `data/storage/`.
