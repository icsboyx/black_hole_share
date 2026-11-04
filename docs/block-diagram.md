# Block Diagram

```mermaid
flowchart TD
    Client["Browser or API client"]
    Proxy["Reverse proxy (optional)"]
    HtmlFiles[("data/html/")]
    LogFiles[("data/logs/")]

    subgraph Process["black_hole_share process"]
        subgraph Web["Actix Web server"]
            Headers["Security headers"]
            Pages["Pages and static files"]
            Upload["POST /api/upload"]
            Content["GET /api/content/{id}"]
            Stats["GET /api/stats"]
        end

        subgraph Background["Background task"]
            Cleanup["Cleanup loop, every second"]
        end

        subgraph State["Shared state (AppState)"]
            Store["In-memory asset store"]
            Limit["Per-IP rate limiter"]
            Logger["Log writer"]
            Counters["In-memory stats counters"]
        end
    end

    Client --> Proxy
    Proxy --> Headers
    Client --> Headers

    Headers --> Pages
    Headers --> Upload
    Headers --> Content
    Headers --> Stats

    Pages --> HtmlFiles
    Pages --> Logger

    Upload --> Limit
    Upload --> Store
    Upload --> Logger

    Content --> Store
    Content --> Logger

    Stats --> Store
    Stats --> Counters

    Cleanup --> Store
    Cleanup --> Limit
    Cleanup --> Logger

    Logger --> Counters
    Logger --> LogFiles
```

- The Actix Web server handles all HTTP traffic, including the pages and the API calls made by their JavaScript.
- The cleanup loop is a separate task that runs without any HTTP request.
- The web server and the cleanup loop use the same shared state.
- Assets, rate limits, and stats counters live only in memory and are lost on restart.
- `/api/stats` reads memory only. The log files are written but never read back.
- The client address comes from `X-Forwarded-For` only when the request arrives from a proxy in `TRUSTED_PROXIES`.
