# Block Diagram

```mermaid
%%{init: {"theme": "base", "themeVariables": {"lineColor": "#33ccff", "fontFamily": "JetBrains Mono, Fira Code, monospace"}, "flowchart": {"wrappingWidth": 400}}}%%
flowchart TD
    subgraph Overview["Black Hole Share"]
        Client["Browser or API client"]
        Proxy["Reverse proxy (optional)"]
        HtmlFiles[("data/html/")]
        LogFiles[("data/logs/")]

        subgraph Process["Application"]
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

            subgraph State["Shared state"]
                Store["In-memory asset store"]
                Limit["Per-IP rate limiter"]
                Logger["Log writer"]
                Counters["In-memory stats counters"]
            end
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

    classDef external fill:#1e1e2e,stroke:#a6adc8,stroke-width:2px,color:#cdd6f4
    classDef web fill:#1a1a1a,stroke:#33ccff,stroke-width:2px,color:#cdd6f4
    classDef task fill:#1a1a1a,stroke:#a6adc8,stroke-width:2px,color:#cdd6f4
    classDef state fill:#1a1a1a,stroke:#00ff99,stroke-width:2px,color:#cdd6f4

    class Client,Proxy,HtmlFiles,LogFiles external
    class Headers,Pages,Upload,Content,Stats web
    class Cleanup task
    class Store,Limit,Logger,Counters state

    style Overview fill:#1a1a1a,stroke:#33ccff,stroke-width:2px,color:#33ccff
    style Process fill:#1e1e2e,stroke:#a6adc8,stroke-width:2px,color:#cdd6f4
    style Web fill:#1e1e2e,stroke:#33ccff,stroke-width:2px,color:#33ccff
    style Background fill:#1e1e2e,stroke:#a6adc8,stroke-width:2px,color:#a6adc8
    style State fill:#1e1e2e,stroke:#00ff99,stroke-width:2px,color:#00ff99

    linkStyle default stroke:#33ccff,stroke-width:2px
```

- The Actix Web server handles all HTTP traffic, including the pages and the API calls made by their JavaScript.
- The cleanup loop is a separate task that runs without any HTTP request.
- The web server and the cleanup loop use the same shared state.
- Assets, rate limits, and stats counters live only in memory and are lost on restart.
- `/api/stats` reads memory only. The log files are written but never read back.
- The client address comes from `X-Forwarded-For` only when the request arrives from a proxy in `TRUSTED_PROXIES`.
