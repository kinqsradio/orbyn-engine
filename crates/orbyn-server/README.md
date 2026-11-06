# orbyn-server

The HTTP API on axum: `/health`, `/ready`, the `/v1` account, session and device routes with the bearer-token extractor, the `/v1/zones` record store routes, the `/v1/sync` WebSocket, CORS, a 64 KiB body limit (6 MiB for uploads) and request tracing. Thin: parsing, auth and mapping only.
