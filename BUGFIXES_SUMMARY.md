# [1.7.3] – 2026-07-08

## Fixed

- **HTTP/3 client** – `H3Protocol` now inherits from `QuicConnectionProtocol` and properly handles `connection_made`. This eliminates the `'H3Protocol' object has no attribute 'connection_made'` error.

## Changed

- **Dependencies** – `httpx` is now installed with the `[http2]` extra, ensuring HTTP/2 support is available. This prevents fallback to HTTP/1.1 when the upstream does not support HTTP/3.
