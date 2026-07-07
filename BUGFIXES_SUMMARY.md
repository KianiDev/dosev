## [1.7.5] – 2026-07-08

### Fixed
- **Connection flood** – reduced the number of simultaneous connections during upstream probing and parallel queries.
  - The `parallel` load‑balancing strategy now limits concurrency to 5 tasks per query via a semaphore.
  - HTTP/3 and HTTP/2 auto‑detection now use a single attempt without retries and cache failed probes to avoid repeated timeouts.
  - Health checks now use a single attempt without retries.
- **`_with_retries`** – added a `no_retry` flag to bypass retries when they are not needed (e.g., probing, health checks).

### Performance
- Reduced QUIC handshake storms and timeout errors in high‑traffic scenarios.
- Failure caching for DoH version auto‑detection prevents repeated probing of non‑HTTP/3 endpoints.

### Documentation
- No user‑facing configuration changes – all fixes are internal.