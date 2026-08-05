# [1.9.0] – 2026-08-05

## Added

- **HTTP/3 DoH connection pooling** (`resolver.py`) – New `H3DohProtocol` and `H3ConnectionPool` classes enable persistent HTTP/3 connections for DoH upstreams, reducing handshake overhead. Connections are reused across multiple queries with proper stream management.
- **EDNS Client Subnet (ECS) support** (`resolver.py`) – Implements RFC 7871 with privacy-safe truncation: IPv4 addresses truncated to /24, IPv6 to /56. Configurable via `dns_ecs_enabled` (default: true).
- **Bailiwick scrubbing** (`resolver.py`, `server.py`) – New `_scrub_unsolicited_sections()` method removes out-of-bailiwick NS records from the authority section to prevent cache poisoning attacks (RFC 2181 §5.4.1, CVE-2025-11411). Configurable via `dns_scrub_unsolicited_ns` (default: true).
- **Request coalescing (single-flight)** (`resolver.py`) – Deduplicates concurrent identical queries by storing canonical responses and stamping per-caller ID/CD bit. Exception-safe future handling prevents hanging followers.
- **New configuration options**:
  - `initial_backoff` (in `[advanced]`, default: `0.1`) – Initial backoff in seconds before first retry, doubles each attempt.
  - `dnssec_chain_validation` (in `[security]`, default: `true`) – Enable recursive chain-of-trust validation (fetches DS/DNSKEY). If false, falls back to legacy static validation using only the root anchor.
  - `dnssec_max_iterations` (in `[security]`, default: `100`) – Maximum number of validation steps to prevent infinite loops (RFC 9276).
- **Health check system** (`resolver.py`) – Circuit breaker for upstreams with configurable thresholds: `unhealthy_threshold`, `healthy_threshold`, `cooldown`, `interval`, and `timeout`. Tracked via `_upstream_health` dictionary.
- **Background task tracking** (`resolver.py`) – All background tasks (DNSSEC trust anchor updater, rate limiter cleanup, pool cleanups, health checks) are now tracked in `_background_tasks` set for clean shutdown.

## Changed

- **Python requirement increased** (`pyproject.toml`, `.github/workflows/ci.yml`) – Minimum version raised from **Python 3.10** to **Python 3.11**. CI now tests on Python 3.11–3.14 (previously 3.10–3.14).
- **Rate limiter now actually enforced** (`resolver.py`, `server.py`) – Previously a no-op; now properly called via `_check_rate_limit()` in `forward_dns_query()` and all transport handlers (UDP, TCP, DoH, HTTP/3). RateLimiter class improved with value clamping and bucket cleanup.
- **DNSSEC validation improvements** (`resolver.py`):
  - Chain validation wrapped in `asyncio.wait_for()` with `dnssec_validation_timeout` to prevent hanging.
  - CPU-bound crypto operations (e.g., `validate_rrsig`) offloaded to dedicated `_CRYPTO_EXECUTOR` (ThreadPoolExecutor with 4 workers) to prevent event loop blocking.
  - DNSSEC caches (`_dnssec_key_cache`, `_dnssec_ds_cache`, `_dnssec_insecure_cache`) now have bounded size limits and periodic expiry cleanup via `_cleanup_insecure_cache()`.
- **Connection pool improvements** (`resolver.py`):
  - Fixed pool size enforcement: now uses `>= max_size` instead of `< max_size` for eviction.
  - Better cleanup: tasks properly cancelled, connections closed on stop.
  - Added `H3ConnectionPool` for HTTP/3 DoH connections.
- **UDP transaction-ID verification** (`resolver.py`) – Per-upstream `asyncio.Lock` in `_udp_locks` and response ID matching to prevent cross-response contamination.
- **DoQ certificate verification** (`resolver.py`) – Changed from `ssl.CERT_NONE` to `ssl.CERT_REQUIRED` with proper CA bundle loading.

## Fixed

- **Rate limiter not being invoked** – Fixed by calling `await resolver._check_rate_limit(client_ip)` at the start of `forward_dns_query()` and in all server transport handlers (UDP, TCP, DoH, HTTP/3).
- **DS digest-type hardcoded fallback** (`resolver.py`) – Now uses the actual `digest_type` from the DS record instead of hardcoded SHA-256/SHA-1 fallback.
- **NSEC3 wrap-around range check** (`resolver.py`) – Fixed to properly handle the hash ring end-of-zone condition per RFC 9276.
- **UDP response ID matching** (`resolver.py`) – Prevents cross-response contamination by verifying response transaction IDs match the query.
- **DoQ certificate verification missing** – Now properly verifies upstream certificates using `CERT_REQUIRED`.
- **HTTP/2 DoH NameError on pooled reuse** – Fixed by properly handling pooled connection state.
- **Connection pool cleanup tasks not cancelled** – Now properly cancelled during shutdown via `stop_pool_cleanups()`.
- **Various DNSSEC validation edge cases** – Multiple fixes for chain validation, including proper handling of DS/DNSKEY record fetching and validation limits.

## Removed

- **Python 3.10 support** – The project now requires Python 3.11 or later.

## Security

- **DoQ certificate verification** – Now enforces `CERT_REQUIRED` with proper CA bundle, preventing MITM attacks on DoQ connections.
- **UDP transaction-ID verification** – Prevents response spoofing attacks by ensuring responses match the original query ID.
- **Bailiwick scrubbing enabled by default** – Protects against cache poisoning via unsolicited NS records (CVE-2025-11411).
