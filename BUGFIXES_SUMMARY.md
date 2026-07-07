# [1.6.0] – 2026-07-08

## Added

- **TCP fallback** – when a UDP response has the TC (truncation) bit set, dosev now automatically retries the same query over TCP and returns the full response. Enabled by default, configurable via `tcp_fallback_enabled` in the `[advanced]` section.
- **Upstream health checks** – periodic health checks with circuit‑breaker logic. Upstreams that fail consecutive checks are marked unhealthy and skipped during query routing. They auto‑recover after successful checks. Configurable via the new `[health]` section:
  - `enabled` – enable/disable
  - `interval` – check frequency
  - `timeout` – per‑check timeout
  - `unhealthy_threshold` – failures to mark unhealthy
  - `healthy_threshold` – successes to mark healthy again
  - `cooldown` – wait time before retrying unhealthy upstreams
  - `domain` – custom domain for health check queries (defaults to `.` for root SOA)

## Fixed

- **Health check task** – now properly started only when an event loop is running (resolver no longer starts background tasks in `__init__`).
- **`_fetch_root_trust_anchor_from_iana`** – removed incorrect `@staticmethod` decorator that caused `self` reference errors.
- **`_get_healthy_upstreams`** – now correctly declared as `async` and awaited.

## Documentation

- Added `[health]` section to `config-reference.md`, `architecture.md`, and the default `dosev.conf` template.
- Added `tcp_fallback_enabled` to `[advanced]` section documentation.

## Testing

- New test suite: `test_health_checks.py` (8 tests).
- New test suite: `test_tcp_fallback.py` (4 tests).
- All 101 tests pass on Windows, macOS, and Linux (Python 3.10–3.14).
