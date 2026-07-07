# v1.5.0 (2026-07-08)

## Features

- **Load balancing strategies**: Added `parallel`, `random`, and `roundrobin` upstream selection strategies (in addition to existing `failover`).
  - `parallel`: query all upstreams concurrently, return first success.
  - `random`: pick a random upstream for each query.
  - `roundrobin`: cycle through upstreams in order.
- **Configuration**: New `load_balancing` option in `[advanced]` section.

## Bug Fixes

- **Parallel strategy**: Fixed `asyncio.wait()` usage to pass `Task` objects instead of bare coroutines (required for Python 3.14+).
- **Tests**: Made `test_load_balancing_parallel` deterministic and fixed cache-related issues in `test_load_balancing_random` and `test_load_balancing_roundrobin`.

## Other

- Documentation updated for all new strategies.
- All 90 tests now pass on Windows, macOS, and Linux (Python 3.10–3.14).
