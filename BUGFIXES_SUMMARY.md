## [1.7.0] – 2026-07-08

### Added
- **`--version` flag** – print the current version and exit.
- **DNSSEC CD flag support** – respect the client's Checking Disabled (CD) flag. When set, DNSSEC validation is skipped, allowing for `dig +cd`‑style queries.

### Changed
- **Refactored `forward_dns_query`** – split into smaller, testable helpers: `_check_hosts_and_blocklists`, `_check_caches`, `_execute_strategy`, and `_process_upstream_response`. No functional change; improves maintainability.

### Fixed
- **CI coverage** – installed package in editable mode so `pytest-cov` correctly collects coverage.
- **Test stability** – resolved flaky tests in `test_dnssec_cd` and `test_load_balancing` by using proper DNS responses and patching.

### Documentation
- Added note about CD flag support in `config-reference.md` and `architecture.md`.

### Testing
- New tests for `--version` and DNSSEC CD flag.
- All 103 tests pass on Windows, macOS, and Linux for Python 3.10–3.14.