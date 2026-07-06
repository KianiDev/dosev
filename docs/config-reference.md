# Configuration Reference

`dosev` uses an INI‑style configuration file. This document describes every available option.

---

## Global Sections

### `[server]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `listen_ip` | string | `0.0.0.0` | IP address to bind to. |
| `listen_port` | int | `53` | Port for UDP and TCP (plain DNS). |
| `listen_tls_port` | int | `853` | Port for DNS‑over‑TLS (DoT). |
| `listen_https_port` | int | `443` | Port for DNS‑over‑HTTPS (DoH). |
| `https_cert_file` | string | `""` | Path to TLS certificate file (required for DoT/DoH). |
| `https_key_file` | string | `""` | Path to TLS private key file (required for DoT/DoH). |
| `https_ca_file` | string | `""` | Path to CA bundle for client certificate verification (optional). |

---

### `[resolver]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `upstream_dns` | string | `1.1.1.1` | Upstream DNS server (host or IP; optional port). |
| `protocol` | string | `udp` | Protocol to use: `udp`, `tcp`, `tls`, `https`, `quic`. |
| `verbose` | bool | `false` | Enable debug logging. |
| `disable_ipv6` | bool | `false` | Do not query AAAA records. |
| `strip_ipv6_records` | bool | `false` | Strip AAAA records from responses. |

---

### `[cache]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ttl` | int | `300` | TTL (seconds) for positive cache entries. |
| `max_size` | int | `1024` | Maximum number of cache entries. |
| `negative_ttl` | int | `60` | TTL for negative (NXDOMAIN) cache entries. |

---

### `[timeouts]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `udp` | float | `2.0` | UDP query timeout (seconds). |
| `tcp` | float | `5.0` | TCP/TLS query timeout. |
| `doh` | float | `5.0` | DoH/DoQ query timeout. |

---

### `[advanced]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `retries` | int | `2` | Number of retries per upstream. |
| `rate_limit_rps` | float | `0.0` | Request per second per client IP (0 = disabled). |
| `rate_limit_burst` | float | `0.0` | Max burst (must be ≥ `rate_limit_rps`). |
| `optimistic_cache_enabled` | bool | `false` | Serve stale responses while refreshing. |
| `optimistic_stale_max_age` | int | `86400` | Maximum age (seconds) for stale responses. |
| `optimistic_stale_response_ttl` | int | `30` | TTL to set on stale responses. |
| `pool_max_size` | int | `5` | Max connections per upstream pool. |
| `pool_idle_timeout` | float | `60.0` | Idle timeout (seconds) for pooled connections. |
| `doh_version` | string | `auto` | DoH version: `1.1`, `2`, `3`, or `auto`. |
| `doh_auto_cache_ttl` | int | `3600` | Cache TTL for auto‑detected DoH versions. |
| `load_balancing` | string | `failover` | Strategy: `failover`, `roundrobin`, `weighted`. |
| `health_check_interval` | int | `60` | Interval (seconds) between upstream health checks. |
| `health_check_timeout` | float | `2.0` | Timeout for a health check query. |

---

### `[security]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dnssec_enabled` | bool | `false` | Enable DNSSEC validation. |
| `auto_update_trust_anchor` | bool | `true` | Automatically fetch root trust anchor from IANA. |
| `trust_anchors_file` | string | `""` | Custom trust anchor file (overrides built‑in). |
| `pinned_certs` | string | `""` | Comma‑separated `hostname=sha256` pins for TLS connections. |
| `rebind_protection` | bool | `false` | Enable rebinding protection. |
| `rebind_action` | string | `strip` | `strip` or `block` when private IPs are detected. |
| `dns_privilege_drop_user` | string | `""` | User to drop privileges to (Linux/Unix). |
| `dns_privilege_drop_group` | string | `""` | Group to drop privileges to. |
| `dns_chroot_dir` | string | `""` | chroot directory (Linux/Unix). |

---

### `[logging]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable request logging to file. |
| `log_dir` | string | `/var/log/dosev` or `%LOCALAPPDATA%/dosev/logs` | Directory for log files. |
| `retention_days` | int | `7` | Number of days to keep log files. |
| `log_prefix` | string | `dns-log` | Prefix for log filenames. |
| `format` | string | `text` | Log format: `text` or `json`. |

---

### `[metrics]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Prometheus metrics endpoint. |
| `port` | int | `8000` | Port for metrics server. |
| `uvloop_enable` | bool | `false` | Use uvloop (faster event loop on Unix). |

---

### `[bootstrap]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `servers` | string | `1.1.1.1:53,8.8.8.8:53` | Comma‑separated list of bootstrap DNS servers (used to resolve upstream hostnames). |
| `timeout` | float | `2.0` | Timeout for bootstrap lookups. |
| `retries` | int | `2` | Number of retries for bootstrap. |

---

### `[upstreams]`

Define multiple upstream servers with custom settings.

```ini
[upstreams]
servers = primary,secondary

[upstreams.primary]
address = 1.1.1.1
protocol = udp
port = 53
hostname = one.one.one.one

[upstreams.secondary]
address = 8.8.8.8
protocol = tls
port = 853
hostname = dns.google
```

Each upstream section supports:
- `address`: IP or hostname.
- `protocol`: `udp`, `tcp`, `tls`, `https`, `quic`.
- `port`: optional (defaults to standard port for the protocol).
- `hostname`: used for SNI (TLS/DoH).
- `path`: DoH path (default `/dns-query`).
- `doh_version`: `auto`, `1.1`, `2`, `3`.
- `weight`: for weighted load balancing (default `1`).

---

### `[blocklists]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable blocklist filtering. |
| `urls` | string | `""` | Comma‑separated list of URLs to fetch. |
| `interval_seconds` | int | `86400` | Refresh interval for remote lists. |
| `action` | string | `NXDOMAIN` | Action for blocked domains: `NXDOMAIN`, `REFUSED`, `ZEROIP`. |
| `local_blocklist_dir` | string | `blocklists` | Directory to store downloaded lists. |
| `reload_on_change` | bool | `true` | Automatically reload if files change. |

---

### `[hosts]`

Define static A/AAAA records.

```ini
[hosts]
# Format: domain = ip
myinternal.local = 192.168.1.10
```

---

## Example Full Configuration

See `examples/dosev.conf.example` in the source repository for a complete example covering all sections.