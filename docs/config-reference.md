# dosev Configuration Reference

## [server]

- `listen_ip`: IP address to bind the server on.
- `listen_port`: Port for plain DNS UDP/TCP listeners.

## [resolver]

- `upstream_dns`: Upstream DNS resolver address.
- `protocol`: Upstream protocol (`udp`, `tcp`, `tls`, `https`).
- `verbose`: `true` or `false`.
- `disable_ipv6`: `true` to block AAAA queries and IPv6 responses.
- `dns_max_payload`: Maximum EDNS0 UDP payload size advertised and accepted.
- `dns_enable_dot`: `true` to enable DNS-over-TLS (DoT) server listener.
- `dns_dot_port`: Port for the DoT listener (default `853`).
- `dns_dot_cert_file`: TLS certificate file path for DoT.
- `dns_dot_key_file`: TLS key file path for DoT.
- `dns_enable_doh`: `true` to enable DNS-over-HTTPS (DoH) server listener.
- `dns_doh_port`: Port for the DoH listener (default `443`).
- `dns_doh_cert_file`: TLS certificate file path for DoH.
- `dns_doh_key_file`: TLS key file path for DoH.
- `dns_doh_path`: HTTP path for DoH requests (default `/dns-query`).

## [cache]

- `ttl`: Cache time-to-live in seconds.
- `max_size`: Maximum cache entries.

## [timeouts]

- `udp`: Upstream UDP timeout.
- `tcp`: Upstream TCP timeout.
- `doh`: Upstream DoH timeout.

## [advanced]

- `retries`: Upstream retry count.
- `rate_limit_rps`: Rate limit in requests per second.
- `rate_limit_burst`: Token-bucket burst size.
- `optimistic_cache_enabled`: `true` to enable optimistic caching.
- `optimistic_stale_max_age`: Maximum age for stale optimistic cache.
- `optimistic_stale_response_ttl`: TTL for stale optimistic responses.
- `pool_max_size`: Connection pool max size.
- `pool_idle_timeout`: Connection pool idle timeout.
- `doh_version`: Preferred DoH version (`auto`, `1.1`, `2`, `3`).
- `doh_auto_cache_ttl`: TTL for auto-detected DoH version results.

## [security]

- `dnssec_enabled`: `true` to enable DNSSEC validation.
- `auto_update_trust_anchor`: `true` to auto-update root trust anchors.
- `trust_anchors_file`: Custom trust anchor file path.
- `pinned_certs`: Certificate pinning map.
- `rebind_protection`: `true` to enable DNS rebinding protection.
- `rebind_action`: `strip` or `block`.
- `dns_privilege_drop_user`: User for privilege dropping.
- `dns_privilege_drop_group`: Group for privilege dropping.
- `dns_chroot_dir`: Chroot directory.

## [metrics]

- `enabled`: Start Prometheus metrics server.
- `port`: Metrics port.
- `uvloop_enable`: `true` to use uvloop if available.

## [bootstrap]

- `servers`: Comma-separated bootstrap DNS servers.
- `timeout`: Bootstrap timeout seconds.
- `retries`: Bootstrap retry count.

## [upstreams]

Defines upstream resolver endpoints by name. Example:

```ini
[upstreams]
servers = primary,secondary

[upstreams.primary]
address = 1.1.1.1
protocol = udp

[upstreams.secondary]
address = dns.google
protocol = https
path = /dns-query
```
