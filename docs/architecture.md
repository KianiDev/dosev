# Architecture

This document describes the internal architecture of `dosev` – its components, data flow, and key design decisions.

---

## Overview

`dosev` is an asynchronous DNS resolver and server built on Python's `asyncio`. It is split into several logical layers:

1. **Configuration** – loading and validating settings from an INI file.
2. **Server** – listening for incoming DNS queries over multiple protocols (UDP, TCP, TLS, HTTPS).
3. **Resolver** – the core logic that processes queries, applies blocklists, handles caching, performs DNSSEC validation, and forwards to upstreams.
4. **Transports** – protocol‑specific client implementations for upstream communication (UDP, TCP, TLS, HTTPS, QUIC).
5. **Utilities** – helpers for blocklist fetching, logging, and metrics.

All components are designed to be modular and testable.

---

## High‑Level Data Flow

```text
Client
   │
   ▼
Server (UDP / TCP / TLS / HTTPS)
   │
   ▼
Resolver.forward_dns_query()
   │
   ├── Hosts override?
   ├── Blocklist match?
   ├── Cache hit?
   │       └── (positive / negative / stale)
   ├── EDNS0 processing
   ├── Upstream selection (configurable: failover, parallel, random, roundrobin)
   ├── Forward via transport (UDP/TCP/TLS/DoH/DoQ)
   ├── DNSSEC validation
   ├── Cache response
   └── Return to client
```

---

## Core Components

### 1. `DNSResolver` (dosev/resolver.py)

The heart of the system. It manages:

- **Caches**: positive cache (TTL‑based), negative cache (NXDOMAIN/NODATA), and stale‑serve logic.
- **Blocklists & Hosts**: exact‑match and suffix‑based domain filtering; static A/AAAA overrides.
- **Upstream management**: supports `failover`, `parallel`, `random`, and `roundrobin` strategies; configured via `load_balancing` in the config.
- **DNSSEC**: validates responses using a trust anchor (bundled or IANA‑fetched); caches validation results.
- **EDNS0**: parses client subnet and forwards it to upstreams.
- **Rate limiting**: token‑bucket per client IP.
- **Rebinding protection**: strips or blocks private IPs.
- **Metrics**: collects request counts, errors, and latency.

**Key Methods**:

- `forward_dns_query(data: bytes) -> bytes` – the main entry point for processing a raw DNS query.
- `_try_upstream(upstream, data) -> bytes` – sends a query to a single upstream, with retries.
- `_wire_cache_get_valid(key) -> Optional[bytes]` – fetches a cached response, with stale‑serve logic.
- `_dnssec_validate(qname, response) -> None` – validates DNSSEC signatures.

### 2. Server Layer (dosev/server.py)

Provides listeners for:

- **UDP**: `asyncio.DatagramProtocol`.
- **TCP**: `asyncio.StreamReader` / `StreamWriter`.
- **TLS (DoT)**: TCP with SSL context on port 853.
- **HTTPS (DoH)**: HTTP/2 and HTTP/3 servers using `aiohttp` and `aioquic`.

Each listener accepts a query, passes it to the resolver, and sends back the response.

**Graceful Shutdown**: Signal handlers (SIGINT, SIGTERM) trigger a clean shutdown, closing all listeners and connection pools.

### 3. Transports (client‑side)

Each transport implements the protocol‑specific forwarding logic:

- `_forward_udp()`
- `_forward_tcp()`
- `_forward_tls()`
- `_forward_https1()`, `_forward_https2()`, `_forward_https3()`
- `_forward_quic()` – now uses a connection pool (`_quic_pool`) to reuse QUIC connections across multiple queries, reducing handshake overhead.

These handle connection pooling, timeouts, retries, certificate pinning, and the `ip` field to skip DNS resolution.

### 4. Caching

Two‑layer cache:

- **DNS cache** (`_dns_cache`): stores parsed responses (used for upstream IP resolution).
- **Wire cache** (`_wire_cache`): stores raw wire‑format responses for fast replay.

Both support TTL expiration and size limits. The wire cache includes a `dnssec_validated` flag.

### 5. Configuration (dosev/config.py)

Loads an INI file and returns a flat dictionary with sensible defaults. Supports all sections documented in the configuration reference.  
On first run, a default configuration file is created in the OS‑specific user config directory (`~/.config/dosev/`, `~/Library/Application Support/dosev/`, or `%APPDATA%\dosev\`).

### 6. Utilities (dosev/utils.py)

- `fetch_blocklists()` – downloads remote blocklists using streaming HTTP.
- Logging helpers.
- Metrics (Prometheus) integration.

---

## Concurrency Model

`dosev` uses `asyncio` for non‑blocking I/O. Each client connection is handled in its own coroutine; the resolver is stateless, so multiple queries can be processed concurrently.

**Thread safety**: The resolver uses `asyncio.Lock` for mutable state (caches, blocklists, configuration). Connection pools also use locks.

**Background tasks**:

- Connection pool cleanup.
- Blocklist refresh.
- DNSSEC trust anchor update.

---

## Security Considerations

- **Privilege dropping**: After binding to privileged ports, the process drops to a non‑root user/group (Linux/Unix).
- **Certificate pinning**: SHA‑256 pinning for TLS connections.
- **Rebinding protection**: Prevents DNS rebinding attacks by filtering private IPs.
- **Rate limiting**: Protects against DDoS.
- **DNSSEC**: Validates response authenticity.
- **chroot**: Optional jail for additional isolation.

---

## Performance Optimizations

- **Asynchronous I/O**: All network operations are non‑blocking.
- **Connection pooling**: Reuses TCP/TLS/HTTP/DoQ connections to reduce handshake overhead.
- **Caching**: Reduces upstream load and latency.
- **Optimistic caching**: Serves stale responses while refreshing in the background.
- **uvloop**: Optional faster event loop (Unix).

---

## Extensibility

The modular design makes it easy to add:

- New transport protocols (e.g., DNSCrypt, ODoH).
- Additional caching strategies.
- Custom load‑balancing policies.
- New metrics or logging backends.

---

## Dependencies

| Library | Purpose |
|---------|---------|
| `dnspython` | DNS message parsing and construction. |
| `aiohttp` | HTTP/1.1 and HTTP/2 client & server. |
| `aioquic` | HTTP/3 and QUIC client & server. |
| `httpx` | HTTP/2 client (optional fallback). |
| `cachetools` | TTL cache (fallback to internal `AsyncTTLCache`). |
| `prometheus-client` | Metrics exposition. |
| `cryptography` | Certificate handling. |

---

## Testing

- **Unit tests**: cover all core logic with mocked network calls.
- **Integration tests**: test against real upstreams (using `dig` or stub servers).
- **CI**: runs on Linux, macOS, and Windows for Python 3.10–3.14.

---

## Future Directions

- Full RFC 5011 trust anchor management.
- DNSCrypt and ODoH client/server support.
- More advanced EDNS0 options.
- Enhanced load balancing (round‑robin, weighted).
- Health checks for upstreams.
- Web‑based status dashboard.
