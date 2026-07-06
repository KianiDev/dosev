# dosev Architecture

## Overview

dosev is structured as a config-driven DNS resolver and server. It accepts client DNS queries, forwards them to configured upstream resolvers, and returns responses while applying policies such as caching, blocklists, DNSSEC, and secure transport handling.

## Components

### Server

The server layer is implemented in `dosev/server.py`.

- UDP listener: handles traditional DNS over UDP.
- TCP listener: handles traditional DNS over TCP.
- DoT listener: optional DNS-over-TLS listener using TLS-wrapped TCP.
- DoH listener: optional DNS-over-HTTPS listener using `aiohttp` to accept HTTP requests.
- Signal handling and graceful shutdown.
- Hot configuration reload support for resolver settings and blocklists.

### Resolver

The core resolver lives in `dosev/resolver.py`.

- Forwards queries to upstream DNS servers over UDP, TCP, TLS, or HTTPS.
- Supports DNS-over-HTTPS client behavior with HTTP/1.1, HTTP/2, and HTTP/3.
- Implements EDNS0 and ECS handling, including payload capping.
- Supports DNSSEC validation, auto-updating trust anchors, and pinned certificates.
- Includes caching, rate limiting, blocklist enforcement, and rebind protection.

### Config

Configuration is handled in `dosev/config.py`.

- Loads defaults when no config file exists.
- Reads server and resolver sections and normalizes values.
- Supports upstream definitions with protocol-specific defaults.
- Exposes secure listener options for DoT and DoH.

## Request flow

1. The server receives a query via UDP/TCP/DoT/DoH.
2. The server parses the raw DNS message and optionally applies local IPv6/blocklist checks.
3. If the query is allowed, it calls `resolver.forward_dns_query()`.
4. The resolver chooses an upstream transport based on config.
5. The upstream response is received, sanitized, and returned to the server.
6. The server sends the response back to the client.

## Deployment model

- Run as a service behind proper privilege separation.
- Use TLS certs when enabling DoT or DoH.
- Keep upstream servers explicit in `config/dosev.conf`.
- Enable metrics and logs for production monitoring.
