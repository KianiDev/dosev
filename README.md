# dosev – Multi‑Protocol DNS Resolver & Server

[![CI](https://github.com/KianiDev/dosev/actions/workflows/ci.yml/badge.svg)](https://github.com/KianiDev/dosev/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/dosev)](https://pypi.org/project/dosev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**dosev** is a high‑performance, asynchronous DNS resolver and forwarding server that speaks **all major DNS protocols** – both as a client and as a server.

- **Client protocols**: DNS over UDP, TCP, TLS (DoT), HTTPS (DoH – HTTP/1.1, HTTP/2, HTTP/3), and QUIC (DoQ).
- **Server protocols**: UDP, TCP, TLS (DoT), HTTPS (DoH – HTTP/2 and HTTP/3).
- **Features**: EDNS0 (including Client Subnet), DNSSEC validation with automatic trust anchor updates, negative caching, optimistic caching (serve‑stale), blocklists, hosts overrides, upstream failover, rate limiting, rebinding protection, Prometheus metrics, and more.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install dosev

# On first run, a default configuration file is created in the OS‑specific user config directory:
#   Linux:   ~/.config/dosev/dosev.conf
#   macOS:   ~/Library/Application Support/dosev/dosev.conf
#   Windows: %APPDATA%\dosev\dosev.conf
# Edit it to your needs, then start the server:
dosev
```

For detailed instructions, see the [Quick Start Guide](docs/quickstart.md).

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Multi‑protocol client** | Forward queries via UDP, TCP, TLS, HTTPS (HTTP/1.1, HTTP/2, HTTP/3), and QUIC. |
| **Multi‑protocol server** | Listen on UDP, TCP, TLS, and HTTPS (HTTP/2 & HTTP/3). |
| **DNSSEC validation** | Validate responses with a built‑in root trust anchor (auto‑updated from IANA). |
| **Caching** | Positive and negative caching with configurable TTLs; optimistic caching (serve‑stale). |
| **Blocklists** | Filter domains using local files or remote lists (automatically refreshed). |
| **Hosts overrides** | Custom A/AAAA records for local name resolution. |
| **EDNS0 & Client Subnet** | Pass client subnet to upstreams for geo‑optimised responses. |
| **Upstream failover** | Try upstreams in order; fall back to the next on failure. |
| **Rate limiting** | Token‑bucket limiter per client IP. |
| **Rebinding protection** | Strip or block private IP addresses from responses. |
| **Metrics** | Prometheus‑compatible metrics (requests, errors, latency). |
| **Privilege dropping** | Drop root privileges after binding to privileged ports. |
| **Cross‑platform** | Works on Linux, macOS, and Windows. |
| **Configuration** | Single INI file; auto‑generated with comments on first run. |

---

## 📖 Documentation

- [Quick Start](docs/quickstart.md) – get up and running in minutes.
- [Configuration Reference](docs/config-reference.md) – all available options explained.
- [Deployment Tips](docs/deployment-tips.md) – systemd and production tuning.
- [Architecture](docs/architecture.md) – internal design and data flow.

---

## 🔧 Configuration Example

```ini
#
# dosev configuration file
# Paths can be absolute or relative to the directory where dosev is started.
#

[server]
listen_ip = 0.0.0.0
listen_port = 53

[resolver]
verbose = false
disable_ipv6 = false
dns_ecs_enabled = true
dns_max_payload = 4096

[upstreams]
# List your upstreams here. Each upstream is defined in its own section.
servers = cloudflare,google

[upstreams.cloudflare]
address = 1.1.1.1
protocol = udp
ip = 1.1.1.1          # optional fixed IP to skip resolution

[upstreams.google]
address = dns.google
protocol = https
port = 443
hostname = dns.google
doh_version = auto
# no 'ip' – will be resolved via bootstrap DNS

[bootstrap]
servers = 1.1.1.1:53,8.8.8.8:53

[security]
dnssec_enabled = true
auto_update_trust_anchor = true

[blocklists]
enabled = true
urls = https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
action = NXDOMAIN
```

See the full [configuration reference](docs/config-reference.md) for all options.

---

## 🧪 Running Tests

```bash
pip install dosev[test]
pytest --cov=dosev --cov-report=term-missing
```

---

## 📄 License

MIT © 2026 Mohammad Amin Kiani

---

## 🙏 Acknowledgements

- [dnspython](https://www.dnspython.org/) – DNS message handling.
- [aiohttp](https://docs.aiohttp.org/) – HTTP/1.1 and HTTP/2 support.
- [aioquic](https://github.com/aiortc/aioquic) – HTTP/3 and QUIC support.
- [Prometheus](https://prometheus.io/) – metrics.
