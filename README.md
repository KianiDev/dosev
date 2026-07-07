# dosev – Multi‑Protocol DNS Resolver & Server

[![CI](https://github.com/KianiDev/dosev/actions/workflows/ci.yml/badge.svg)](https://github.com/KianiDev/dosev/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/dosev)](https://pypi.org/project/dosev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**dosev** is a high‑performance, asynchronous DNS resolver and forwarding server that speaks **all major DNS protocols** – both as a client and as a server.

- **Client protocols**: DNS over UDP, TCP, TLS (DoT), HTTPS (DoH – HTTP/1.1, HTTP/2, HTTP/3), and QUIC (DoQ).
- **Server protocols**: UDP, TCP, TLS (DoT), HTTPS (DoH – HTTP/2 and HTTP/3).
- **Features**: EDNS0 (including Client Subnet), DNSSEC validation with automatic trust anchor updates, negative caching, optimistic caching (serve‑stale), blocklists, hosts overrides, upstream health checks, load balancing, Prometheus metrics, and more.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install dosev

# Create a minimal config file
mkdir -p config
cat > config/dosev.conf <<EOF
[server]
listen_ip = 0.0.0.0
listen_port = 53

[resolver]
upstream_dns = 1.1.1.1
protocol = udp
EOF

# Start the server
dosev --config config/dosev.conf
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
| **Load balancing & health checks** | Distribute queries across multiple upstreams; automatically exclude unhealthy ones. |
| **Rate limiting** | Token‑bucket limiter per client IP. |
| **Rebinding protection** | Strip or block private IP addresses from responses. |
| **Metrics** | Prometheus‑compatible metrics (requests, errors, latency, cache stats). |
| **Privilege dropping** | Drop root privileges after binding to privileged ports. |
| **Cross‑platform** | Works on Linux, macOS, and Windows. |
| **Configuration** | Single INI file; can be reloaded without restarting. |

---

## 📖 Documentation

- [Quick Start](docs/quickstart.md) – get up and running in minutes.
- [Configuration Reference](docs/configuration.md) – all available options explained.
- [Deployment Guide](docs/deployment.md) – systemd, Docker, and production tuning.
- [Contributing](docs/CONTRIBUTING.md) – how to help improve dosev.

---

## 🔧 Configuration Example

```ini
[server]
listen_ip = 0.0.0.0
listen_port = 53

[resolver]
upstream_dns = 1.1.1.1
protocol = udp

[security]
dnssec_enabled = true
auto_update_trust_anchor = true

[blocklists]
enabled = true
urls = https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
action = NXDOMAIN
```

See the full [configuration reference](docs/configuration.md) for all options.

---

## 🧪 Running Tests

```bash
pip install dosev[test]
pytest --cov=dosev --cov-report=term-missing
```

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](docs/CONTRIBUTING.md) before opening issues or pull requests.

---

## 📄 License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [dnspython](https://www.dnspython.org/) – for DNS message handling.
- [aiohttp](https://docs.aiohttp.org/) – for HTTP/1.1 and HTTP/2 support.
- [aioquic](https://github.com/aiortc/aioquic) – for HTTP/3 and QUIC support.
- [Prometheus](https://prometheus.io/) – for metrics.
