# dosev Quickstart

## Overview

dosev is a lightweight multi-protocol DNS resolver and server. It supports plain UDP/TCP, DNS-over-TLS (DoT), and DNS-over-HTTPS (DoH).

## Prerequisites

- Python 3.10+
- Recommended: use a virtual environment
- Optional dependencies for full feature support:
  - `aiohttp` for DoH server support
  - `httpx[h2]` for HTTP/2 DoH client support
  - `aioquic` for HTTP/3 DoH client support

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

## Create a config file

Copy the example config:

```bash
copy config\dosev.conf.example config\dosev.conf
```

Modify any values you need in `config/dosev.conf`.

## Run the server

```bash
.venv\Scripts\python.exe -m dosev.cli --config config/dosev.conf
```

By default, the server listens on plain UDP/TCP on port `53`.

## Enable secure server endpoints

To enable DoT or DoH, update the `[resolver]` section in `config/dosev.conf`:

```ini
[resolver]
dns_enable_dot = true
dns_dot_cert_file = /path/to/cert.pem
dns_dot_key_file = /path/to/key.pem

# Optional DoH listener
dns_enable_doh = true
dns_doh_cert_file = /path/to/cert.pem
dns_doh_key_file = /path/to/key.pem
dns_doh_path = /dns-query
```

Then restart the server.

## Verify it works

- DNS over UDP: query port `53`
- DNS over TLS: connect to `853`
- DNS over HTTPS: send DoH requests to port `443` and `dns_doh_path`

For server-side validation, use your system logs or the configured DNS log location.
