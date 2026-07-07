# Quick Start Guide

This guide will help you get `dosev` up and running in less than 5 minutes.

---

## Installation

### Using pip

```bash
pip install dosev
```

### From source

```bash
git clone https://github.com/KianiDev/dosev.git
cd dosev
pip install -e .
```

---

## First Run

Run `dosev` without any arguments – it will create a default configuration file in the OS‑specific user config directory and exit with instructions:

```bash
dosev
```

Output:
```
Default configuration file created at:
  /home/user/.config/dosev/dosev.conf
Please edit it to your needs and restart dosev.
```

Edit the file to suit your needs, then run `dosev` again.

---

## Minimal Configuration

If you prefer to write your own, here’s a minimal working config:

```ini
[server]
listen_ip = 0.0.0.0
listen_port = 53

[upstreams]
servers = default

[upstreams.default]
address = 1.1.1.1
protocol = udp
ip = 1.1.1.1
```

Save it as `dosev.conf` and start the server:

```bash
dosev --config /path/to/dosev.conf
```

---

## Testing Your Resolver

Use `dig` (or `nslookup`) to query the local resolver:

```bash
dig @127.0.0.1 example.com A
```

If everything works, you’ll receive a response with the IP address of `example.com`.

---

## Enabling DNSSEC

Add to your config:

```ini
[security]
dnssec_enabled = true
auto_update_trust_anchor = true
```

`dosev` will use the built-in root trust anchor and automatically keep it up-to-date from IANA.

---

## Enabling Blocklists

Add to your config:

```ini
[blocklists]
enabled = true
urls = https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
action = NXDOMAIN
```

Blocklists will be downloaded and refreshed automatically.

---

## Using DoH or DoT (Server Side)

For encrypted server endpoints, add:

```ini
[resolver]
dns_enable_dot = true
dns_dot_port = 853
dns_enable_doh = true
dns_doh_port = 443
dns_doh_cert_file = /path/to/cert.pem
dns_doh_key_file = /path/to/key.pem
dns_doh_path = /dns-query
```

Then clients can query via `tls://` or `https://`.

---

## Using DoH or DoT (Client Side)

To forward queries over an encrypted transport, define an upstream with the appropriate `protocol`:

```ini
[upstreams.secure]
address = cloudflare-dns.com
protocol = tls    # or https, quic
port = 853        # or 443 for https
```

---

## Configuration Validation

Check your config without starting the server:

```bash
dosev --check-config --config /path/to/dosev.conf
```

---

## Next Steps

- Read the [Configuration Reference](config-reference.md) to explore all options.
- Check the [Deployment Tips](deployment-tips.md) for production setups.
- Review the [Architecture](architecture.md) to understand how dosev works.

---

## Getting Help

If you encounter issues, please open an issue on GitHub with your configuration and logs.
