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

## Minimal Configuration

Create a configuration file:

```bash
mkdir -p config
cat > config/dosev.conf <<EOF
[server]
listen_ip = 0.0.0.0
listen_port = 53

[resolver]
upstream_dns = 1.1.1.1
protocol = udp
EOF
```

---

## Starting the Server

```bash
dosev --config config/dosev.conf
```

You should see log output indicating that UDP and TCP listeners are running.

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
[server]
listen_tls_port = 853
listen_https_port = 443
https_cert_file = /path/to/cert.pem
https_key_file = /path/to/key.pem
```

Then clients can query via `tls://` or `https://`.

---

## Using DoH or DoT (Client Side)

To forward queries over an encrypted transport:

```ini
[resolver]
upstream_dns = 1.1.1.1
protocol = tls     # or https, quic
```

---

## Configuration Validation

Check your config without starting the server:

```bash
dosev --check-config --config config/dosev.conf
```

---

## Next Steps

- Read the [Configuration Reference](configuration.md) to explore all options.
- Check the [Deployment Tips](deployment-tips.md) for production setups.
- Review the [Architecture](architecture.md) to understand how dosev works.

---

## Getting Help

If you encounter issues, please open an issue on GitHub with your configuration and logs.
