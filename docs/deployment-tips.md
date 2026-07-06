# Deployment Tips

This document provides practical guidance for deploying `dosev` in production environments.

---

## Systemd Service (Linux)

Create a systemd unit file at `/etc/systemd/system/dosev.service`:

```ini
[Unit]
Description=dosev DNS resolver
After=network.target

[Service]
Type=simple
User=dosev
Group=dosev
WorkingDirectory=/etc/dosev
ExecStart=/usr/local/bin/dosev --config /etc/dosev/dosev.conf
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dosev
sudo systemctl start dosev
```

---

## Docker

### Using the official image

```bash
docker run -d \
  --name dosev \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 853:853/tcp \
  -p 443:443/tcp \
  -v ./config:/etc/dosev \
  ghcr.io/kianidev/dosev:latest \
  --config /etc/dosev/dosev.conf
```

### Docker Compose

```yaml
version: '3'
services:
  dosev:
    image: ghcr.io/kianidev/dosev:latest
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "853:853/tcp"
      - "443:443/tcp"
    volumes:
      - ./config:/etc/dosev
      - ./blocklists:/var/lib/dosev/blocklists
    command: ["--config", "/etc/dosev/dosev.conf"]
```

---

## Performance Tuning

- **Increase file descriptor limits**: `ulimit -n 65536` or `LimitNOFILE=65536` in systemd.
- **Enable uvloop**: Set `uvloop_enable = true` in `[metrics]` (Unix only).
- **Adjust pool sizes**: Increase `pool_max_size` for high‑throughput environments.
- **Enable optimistic caching**: `optimistic_cache_enabled = true` reduces latency during upstream failures.
- **Load balancing**: Use `roundrobin` or `weighted` to distribute load.
- **Health checks**: Set `health_check_interval` to 30–60 seconds for timely failure detection.

---

## Monitoring

### Prometheus

If `metrics_enabled = true`, metrics are exposed at `http://<listen_ip>:<metrics_port>/metrics`.

Key metrics:
- `dosev_dns_requests_total{proto}` – requests per protocol.
- `dosev_dns_request_errors_total{proto}` – errors per protocol.
- `dosev_dns_request_latency_seconds{proto}` – latency histogram.
- `dosev_cache_hits_total` / `dosev_cache_misses_total` – cache efficiency.

### Logging

Enable structured JSON logging for easier ingestion:

```ini
[logging]
format = json
```

---

## Security Hardening

- **Run as non‑root**: Use `dns_privilege_drop_user` and `dns_privilege_drop_group`.
- **Use chroot**: Set `dns_chroot_dir` to a safe directory (e.g., `/var/empty`).
- **Bind to loopback only** if local use: `listen_ip = 127.0.0.1`.
- **Enable DNSSEC**: `dnssec_enabled = true`.
- **Enable rebinding protection**: `rebind_protection = true` and `rebind_action = strip`.
- **Rate limiting**: Set `rate_limit_rps` to a reasonable value (e.g., 10–100).
- **Firewall**: Restrict access to ports 53, 853, 443 only to trusted clients.

---

## Upgrading

```bash
pip install --upgrade dosev
```

Or if using source:

```bash
git pull
pip install -e .
```

Always test the new version with `--check-config` before restarting.

---

## Troubleshooting

- **Validate config**: `dosev --check-config --config /path/to/config`
- **Check logs**: Look at system logs and `dosev` logs.
- **Test upstream connectivity**: Ensure upstream DNS servers are reachable.
- **Firewall**: Verify required ports are open.
- **File permissions**: Ensure log and blocklist directories are writable by the `dosev` user.

---

For further assistance, please open an issue on GitHub.