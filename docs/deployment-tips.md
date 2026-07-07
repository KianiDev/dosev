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

## Running as Non‑Root User

If you don't want to use systemd, you can run dosev manually as a non‑root user after binding to privileged ports:

```bash
# Bind to port 53 (requires root)
sudo dosev --config /etc/dosev/dosev.conf --user dosev --group dosev
```

Or use the built‑in privilege dropping (Linux/Unix):

```ini
[security]
dns_privilege_drop_user = dosev
dns_privilege_drop_group = dosev
```

---

## Performance Tuning

- **Increase file descriptor limits**: `ulimit -n 65536` or `LimitNOFILE=65536` in systemd.
- **Enable uvloop**: Set `uvloop_enable = true` in `[metrics]` (Unix only).
- **Adjust pool sizes**: Increase `pool_max_size` for high‑throughput environments.
- **Enable optimistic caching**: `optimistic_cache_enabled = true` reduces latency during upstream failures.
- **Use fixed IPs**: Specify `ip` for upstreams to avoid DNS resolution overhead.

---

## Monitoring

### Prometheus

If `metrics_enabled = true`, metrics are exposed at `http://<listen_ip>:<metrics_port>/metrics`.

Key metrics:
- `dosev_dns_requests_total{proto}` – requests per protocol.
- `dosev_dns_request_errors_total{proto}` – errors per protocol.
- `dosev_dns_request_latency_seconds{proto}` – latency histogram.

### Logging

Enable request logging to file:

```ini
[logging]
enabled = true
log_dir = /var/log/dosev
retention_days = 7
```

**Note:** Only plain text logging is supported.

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

For further assistance, please open an issue on GitHub.
