# dosev Deployment Tips

## Run as a dedicated service

For production, run dosev under a dedicated user account and drop privileges when possible.

## Ports and privileges

- Plain DNS on port `53` typically requires root/administrator privileges.
- DoT on port `853` and DoH on port `443` may also require elevated privileges.
- Use `dns_privilege_drop_user`, `dns_privilege_drop_group`, and `dns_chroot_dir` in the config if running on Linux/Unix.

## TLS certificates

- Use valid TLS certificates for DoT and DoH.
- `dns_dot_cert_file` and `dns_dot_key_file` are required when `dns_enable_dot` is enabled.
- `dns_doh_cert_file` and `dns_doh_key_file` are required when `dns_enable_doh` is enabled.

## Monitoring

- Enable `metrics` and point Prometheus at `metrics_port`.
- Optionally enable DNS request logging with `logging.enabled`.

## Best practices

- Keep upstream servers explicit and use trusted providers.
- Configure `dns_max_payload` when you need a larger EDNS0 UDP window.
- Use `disable_ipv6` if you need to block AAAA traffic.
- Test DoH and DoT listeners after startup with real client tools.
