import sys
import argparse
from .config import load_config
from .server import run_server_sync

def main() -> None:
    parser = argparse.ArgumentParser(description="dosev DNS server")
    parser.add_argument("--config", "-c", default="config/dosev.conf",
                        help="Path to configuration file (default: config/dosev.conf)")
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Failed to load config: {e}", file=sys.stderr)
        sys.exit(1)

    run_server_sync(
        listen_ip=config["listen_ip"],
        listen_port=config["listen_port"],
        upstream_dns=config["upstream_dns"],
        protocol=config["protocol"],
        verbose=config.get("verbose", False),
        blocklists=config.get("blocklists"),
        disable_ipv6=config.get("disable_ipv6", False),
        dns_cache_ttl=config.get("dns_cache_ttl", 300),
        dns_cache_max_size=config.get("dns_cache_max_size", 1024),
        dns_logging_enabled=config.get("dns_logging_enabled", False),
        dns_log_retention_days=config.get("dns_log_retention_days", 7),
        dns_log_dir=config.get("dns_log_dir", "/var/log/dosev"),
        dns_log_prefix=config.get("dns_log_prefix", "dns-log"),
        dns_pinned_certs=config.get("dns_pinned_certs", {}),
        dnssec_enabled=config.get("dnssec_enabled", False),
        trust_anchors_file=config.get("trust_anchors_file", ""),
        metrics_enabled=config.get("metrics_enabled", False),
        metrics_port=config.get("metrics_port", 8000),
        uvloop_enable=config.get("uvloop_enable", False),
        upstream_retries=config.get("upstream_retries", 2),
        upstream_udp_timeout=config.get("upstream_udp_timeout", 2.0),
        upstream_tcp_timeout=config.get("upstream_tcp_timeout", 5.0),
        upstream_doh_timeout=config.get("upstream_doh_timeout", 5.0),
        rate_limit_rps=config.get("rate_limit_rps", 0.0),
        rate_limit_burst=config.get("rate_limit_burst", 0.0),
        upstreams=config.get("upstreams", []),
        optimistic_cache_enabled=config.get("optimistic_cache_enabled", False),
        optimistic_stale_max_age=config.get("optimistic_stale_max_age", 86400),
        optimistic_stale_response_ttl=config.get("optimistic_stale_response_ttl", 30),
        dns_privilege_drop_user=config.get("dns_privilege_drop_user", ""),
        dns_privilege_drop_group=config.get("dns_privilege_drop_group", ""),
        dns_chroot_dir=config.get("dns_chroot_dir", ""),
        dns_rebind_protection=config.get("dns_rebind_protection", False),
        dns_rebind_action=config.get("dns_rebind_action", "strip"),
        pool_max_size=config.get("pool_max_size", 5),
        pool_idle_timeout=config.get("pool_idle_timeout", 60.0),
        doh_version=config.get("doh_version", "auto"),
        doh_auto_cache_ttl=config.get("doh_auto_cache_ttl", 3600),
        bootstrap=config.get("bootstrap", {"servers": [], "timeout": 2.0, "retries": 2}),
    )

if __name__ == "__main__":
    main()