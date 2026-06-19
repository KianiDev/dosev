import configparser

from dosev.config import load_config


def test_load_config_parses_all_extra_sections(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["server"] = {"listen_ip": "127.0.0.2", "listen_port": "5354"}
    cfg["resolver"] = {
        "upstream_dns": "9.9.9.9",
        "protocol": "TLS",
        "verbose": "true",
        "disable_ipv6": "true",
    }
    cfg["cache"] = {"ttl": "123", "max_size": "456"}
    cfg["timeouts"] = {"udp": "1.5", "tcp": "4.5", "doh": "9.5"}
    cfg["advanced"] = {
        "retries": "5",
        "rate_limit_rps": "6.5",
        "rate_limit_burst": "7.5",
        "optimistic_cache_enabled": "true",
        "optimistic_stale_max_age": "100",
        "optimistic_stale_response_ttl": "11",
        "pool_max_size": "12",
        "pool_idle_timeout": "13.5",
        "doh_version": "3",
        "doh_auto_cache_ttl": "14",
    }
    cfg["security"] = {
        "dnssec_enabled": "true",
        "trust_anchors_file": "/tmp/anchors.txt",
        "pinned_certs": "a.example.com=abc,*.example.com=def",
        "rebind_protection": "true",
        "rebind_action": "BLOCK",
        "dns_privilege_drop_user": "dns",
        "dns_privilege_drop_group": "nogroup",
        "dns_chroot_dir": "/var/empty",
    }
    cfg["logging"] = {
        "enabled": "true",
        "retention_days": "8",
        "log_dir": "/tmp/dnslog",
        "log_prefix": "custom-log",
    }
    cfg["metrics"] = {
        "enabled": "true",
        "port": "9100",
        "uvloop_enable": "true",
    }
    cfg["bootstrap"] = {"servers": "1.1.1.1:53,8.8.4.4:53", "timeout": "3.5", "retries": "6"}
    cfg["upstreams"] = {"servers": "primary,secondary"}
    cfg["upstreams.primary"] = {
        "address": "dns1.example.com",
        "protocol": "TLS",
        "port": "853",
        "hostname": "dns1.example.com",
        "doh_version": "2",
        "path": "/dns-query",
    }
    cfg["upstreams.secondary"] = {
        "address": "dns2.example.com",
        "protocol": "https",
    }
    cfg["blocklists"] = {
        "enabled": "true",
        "urls": "https://a/list.txt,https://b/list.txt",
        "interval_seconds": "1234",
        "action": "REFUSED",
        "local_blocklist_dir": "/tmp/bl",
        "reload_on_change": "false",
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    config = load_config(str(cfg_path))

    assert config["listen_ip"] == "127.0.0.2"
    assert config["protocol"] == "tls"
    assert config["dns_cache_ttl"] == 123
    assert config["dns_pinned_certs"] == {"a.example.com": "abc", "*.example.com": "def"}
    assert config["dnssec_enabled"] is True
    assert config["upstreams"][0]["doh_version"] == "2"
    assert config["bootstrap"]["servers"] == ["1.1.1.1:53", "8.8.4.4:53"]
    assert config["blocklists"]["reload_on_change"] is False
    assert config["doh_version"] == "3"
    assert config["optimistic_cache_enabled"] is True
    assert config["dns_privilege_drop_user"] == "dns"
    assert config["dns_log_prefix"] == "custom-log"
