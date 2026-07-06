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
        "dns_max_payload": "2048",
        "dns_enable_dot": "true",
        "dns_dot_port": "853",
        "dns_dot_cert_file": "/tmp/dot-cert.pem",
        "dns_dot_key_file": "/tmp/dot-key.pem",
        "dns_enable_doh": "true",
        "dns_doh_port": "443",
        "dns_doh_cert_file": "/tmp/doh-cert.pem",
        "dns_doh_key_file": "/tmp/doh-key.pem",
        "dns_doh_path": "/dns-query",
    }
    cfg["cache"] = {"ttl": "123", "max_size": "456", "negative_ttl": "7"}
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
    assert config["dns_negative_cache_ttl"] == 7
    assert config["dns_pinned_certs"] == {"a.example.com": "abc", "*.example.com": "def"}
    assert config["dns_ecs_enabled"] is True
    assert config["dns_max_payload"] == 2048
    assert config["dns_enable_dot"] is True
    assert config["dns_dot_port"] == 853
    assert config["dns_dot_cert_file"] == "/tmp/dot-cert.pem"
    assert config["dns_dot_key_file"] == "/tmp/dot-key.pem"
    assert config["dns_enable_doh"] is True
    assert config["dns_doh_port"] == 443
    assert config["dns_doh_cert_file"] == "/tmp/doh-cert.pem"
    assert config["dns_doh_key_file"] == "/tmp/doh-key.pem"
    assert config["dns_doh_path"] == "/dns-query"
    assert config["dnssec_enabled"] is True
    assert config["upstreams"][0]["doh_version"] == "2"


def test_load_config_parses_dns_ecs_enabled_false(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["resolver"] = {"dns_ecs_enabled": "false"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    config = load_config(str(cfg_path))
    assert config["dns_ecs_enabled"] is False
    assert config["dns_max_payload"] == 4096
    assert config["bootstrap"]["servers"] == ["1.1.1.1:53", "8.8.8.8:53"]
def test_load_config_upstreams_with_default_ports(tmp_path):
    """Test that upstreams get default ports based on protocol."""
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["upstreams"] = {"servers": "primary,secondary"}
    cfg["upstreams.primary"] = {"address": "dns1.example.com", "protocol": "tls"}
    cfg["upstreams.secondary"] = {"address": "dns2.example.com", "protocol": "https"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)
    
    config = load_config(str(cfg_path))
    assert config["upstreams"][0]["port"] == 853  # TLS default
    assert config["upstreams"][1]["port"] == 443  # HTTPS default

def test_load_config_upstreams_with_custom_port(tmp_path):
    """Test that upstreams respect custom port configuration."""
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["upstreams"] = {"servers": "primary"}
    cfg["upstreams.primary"] = {"address": "dns1.example.com", "protocol": "udp", "port": "5353"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)
    
    config = load_config(str(cfg_path))
    assert config["upstreams"][0]["port"] == 5353


def test_load_config_rejects_invalid_port(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["server"] = {"listen_port": "70000"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    try:
        load_config(str(cfg_path))
    except ValueError as exc:
        assert "listen_port" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid listen_port")


def test_load_config_warns_for_secure_listener_without_cert(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["resolver"] = {"dns_enable_dot": "true", "dns_dot_cert_file": "/tmp/cert.pem"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    try:
        load_config(str(cfg_path))
    except ValueError as exc:
        assert "dns_enable_dot" in str(exc)
    else:
        raise AssertionError("Expected ValueError for incomplete TLS config")


def test_load_config_warns_for_metrics_conflict(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["metrics"] = {"enabled": "true", "port": "53"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_config(str(cfg_path))

    assert any("Metrics are enabled on port 53" in str(w.message) for w in caught)