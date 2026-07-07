import os
import tempfile
import configparser
from dosev.config import load_config


def test_load_config_defaults_nonexistent_file(tmp_path):
    config = load_config(str(tmp_path / "missing.conf"))
    assert config["listen_ip"] == "0.0.0.0"
    assert config["dns_cache_ttl"] == 300
    assert config["blocklists"]["enabled"] is False
    # upstream_dns and protocol removed


def test_load_config_from_file(tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg = configparser.ConfigParser()
    cfg["server"] = {"listen_ip": "127.0.0.1", "listen_port": "5353"}
    cfg["cache"] = {"ttl": "100", "max_size": "256"}
    cfg["blocklists"] = {"enabled": "true", "urls": "https://example.com/bl.txt", "interval_seconds": "3600"}
    with open(cfg_path, "w", encoding="utf-8") as f:
        cfg.write(f)

    config = load_config(str(cfg_path))
    assert config["listen_ip"] == "127.0.0.1"
    assert config["listen_port"] == 5353
    assert config["dns_cache_ttl"] == 100
    assert config["dns_cache_max_size"] == 256
    assert config["blocklists"]["enabled"] is True
    assert config["blocklists"]["interval_seconds"] == 3600