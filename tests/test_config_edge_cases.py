"""
Tests for config loading edge cases.
"""

import os
import tempfile
import configparser
import pytest
from dosev.config import load_config, write_default_config, _validate_and_warn


def test_load_config_missing_file():
    """load_config should return defaults when file doesn't exist."""
    config = load_config("/nonexistent/path/file.conf")
    assert config["listen_ip"] == "0.0.0.0"
    assert config["listen_port"] == 53
    assert config["dnssec_max_validations"] == 32


def test_load_config_with_custom_values():
    """load_config should read custom values from file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
        f.write("""
[server]
listen_ip = 127.0.0.1
listen_port = 5353

[security]
dnssec_max_validations = 64
dnssec_max_dnskey_records = 16
dnssec_validation_timeout = 5.0
dns_scrub_unsolicited_ns = false
""")
        path = f.name

    try:
        config = load_config(path)
        assert config["listen_ip"] == "127.0.0.1"
        assert config["listen_port"] == 5353
        assert config["dnssec_max_validations"] == 64
        assert config["dnssec_max_dnskey_records"] == 16
        assert config["dnssec_validation_timeout"] == 5.0
        assert config["dns_scrub_unsolicited_ns"] is False
    finally:
        os.unlink(path)


def test_write_default_config_creates_directory():
    """write_default_config should create directory if it doesn't exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "subdir", "dosev.conf")
        write_default_config(path)
        assert os.path.exists(path)
        with open(path, 'r') as f:
            content = f.read()
            assert "[server]" in content
            assert "[security]" in content
            assert "dnssec_max_validations" in content


def test_validate_invalid_port():
    """Validation should reject invalid port numbers."""
    with pytest.raises(ValueError, match="listen_port must be between 1 and 65535"):
        _validate_and_warn({"listen_port": 0})

    with pytest.raises(ValueError, match="listen_port must be between 1 and 65535"):
        _validate_and_warn({"listen_port": 65536})


def test_validate_invalid_dnssec_options():
    """Validation should reject invalid DNSSEC options."""
    with pytest.raises(ValueError, match="dnssec_max_validations must be non-negative"):
        _validate_and_warn({"dnssec_max_validations": -1})

    with pytest.raises(ValueError, match="dnssec_max_dnskey_records must be non-negative"):
        _validate_and_warn({"dnssec_max_dnskey_records": -1})


def test_validate_invalid_validation_timeout():
    """Validation should reject non-positive timeout."""
    with pytest.raises(ValueError, match="dnssec_validation_timeout must be positive"):
        _validate_and_warn({"dnssec_validation_timeout": 0})

    with pytest.raises(ValueError, match="dnssec_validation_timeout must be positive"):
        _validate_and_warn({"dnssec_validation_timeout": -1.0})