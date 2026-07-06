import os
import configparser
import warnings
from typing import Dict, Any, List, Optional


def _default_log_dir() -> str:
    if os.name == 'nt':
        return os.path.join(os.getenv('LOCALAPPDATA') or os.path.expanduser('~'), 'dosev', 'logs')
    return '/var/log/dosev'


def _validate_and_warn(config: Dict[str, Any]) -> None:
    listen_port = config.get('listen_port', 53)
    if not isinstance(listen_port, int) or not 1 <= listen_port <= 65535:
        raise ValueError('listen_port must be between 1 and 65535')

    dns_max_payload = config.get('dns_max_payload', 4096)
    if not isinstance(dns_max_payload, int) or not 512 <= dns_max_payload <= 4096:
        raise ValueError('dns_max_payload must be between 512 and 4096')

    protocol = config.get('protocol', 'udp')
    if protocol not in {'udp', 'tcp', 'tls', 'https', 'quic'}:
        raise ValueError('protocol must be one of: udp, tcp, tls, https, quic')

    if config.get('dns_enable_dot', False) and not (config.get('dns_dot_cert_file') and config.get('dns_dot_key_file')):
        raise ValueError('dns_enable_dot requires dns_dot_cert_file and dns_dot_key_file')

    if config.get('dns_enable_doh', False) and not (config.get('dns_doh_cert_file') and config.get('dns_doh_key_file')):
        raise ValueError('dns_enable_doh requires dns_doh_cert_file and dns_doh_key_file')

    if config.get('dns_enable_dot', False) or config.get('dns_enable_doh', False):
        if config.get('protocol') == 'udp':
            warnings.warn('Secure listeners are enabled while the main resolver protocol is udp; this is usually intentional but verify your upstream defaults.', RuntimeWarning)

    rate_limit_rps = config.get('rate_limit_rps', 0.0)
    if rate_limit_rps < 0:
        raise ValueError('rate_limit_rps must be non-negative')

    rate_limit_burst = config.get('rate_limit_burst', 0.0)
    if rate_limit_burst < 0:
        raise ValueError('rate_limit_burst must be non-negative')

    if config.get('metrics_enabled', False) and config.get('metrics_port', 8000) == 53:
        warnings.warn('Metrics are enabled on port 53; this may conflict with DNS traffic.', RuntimeWarning)

    if config.get('doh_version', 'auto') not in {'auto', '1.1', '2', '3'}:
        raise ValueError('doh_version must be auto, 1.1, 2, or 3')


def load_config(path: str = 'config/dosev.conf') -> Dict[str, Any]:
    config = configparser.ConfigParser()
    if not os.path.exists(path):
        return {
            'listen_ip': '0.0.0.0',
            'listen_port': 53,
            'upstream_dns': '1.1.1.1',
            'protocol': 'udp',
            'verbose': False,
            'disable_ipv6': False,
            'strip_ipv6_records': None,  # None = use disable_ipv6 value
            'dns_cache_ttl': 300,
            'dns_cache_max_size': 1024,
            'dns_negative_cache_ttl': 5,
            'dns_logging_enabled': False,
            'dns_log_retention_days': 7,
            'dns_log_dir': _default_log_dir(),
            'dns_log_prefix': 'dns-log',
            'dns_pinned_certs': {},
            'dns_ecs_enabled': True,
            'dnssec_enabled': False,
            'auto_update_trust_anchor': True,
            'trust_anchors_file': '',
            'metrics_enabled': False,
            'metrics_port': 8000,
            'uvloop_enable': False,
            'upstream_retries': 2,
            'upstream_udp_timeout': 2.0,
            'upstream_tcp_timeout': 5.0,
            'upstream_doh_timeout': 5.0,
            'rate_limit_rps': 0.0,
            'rate_limit_burst': 0.0,
            'upstreams': [],
            'optimistic_cache_enabled': False,
            'optimistic_stale_max_age': 86400,
            'optimistic_stale_response_ttl': 30,
            'dns_privilege_drop_user': '',
            'dns_privilege_drop_group': '',
            'dns_chroot_dir': '',
            'dns_rebind_protection': False,
            'dns_rebind_action': 'strip',
            'pool_max_size': 5,
            'pool_idle_timeout': 60.0,
            'doh_version': 'auto',
            'doh_auto_cache_ttl': 3600,
            'bootstrap': {'servers': ['1.1.1.1:53', '8.8.8.8:53'], 'timeout': 2.0, 'retries': 2},
            'blocklists': {
                'enabled': False,
                'urls': [],
                'interval_seconds': 86400,
                'action': 'NXDOMAIN',
                'local_blocklist_dir': 'blocklists',
                'reload_on_change': True,
            },
        }

    config.read(path)

    listen_ip = config.get('server', 'listen_ip', fallback='0.0.0.0')
    listen_port = config.getint('server', 'listen_port', fallback=53)

    upstream_dns = config.get('resolver', 'upstream_dns', fallback='1.1.1.1')
    protocol = config.get('resolver', 'protocol', fallback='udp').lower()
    verbose = config.getboolean('resolver', 'verbose', fallback=False)
    disable_ipv6 = config.getboolean('resolver', 'disable_ipv6', fallback=False)
    dns_ecs_enabled = config.getboolean('resolver', 'dns_ecs_enabled', fallback=True)
    dns_max_payload = config.getint('resolver', 'dns_max_payload', fallback=4096)
    dns_enable_dot = config.getboolean('resolver', 'dns_enable_dot', fallback=False)
    dns_dot_port = config.getint('resolver', 'dns_dot_port', fallback=853)
    dns_dot_cert_file = config.get('resolver', 'dns_dot_cert_file', fallback='')
    dns_dot_key_file = config.get('resolver', 'dns_dot_key_file', fallback='')
    dns_enable_doh = config.getboolean('resolver', 'dns_enable_doh', fallback=False)
    dns_doh_port = config.getint('resolver', 'dns_doh_port', fallback=443)
    dns_doh_cert_file = config.get('resolver', 'dns_doh_cert_file', fallback='')
    dns_doh_key_file = config.get('resolver', 'dns_doh_key_file', fallback='')
    dns_doh_path = config.get('resolver', 'dns_doh_path', fallback='/dns-query')
    strip_ipv6_records_raw = config.get('resolver', 'strip_ipv6_records', fallback=None)
    if strip_ipv6_records_raw is None:
        strip_ipv6_records = None
    else:
        strip_ipv6_records = config.getboolean('resolver', 'strip_ipv6_records', fallback=None)

    dns_cache_ttl = config.getint('cache', 'ttl', fallback=300)
    dns_cache_max_size = config.getint('cache', 'max_size', fallback=1024)
    dns_negative_cache_ttl = config.getint('cache', 'negative_ttl', fallback=5)

    upstream_udp_timeout = config.getfloat('timeouts', 'udp', fallback=2.0)
    upstream_tcp_timeout = config.getfloat('timeouts', 'tcp', fallback=5.0)
    upstream_doh_timeout = config.getfloat('timeouts', 'doh', fallback=5.0)

    upstream_retries = config.getint('advanced', 'retries', fallback=2)
    rate_limit_rps = config.getfloat('advanced', 'rate_limit_rps', fallback=0.0)
    rate_limit_burst = config.getfloat('advanced', 'rate_limit_burst', fallback=0.0)
    optimistic_cache_enabled = config.getboolean('advanced', 'optimistic_cache_enabled', fallback=False)
    optimistic_stale_max_age = config.getint('advanced', 'optimistic_stale_max_age', fallback=86400)
    optimistic_stale_response_ttl = config.getint('advanced', 'optimistic_stale_response_ttl', fallback=30)
    pool_max_size = config.getint('advanced', 'pool_max_size', fallback=5)
    pool_idle_timeout = config.getfloat('advanced', 'pool_idle_timeout', fallback=60.0)
    doh_version = config.get('advanced', 'doh_version', fallback='auto').lower()
    if doh_version not in ('auto', '1.1', '2', '3'):
        doh_version = 'auto'
    doh_auto_cache_ttl = config.getint('advanced', 'doh_auto_cache_ttl', fallback=3600)

    dnssec_enabled = config.getboolean('security', 'dnssec_enabled', fallback=False)
    auto_update_trust_anchor = config.getboolean('security', 'auto_update_trust_anchor', fallback=True)
    trust_anchors_file = config.get('security', 'trust_anchors_file', fallback='')

    pinned_raw = config.get('security', 'pinned_certs', fallback='')
    dns_pinned_certs = {}
    for item in [s.strip() for s in pinned_raw.split(',') if s.strip()]:
        if '=' in item:
            host, fp = item.split('=', 1)
            dns_pinned_certs[host.strip()] = fp.strip()

    dns_rebind_protection = config.getboolean('security', 'rebind_protection', fallback=False)
    dns_rebind_action = config.get('security', 'rebind_action', fallback='strip').lower()
    if dns_rebind_action not in ('strip', 'block'):
        dns_rebind_action = 'strip'

    dns_privilege_drop_user = config.get('security', 'dns_privilege_drop_user', fallback='')
    dns_privilege_drop_group = config.get('security', 'dns_privilege_drop_group', fallback='')
    dns_chroot_dir = config.get('security', 'dns_chroot_dir', fallback='')

    dns_logging_enabled = config.getboolean('logging', 'enabled', fallback=False)
    dns_log_dir = config.get('logging', 'log_dir', fallback=_default_log_dir())
    dns_log_retention_days = config.getint('logging', 'retention_days', fallback=7)
    dns_log_prefix = config.get('logging', 'log_prefix', fallback='dns-log')

    metrics_enabled = config.getboolean('metrics', 'enabled', fallback=False)
    metrics_port = config.getint('metrics', 'port', fallback=8000)
    uvloop_enable = config.getboolean('metrics', 'uvloop_enable', fallback=False)

    bootstrap_servers_raw = config.get('bootstrap', 'servers', fallback='')
    if bootstrap_servers_raw.strip():
        bootstrap_servers = [s.strip() for s in bootstrap_servers_raw.split(',') if s.strip()]
    else:
        bootstrap_servers = ['1.1.1.1:53', '8.8.8.8:53']
    bootstrap_timeout = config.getfloat('bootstrap', 'timeout', fallback=2.0)
    bootstrap_retries = config.getint('bootstrap', 'retries', fallback=2)
    bootstrap = {
        'servers': bootstrap_servers,
        'timeout': bootstrap_timeout,
        'retries': bootstrap_retries,
    }

    upstreams = []
    if config.has_section('upstreams') and config.has_option('upstreams', 'servers'):
        server_names = [s.strip() for s in config.get('upstreams', 'servers').split(',') if s.strip()]
        for name in server_names:
            section = f'upstreams.{name}'
            if not config.has_section(section):
                continue
            address = config.get(section, 'address', fallback='')
            if not address:
                continue
            proto = config.get(section, 'protocol', fallback='udp').lower()
            port_str = config.get(section, 'port', fallback=None)
            if port_str:
                try:
                    port = int(port_str)
                except ValueError:
                    port = None
            else:
                default_ports = {'tls': 853, 'https': 443, 'quic': 853, 'udp': 53, 'tcp': 53}
                port = default_ports.get(proto, 53)
            hostname = config.get(section, 'hostname', fallback='') or address
            path = config.get(section, 'path', fallback='')
            us_doh_version = config.get(section, 'doh_version', fallback=doh_version).lower()
            if us_doh_version not in ('auto', '1.1', '2', '3'):
                us_doh_version = doh_version
            upstreams.append({
                'address': address,
                'protocol': proto,
                'port': port,
                'hostname': hostname,
                'doh_version': us_doh_version,
                'path': path,
            })

    blocklists = {
        'enabled': config.getboolean('blocklists', 'enabled', fallback=False),
        'urls': [u.strip() for u in config.get('blocklists', 'urls', fallback='').split(',') if u.strip()],
        'interval_seconds': config.getint('blocklists', 'interval_seconds', fallback=86400),
        'action': config.get('blocklists', 'action', fallback='NXDOMAIN').upper(),
        'local_blocklist_dir': config.get('blocklists', 'local_blocklist_dir', fallback='blocklists'),
        'reload_on_change': config.getboolean('blocklists', 'reload_on_change', fallback=True),
    }

    validated_config = {
        'listen_ip': listen_ip,
        'listen_port': listen_port,
        'upstream_dns': upstream_dns,
        'protocol': protocol,
        'dns_enable_dot': dns_enable_dot,
        'dns_dot_port': dns_dot_port,
        'dns_dot_cert_file': dns_dot_cert_file,
        'dns_dot_key_file': dns_dot_key_file,
        'dns_enable_doh': dns_enable_doh,
        'dns_doh_port': dns_doh_port,
        'dns_doh_cert_file': dns_doh_cert_file,
        'dns_doh_key_file': dns_doh_key_file,
        'dns_doh_path': dns_doh_path,
        'verbose': verbose,
        'disable_ipv6': disable_ipv6,
        'strip_ipv6_records': strip_ipv6_records,
        'dns_cache_ttl': dns_cache_ttl,
        'dns_cache_max_size': dns_cache_max_size,
        'dns_negative_cache_ttl': dns_negative_cache_ttl,
        'dns_logging_enabled': dns_logging_enabled,
        'dns_log_retention_days': dns_log_retention_days,
        'dns_log_dir': dns_log_dir,
        'dns_log_prefix': dns_log_prefix,
        'dns_pinned_certs': dns_pinned_certs,
        'dns_ecs_enabled': dns_ecs_enabled,
        'dns_max_payload': dns_max_payload,
        'dnssec_enabled': dnssec_enabled,
        'auto_update_trust_anchor': auto_update_trust_anchor,
        'metrics_enabled': metrics_enabled,
        'metrics_port': metrics_port,
        'uvloop_enable': uvloop_enable,
        'upstream_retries': upstream_retries,
        'upstream_udp_timeout': upstream_udp_timeout,
        'upstream_tcp_timeout': upstream_tcp_timeout,
        'upstream_doh_timeout': upstream_doh_timeout,
        'rate_limit_rps': rate_limit_rps,
        'rate_limit_burst': rate_limit_burst,
        'upstreams': upstreams,
        'optimistic_cache_enabled': optimistic_cache_enabled,
        'optimistic_stale_max_age': optimistic_stale_max_age,
        'optimistic_stale_response_ttl': optimistic_stale_response_ttl,
        'dns_privilege_drop_user': dns_privilege_drop_user,
        'dns_privilege_drop_group': dns_privilege_drop_group,
        'dns_chroot_dir': dns_chroot_dir,
        'dns_rebind_protection': dns_rebind_protection,
        'dns_rebind_action': dns_rebind_action,
        'pool_max_size': pool_max_size,
        'pool_idle_timeout': pool_idle_timeout,
        'doh_version': doh_version,
        'doh_auto_cache_ttl': doh_auto_cache_ttl,
        'bootstrap': bootstrap,
        'blocklists': blocklists,
    }

    _validate_and_warn(validated_config)
    return validated_config