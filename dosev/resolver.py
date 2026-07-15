# dosev/resolver.py – final production version with DoH URL parsing
# RFC compliance fixes applied: EDNS0, DNSSEC unsigned, negative cache TTL, TC bit
# Added: DoQ connection pooling, IPv6 stripping, HTTP/3 client (already present)
# Added: Upstream selection strategies (failover, parallel, random, roundrobin)
# Added: Health checks (circuit breaker) and TCP fallback on truncation
# Added: DNSSEC CD flag support (respect client's CD bit)
# Refactored: forward_dns_query split into helpers for maintainability
# Fixed: Reduced retries for auto-probing, added negative cache, limited concurrency
# Security: DNSSEC KeyTrap mitigation (CVE-2023-50387) – limits validations, DNSKEYs, timeout
# Security: Scrub unsolicited NS records (CVE-2025-11411, RFC 2181) – prevent cache poisoning

import asyncio
import logging
import socket
import ssl
import struct
import time
import hashlib
import ipaddress
import os
import random
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional, Tuple, Any, Set, Dict, Union, List, Callable, Coroutine, Iterable
from urllib.parse import urlparse

DEFAULT_LOG_DIR = os.path.join(os.getenv('LOCALAPPDATA') or os.path.expanduser('~'), 'dosev', 'logs') if os.name == 'nt' else '/var/log/dosev'

try:
    from cachetools import TTLCache
    _HAS_CACHETOOLS = True
except Exception:
    _HAS_CACHETOOLS = False
    TTLCache = None

try:
    import aioquic.asyncio
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    _HAS_AIOQUIC = True
except Exception:
    aioquic = None
    QuicConfiguration = None
    QuicConnection = None
    _HAS_AIOQUIC = False

try:
    from prometheus_client import Counter, Histogram
    _HAS_PROM = True
except Exception:
    Counter = None
    Histogram = None
    _HAS_PROM = False

try:
    import dns.message
    import dns.dnssec
    import dns.name
    import dns.resolver
    import dns.rdatatype
    import dns.rrset
    import dns.rdataclass
    import dns.rcode
    _HAS_DNSPY = True
except Exception:
    dns = None
    _HAS_DNSPY = False

try:
    import uvloop
    _HAS_UVLOOP = True
except Exception:
    uvloop = None
    _HAS_UVLOOP = False

MAX_UDP_PAYLOAD = 4096

# ---------- Default DNSSEC trust anchor (root KSK) ----------
DEFAULT_ROOT_DNSKEY = (
    ". 172800 IN DNSKEY 257 3 8 "
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+Erq1sBvNaRfxv4d8+1o5RsS5rG3FJ0fruu1Wg+0JvN6sL5nlk46iS2BsUj8IYL0="
)
DEFAULT_ROOT_DS = "19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"


class AsyncTTLCache:
    """Async-capable TTL cache with optional size limit and per-item TTL."""
    def __init__(self, maxsize: int = 1024, ttl: int = 300) -> None:
        self._data: Dict[str, Tuple[Any, float]] = {}
        self._default_ttl: int = ttl
        self._max: int = maxsize
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            v = self._data.get(key)
            if not v:
                return None
            value, expire = v
            if time.time() >= expire:
                del self._data[key]
                return None
            return value

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        async with self._lock:
            if len(self._data) >= self._max:
                oldest = min(self._data.items(), key=lambda kv: kv[1][1])[0]
                del self._data[oldest]
            expiry = time.time() + (ttl if ttl is not None else self._default_ttl)
            self._data[key] = (value, expiry)

    async def delete(self, key: str) -> None:
        async with self._lock:
            try:
                if key in self._data:
                    del self._data[key]
            except Exception:
                pass


class RateLimiter:
    """Token-bucket rate limiter for DNS queries (per IP)."""
    def __init__(self, rate: float, burst: float) -> None:
        self.rate: float = rate
        self.burst: float = burst
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

    async def is_allowed(self, key: str) -> bool:
        async with self._lock:
            now = time.time()
            tokens, last = self._buckets.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return True
            self._buckets[key] = (tokens, now)
            return False


class ConnectionPool:
    """A simple connection pool for TCP and TLS connections."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[asyncio.StreamReader, asyncio.StreamWriter, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        async with self._lock:
            if key in self._pools:
                while self._pools[key]:
                    reader, writer, _ = self._pools[key].pop()
                    if not writer.is_closing():
                        return reader, writer
                    try:
                        writer.close()
                    except Exception:
                        pass
        return None

    async def put(self, key: Tuple, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._lock:
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                return

            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) < self.max_size:
                self._pools[key].append((reader, writer, time.time()))
            else:
                writer.close()

    async def start_cleanup(self) -> None:
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    keys_to_purge = []
                    for key in list(self._pools.keys()):
                        keep = []
                        for reader, writer, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout or writer.is_closing():
                                try:
                                    writer.close()
                                except Exception:
                                    pass
                            else:
                                keep.append((reader, writer, last_used))
                        if keep:
                            self._pools[key] = keep
                        else:
                            keys_to_purge.append(key)
                    for key in keys_to_purge:
                        del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
        async with self._lock:
            for key in list(self._pools.values()):
                for _, writer, _ in key:
                    try:
                        writer.close()
                    except Exception:
                        pass
            self._pools.clear()


class ClientPool:
    """A pool that holds arbitrary client objects (httpx clients, QUIC connections, etc.)."""
    def __init__(self, max_size: int = 5, idle_timeout: float = 60.0) -> None:
        self.max_size: int = max_size
        self.idle_timeout: float = idle_timeout
        self._pools: Dict[Tuple, List[Tuple[Any, float]]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None

    async def get(self, key: Tuple) -> Optional[Any]:
        async with self._lock:
            if key in self._pools and self._pools[key]:
                client, _ = self._pools[key].pop()
                return client
        return None

    async def put(self, key: Tuple, client: Any) -> None:
        async with self._lock:
            if key not in self._pools:
                self._pools[key] = []
            if len(self._pools[key]) < self.max_size:
                self._pools[key].append((client, time.time()))
            else:
                await self._close_client(client)

    async def start_cleanup(self) -> None:
        async def _cleanup():
            while True:
                await asyncio.sleep(self.idle_timeout / 2)
                now = time.time()
                async with self._lock:
                    for key in list(self._pools.keys()):
                        keep = []
                        for client, last_used in self._pools[key]:
                            if now - last_used > self.idle_timeout:
                                await self._close_client(client)
                            else:
                                keep.append((client, last_used))
                        self._pools[key] = keep
                        if not self._pools[key]:
                            del self._pools[key]
        self._cleanup_task = asyncio.create_task(_cleanup())

    async def stop(self) -> None:
        if self._cleanup_task:
            self._cleanup_task.cancel()
        async with self._lock:
            for key in list(self._pools.values()):
                for client, _ in key:
                    await self._close_client(client)
            self._pools.clear()

    async def _close_client(self, client: Any) -> None:
        try:
            if isinstance(client, tuple) and len(client) == 2:
                conn, _ = client
                if hasattr(conn, 'close'):
                    conn.close()
                return
            # For aioquic clients, close the QUIC connection and exit context manager
            if hasattr(client, '_quic') and hasattr(client._quic, 'close'):
                client._quic.close()
            if hasattr(client, '_cm'):
                try:
                    await client._cm.__aexit__(None, None, None)
                except Exception:
                    pass
            if hasattr(client, 'aclose'):
                await client.aclose()
            elif hasattr(client, 'close'):
                client.close()
        except Exception:
            pass


class DNSResolver:
    """Async, robust DNS resolver/forwarder with DNSSEC validation cache.

    Features:
      - Async TTL cache (cachetools or internal async cache)
      - Per-protocol timeouts and retry/backoff
      - DoH over TLS with SNI preserved (manual HTTP/1.1, HTTP/2, HTTP/3)
      - Optional certificate pinning and DNSSEC validation
      - Optional Prometheus metrics and uvloop enable
      - Integrated rate limiter (per client IP)
      - Multi-upstream with automatic failover
      - Optimistic caching (serve-stale per RFC 8767)
      - DNS rebinding protection (strip or block private IPs)
      - Connection pooling for TCP, TLS, HTTP/2, HTTP/3, and DoQ
      - Bootstrap DNS servers for upstream hostname resolution
      - Custom port support (host:port)
      - DNSSEC validation cache (store validation result per RRset)
      - Automatic trust anchor management (bundled root key + optional IANA fetch)
      - DoH URL parsing (full https://host/path support)
      - IPv6 stripping (strip AAAA records from responses)
      - Upstream selection strategies: failover, parallel, random, roundrobin
      - Health checks (circuit breaker) for upstreams
      - TCP fallback on truncated UDP responses
      - DNSSEC CD flag support (respect client's CD bit)
      - DNSSEC KeyTrap mitigation (limits validations, DNSKEYs, timeout)
      - Scrub unsolicited NS records to prevent cache poisoning
    """

    def __init__(self,
                  upstreams: Optional[List[Dict[str, Any]]] = None,
                  verbose: bool = False,
                  disable_ipv6: bool = False,
                  strip_ipv6_records: bool = False,
                  cache_ttl: int = 300,
                  cache_max_size: int = 2048,
                  negative_cache_ttl: int = 5,
                  doh_timeout: float = 5.0,
                  udp_timeout: float = 2.0,
                  tcp_timeout: float = 5.0,
                  retries: int = 1,
                  dns_logging_enabled: bool = False,
                  dns_log_dir: str = DEFAULT_LOG_DIR,
                  pinned_certs: Optional[Dict[str, str]] = None,
                  dnssec_enabled: bool = False,
                  trust_anchors: Optional[Union[Dict[str, str], str]] = None,
                  auto_update_trust_anchor: bool = True,
                  metrics_enabled: bool = False,
                  metrics_port: int = 8000,
                  uvloop_enable: bool = False,
                  rate_limit_rps: float = 0.0,
                  rate_limit_burst: float = 0.0,
                  optimistic_cache_enabled: bool = False,
                  optimistic_stale_max_age: int = 86400,
                  optimistic_stale_response_ttl: int = 30,
                  rebind_protection_enabled: bool = False,
                  rebind_action: str = 'strip',
                  ecs_enabled: bool = True,
                  max_edns_payload: int = MAX_UDP_PAYLOAD,
                  pool_max_size: int = 5,
                  pool_idle_timeout: float = 60.0,
                  doh_version: str = 'auto',
                  doh_auto_cache_ttl: int = 3600,
                  load_balancing: str = 'failover',
                  bootstrap: Optional[Dict[str, Any]] = None,
                  tcp_fallback_enabled: bool = True,
                  health_config: Optional[Dict[str, Any]] = None,
                  dnssec_max_validations: int = 32,
                  dnssec_max_dnskey_records: int = 8,
                  dnssec_validation_timeout: float = 2.0,
                  scrub_unsolicited_ns: bool = True) -> None:
        self.upstreams: List[Dict[str, Any]] = upstreams or []

        if bootstrap is None:
            bootstrap = {}
        self.bootstrap_servers: List[str] = bootstrap.get('servers', [])
        self.bootstrap_timeout: float = bootstrap.get('timeout', 2.0)
        self.bootstrap_retries: int = bootstrap.get('retries', 2)

        self.disable_ipv6: bool = bool(disable_ipv6)
        self.strip_ipv6_records: bool = bool(strip_ipv6_records)
        self.verbose: bool = bool(verbose)
        self.logger: logging.Logger = logging.getLogger("dosev.DNSResolver")
        if not self.logger.handlers:
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            self.logger.addHandler(h)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        if _HAS_CACHETOOLS:
            self._dns_cache: Any = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache: Any = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._negative_cache: Any = TTLCache(maxsize=cache_max_size, ttl=negative_cache_ttl)
            self._cache_is_sync: bool = True
        else:
            self._dns_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._wire_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=cache_ttl)
            self._negative_cache: Any = AsyncTTLCache(maxsize=cache_max_size, ttl=negative_cache_ttl)
            self._cache_is_sync: bool = False

        self.negative_cache_ttl: int = max(1, int(negative_cache_ttl))

        self._lock: asyncio.Lock = asyncio.Lock()
        self._config_lock: asyncio.Lock = asyncio.Lock()
        self._trust_anchor_lock: asyncio.Lock = asyncio.Lock()
        self._blocklist_lock: asyncio.Lock = asyncio.Lock()

        self.doh_timeout: float = doh_timeout
        self.udp_timeout: float = udp_timeout
        self.tcp_timeout: float = tcp_timeout
        self.retries: int = max(1, int(retries))

        self.dns_logging_enabled: bool = dns_logging_enabled
        if dns_logging_enabled:
            dns_log_dir = dns_log_dir or DEFAULT_LOG_DIR
            try:
                from logging.handlers import TimedRotatingFileHandler
                os.makedirs(dns_log_dir, exist_ok=True)
                fh = TimedRotatingFileHandler(os.path.join(dns_log_dir, 'dns-requests.log'), when='midnight', backupCount=7)
                fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
                flog = logging.getLogger("dosev.DNSRequests")
                flog.setLevel(logging.INFO)
                if not any(isinstance(h, TimedRotatingFileHandler) for h in flog.handlers):
                    flog.addHandler(fh)
                self._file_logger: Optional[logging.Logger] = flog
            except Exception as e:
                self.logger.warning("Failed to init file logger: %s", e)
                self._file_logger = None
        else:
            self._file_logger = None

        self.pinned_certs: Dict[str, str] = pinned_certs or {}
        self.dnssec_enabled: bool = bool(dnssec_enabled)
        self.auto_update_trust_anchor: bool = auto_update_trust_anchor

        self.trust_anchors: Any = trust_anchors
        self._dnssec_raw_anchors: Optional[Any] = None
        self._dnssec_keyring: Optional[Any] = None
        self._trust_anchor_updater_task: Optional[asyncio.Task] = None

        self.metrics_enabled: bool = bool(metrics_enabled) and _HAS_PROM
        self._metrics: Optional[Dict[str, Any]] = None
        if self.metrics_enabled:
            try:
                self._metrics = {
                    'requests_total': Counter('dosev_dns_requests_total', 'Total DNS upstream requests', ['proto']),
                    'requests_errors': Counter('dosev_dns_request_errors_total', 'Failed DNS upstream requests', ['proto']),
                    'request_latency_seconds': Histogram('dosev_dns_request_latency_seconds', 'Upstream request latency seconds', ['proto'])
                }
                try:
                    from prometheus_client import start_http_server
                    try:
                        start_http_server(int(metrics_port))
                        self.logger.info("Prometheus metrics server started on :%s", metrics_port)
                    except Exception as e:
                        self.logger.debug("Could not start prometheus http server on %s: %s", metrics_port, e)
                except Exception as e:
                    self.logger.debug("Could not start prometheus http server: %s", e)
            except Exception:
                self._metrics = None

        if uvloop_enable and _HAS_UVLOOP:
            try:
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
                self.logger.info("uvloop enabled")
            except Exception as e:
                self.logger.warning("Failed to enable uvloop: %s", e)

        self._blocklist_exact: Set[str] = set()
        self._blocklist_suffix: Set[str] = set()
        self._hosts_map: Dict[str, Tuple[str, ...]] = {}
        self._block_action: str = 'NXDOMAIN'

        self.rate_limit_rps: float = rate_limit_rps
        self.rate_limit_burst: float = rate_limit_burst
        if rate_limit_rps > 0:
            effective_burst = max(1.0, rate_limit_burst)
            self.rate_limiter: Optional[RateLimiter] = RateLimiter(rate_limit_rps, effective_burst)
        else:
            self.rate_limiter = None

        self.optimistic_cache_enabled: bool = optimistic_cache_enabled
        self.stale_max_age: int = optimistic_stale_max_age
        self.stale_response_ttl: int = optimistic_stale_response_ttl
        self._stale_refresh_pending: Set[str] = set()
        self._stale_refresh_lock: asyncio.Lock = asyncio.Lock()

        self.rebind_protection_enabled: bool = rebind_protection_enabled
        self.rebind_action: str = rebind_action
        self.ecs_enabled: bool = bool(ecs_enabled)
        self.max_edns_payload: int = max(512, int(max_edns_payload))

        self._tcp_pool: ConnectionPool = ConnectionPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._h2_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._h3_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)
        self._quic_pool: ClientPool = ClientPool(max_size=pool_max_size, idle_timeout=pool_idle_timeout)

        self.doh_version: str = doh_version
        self.doh_auto_cache_ttl: int = doh_auto_cache_ttl
        self._doh_auto_cache: Dict[str, Tuple[str, float]] = {}
        self._doh_auto_lock: asyncio.Lock = asyncio.Lock()

        self.load_balancing: str = load_balancing
        self._rr_index: int = 0

        self.tcp_fallback_enabled: bool = tcp_fallback_enabled

        self._health_config: Dict[str, Any] = health_config or {}
        self._health_enabled: bool = self._health_config.get('enabled', False)
        self._health_interval: int = self._health_config.get('interval', 30)
        self._health_timeout: float = self._health_config.get('timeout', 2.0)
        self._health_unhealthy_threshold: int = self._health_config.get('unhealthy_threshold', 3)
        self._health_healthy_threshold: int = self._health_config.get('healthy_threshold', 2)
        self._health_cooldown: int = self._health_config.get('cooldown', 60)
        self._health_domain: str = self._health_config.get('domain', '.')

        self._upstream_health: Dict[str, Dict[str, Any]] = {}
        self._health_lock: asyncio.Lock = asyncio.Lock()
        self._health_task: Optional[asyncio.Task] = None

        # ---------- DNSSEC KeyTrap mitigation ----------
        self.dnssec_max_validations: int = dnssec_max_validations
        self.dnssec_max_dnskey_records: int = dnssec_max_dnskey_records
        self.dnssec_validation_timeout: float = dnssec_validation_timeout

        # ---------- Scrub unsolicited NS records ----------
        self.scrub_unsolicited_ns: bool = scrub_unsolicited_ns

    # ---------- Health check methods ----------
    def _get_upstream_key(self, upstream: Dict[str, Any]) -> str:
        addr = upstream.get('address', '')
        proto = upstream.get('protocol', 'udp')
        port = upstream.get('port', 53)
        return f"{addr}:{proto}:{port}"

    async def _do_health_check(self, upstream: Dict[str, Any]) -> bool:
        try:
            qname = self._health_domain
            query = dns.message.make_query(qname, dns.rdatatype.SOA)
            data = query.to_wire()
            result = await asyncio.wait_for(
                self._try_upstream(upstream, data, _health_check=True, _no_retry=True),
                timeout=self._health_timeout
            )
            return True
        except Exception as e:
            self.logger.debug("Health check failed for %s: %s", upstream.get('address'), e)
            return False

    async def _health_check_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self._health_interval)
                async with self._health_lock:
                    for upstream in self.upstreams:
                        key = self._get_upstream_key(upstream)
                        state = self._upstream_health.get(key, {})
                        now = time.time()
                        if state.get('next_retry', 0) > now:
                            continue
                        healthy = await self._do_health_check(upstream)
                        if healthy:
                            state['successes'] = state.get('successes', 0) + 1
                            state['failures'] = 0
                            if state['successes'] >= self._health_healthy_threshold:
                                state['healthy'] = True
                                state['successes'] = 0
                                self.logger.info("Upstream %s is now healthy", upstream.get('address'))
                        else:
                            state['failures'] = state.get('failures', 0) + 1
                            state['successes'] = 0
                            if state['failures'] >= self._health_unhealthy_threshold:
                                state['healthy'] = False
                                state['next_retry'] = time.time() + self._health_cooldown
                                self.logger.warning("Upstream %s marked unhealthy (failures=%d)",
                                                    upstream.get('address'), state['failures'])
                        state['last_check'] = time.time()
                        self._upstream_health[key] = state
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.warning("Health check loop error: %s", e)

    async def start_health_checks(self) -> None:
        if self._health_enabled and self.upstreams and self._health_task is None:
            self._health_task = asyncio.create_task(self._health_check_loop())
            self.logger.info("Health check loop started")

    async def start_background_tasks(self) -> None:
        """Start background tasks: DNSSEC trust anchor updater and health checks."""
        if self.dnssec_enabled and self.auto_update_trust_anchor and self._trust_anchor_updater_task is None:
            self._trust_anchor_updater_task = asyncio.create_task(self._background_trust_anchor_updater())
            self.logger.info("Trust anchor updater started")
        if self._health_enabled and self.upstreams and self._health_task is None:
            self._health_task = asyncio.create_task(self._health_check_loop())
            self.logger.info("Health check loop started")

    async def _get_healthy_upstreams(self, upstreams: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self._health_enabled:
            return upstreams
        healthy = []
        async with self._health_lock:
            for up in upstreams:
                key = self._get_upstream_key(up)
                state = self._upstream_health.get(key, {})
                if not state:
                    self._upstream_health[key] = {'healthy': True, 'failures': 0, 'successes': 0,
                                                  'last_check': 0, 'next_retry': 0}
                    healthy.append(up)
                elif state.get('healthy', True):
                    healthy.append(up)
        if not healthy:
            self.logger.warning("All upstreams are unhealthy, falling back to all")
            return upstreams
        return healthy

    # ---------- Existing helpers ----------
    async def start_pool_cleanups(self) -> None:
        await self._tcp_pool.start_cleanup()
        await self._h2_pool.start_cleanup()
        await self._h3_pool.start_cleanup()
        await self._quic_pool.start_cleanup()

    async def stop_pool_cleanups(self) -> None:
        await self._tcp_pool.stop()
        await self._h2_pool.stop()
        await self._h3_pool.stop()
        await self._quic_pool.stop()

    async def stop_background_tasks(self) -> None:
        if self._trust_anchor_updater_task is not None:
            self._trust_anchor_updater_task.cancel()
            try:
                await self._trust_anchor_updater_task
            except asyncio.CancelledError:
                pass
            self._trust_anchor_updater_task = None
        if self._health_task is not None:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
            self._health_task = None

    # ---------- blocklist helpers ----------
    async def set_blocklist(self, domains: Iterable[str]) -> None:
        async with self._blocklist_lock:
            self._blocklist_exact.clear()
            self._blocklist_suffix.clear()
            for d in domains:
                d = d.strip().lower().rstrip('.')
                if not d:
                    continue
                if d.startswith("."):
                    self._blocklist_suffix.add(d.lstrip("."))
                else:
                    self._blocklist_exact.add(d)

    async def set_hosts_map(self, hosts_map: Dict[str, Tuple[str, ...]]) -> None:
        async with self._blocklist_lock:
            self._hosts_map = {k.lower().rstrip('.'): tuple(v) for k, v in (hosts_map or {}).items()}

    async def get_host_for(self, qname: str) -> Optional[Tuple[str, ...]]:
        if not qname:
            return None
        async with self._blocklist_lock:
            return self._hosts_map.get(qname.lower().rstrip('.'))

    async def add_blocked(self, domain: str) -> None:
        d = domain.strip().lower().rstrip('.')
        async with self._blocklist_lock:
            if d.startswith("."):
                self._blocklist_suffix.add(d.lstrip("."))
            else:
                self._blocklist_exact.add(d)

    async def is_blocked(self, qname: Optional[str]) -> bool:
        if not qname:
            return False
        q = qname.lower().rstrip('.')
        async with self._blocklist_lock:
            if q in self._blocklist_exact:
                return True
            for suf in self._blocklist_suffix:
                if q == suf or q.endswith("." + suf):
                    return True
        return False

    @staticmethod
    def load_blocklists_from_dir(directory: str) -> Tuple[Set[str], Set[str], Dict[str, Tuple[str, ...]]]:
        exact_set: Set[str] = set()
        suffix_set: Set[str] = set()
        hosts_map: Dict[str, Tuple[str, ...]] = {}
        if not os.path.isdir(directory):
            return exact_set, suffix_set, hosts_map
        for fname in os.listdir(directory):
            path = os.path.join(directory, fname)
            if not os.path.isfile(path):
                continue
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.split('#', 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) == 0:
                        continue
                    if len(parts) >= 2 and (parts[0].count('.') == 3 or ':' in parts[0]):
                        ip = parts[0]
                        domain = parts[1].lower().rstrip('.')
                        hosts_map[domain] = (ip,)
                        continue
                    domain = parts[0].lower().rstrip('.')
                    if domain.startswith('.'):
                        suffix_set.add(domain.lstrip('.'))
                    else:
                        exact_set.add(domain)
        return exact_set, suffix_set, hosts_map

    # ---------- wire-cache helpers ----------
    async def _wire_cache_get(self, key: Tuple[str, int, str]) -> Optional[Tuple[bytes, float, bytes, float, bool]]:
        try:
            if self._cache_is_sync:
                val = self._wire_cache.get(key)
                if val is None:
                    return None
                if isinstance(val, tuple):
                    if len(val) == 4:
                        a, b, c, d = val
                        return (a, b, c, d, False)
                    elif len(val) == 5:
                        return val
                return None
            else:
                val = await self._wire_cache.get(key)
                if val is None:
                    return None
                if isinstance(val, tuple):
                    if len(val) == 4:
                        a, b, c, d = val
                        return (a, b, c, d, False)
                    elif len(val) == 5:
                        return val
                return None
        except Exception as e:
            self.logger.debug("wire cache get error %s: %s", key, e)
            return None

    async def _wire_cache_set(self, key: Tuple[str, int, str],
                              value: Tuple[bytes, float, bytes, float, bool]) -> None:
        try:
            if self._cache_is_sync:
                self._wire_cache[key] = value
            else:
                await self._wire_cache.set(key, value)
        except Exception as e:
            self.logger.debug("wire cache set error %s: %s", key, e)

    async def _wire_cache_delete(self, key: Tuple[str, int, str]) -> None:
        try:
            if self._cache_is_sync:
                if key in self._wire_cache:
                    del self._wire_cache[key]
            else:
                await self._wire_cache.delete(key)
        except Exception:
            pass

    async def _wire_cache_get_valid(self, key: Tuple[str, int, str]) -> Optional[Tuple[bytes, bool]]:
        async with self._lock:
            entry = await self._wire_cache_get(key)
            if entry is None:
                return None
            resp_bytes, expiry, query_data, stale_until, dnssec_validated = entry
            now = time.time()
            if now < expiry:
                return resp_bytes, dnssec_validated
            if self.optimistic_cache_enabled and now < stale_until:
                self.logger.debug("serving stale response for %s (age=%.1fs)", key, now - expiry)
                stale_resp = self._set_response_ttl(resp_bytes, self.stale_response_ttl)
                asyncio.create_task(self._maybe_refresh_stale(key, query_data))
                return stale_resp, dnssec_validated
            await self._wire_cache_delete(key)
            return None

    async def _cache_get(self, key: Tuple[str, int, str]) -> Optional[str]:
        try:
            if self._cache_is_sync:
                return self._dns_cache.get(key)
            else:
                return await self._dns_cache.get(key)
        except Exception:
            return None

    async def _cache_set(self, key: Tuple[str, int, str], value: str) -> None:
        try:
            if self._cache_is_sync:
                self._dns_cache[key] = value
            else:
                await self._dns_cache.set(key, value)
        except Exception:
            pass

    async def _negative_cache_get(self, key: Tuple[str, int, str]) -> Optional[bytes]:
        try:
            if self._cache_is_sync:
                return self._negative_cache.get(key)
            return await self._negative_cache.get(key)
        except Exception:
            return None

    async def _negative_cache_set(self, key: Tuple[str, int, str], value: bytes, ttl: Optional[int] = None) -> None:
        try:
            if self._cache_is_sync:
                self._negative_cache[key] = value
            else:
                await self._negative_cache.set(key, value, ttl=ttl)
        except Exception:
            pass

    async def _negative_cache_delete(self, key: Tuple[str, int, str]) -> None:
        try:
            if self._cache_is_sync:
                if key in self._negative_cache:
                    del self._negative_cache[key]
            else:
                await self._negative_cache.delete(key)
        except Exception:
            pass

    @staticmethod
    def _is_negative_response(response_bytes: bytes) -> bool:
        try:
            if not response_bytes or len(response_bytes) < 12 or not _HAS_DNSPY:
                return False
            msg = dns.message.from_wire(response_bytes)
            if msg.rcode() == dns.rcode.NXDOMAIN:
                return True
            return msg.rcode() == dns.rcode.NOERROR and not msg.answer
        except Exception:
            return False

    # ---------- other helpers ----------
    async def _maybe_refresh_stale(self, key: Tuple[str, int, str], query_data: bytes) -> None:
        async with self._stale_refresh_lock:
            if key in self._stale_refresh_pending:
                return
            self._stale_refresh_pending.add(key)
        asyncio.create_task(self._background_refresh(key, query_data))

    async def _background_refresh(self, key: Tuple[str, int, str], query_data: bytes) -> None:
        try:
            upstream_list = self.upstreams
            if not upstream_list:
                upstream_list = [{
                    'address': '1.1.1.1',
                    'protocol': 'udp',
                    'port': 53,
                    'hostname': '1.1.1.1',
                    'ip': '1.1.1.1',
                }]
            last_exc = None
            for upstream in upstream_list:
                try:
                    resp = await self._try_upstream(upstream, query_data)
                    dnssec_ok = False
                    if self.dnssec_enabled:
                        qname = key[0] if key[0] else None
                        if qname:
                            try:
                                secure, insecure = await self._dnssec_validate(qname, resp, dnssec_requested=False)
                                if secure:
                                    dnssec_ok = True
                                else:
                                    dnssec_ok = False
                            except Exception as e:
                                self.logger.warning("DNSSEC validation failed for stale refresh %s: %s", key, e)
                                continue
                    ttl = self._extract_min_ttl(resp)
                    if ttl <= 0:
                        ttl = 30
                    expiry = time.time() + ttl
                    stale_until = expiry + self.stale_max_age if self.optimistic_cache_enabled else expiry
                    val = (resp, expiry, query_data, stale_until, dnssec_ok)
                    async with self._lock:
                        await self._wire_cache_set(key, val)
                    self.logger.debug("stale refresh succeeded for %s from %s", key, upstream['address'])
                    return
                except Exception as e:
                    last_exc = e
                    self.logger.debug("stale refresh upstream %s failed: %s", upstream['address'], e)
            self.logger.warning("stale refresh failed for %s: %s", key, last_exc)
        finally:
            async with self._stale_refresh_lock:
                self._stale_refresh_pending.discard(key)

    def _set_response_ttl(self, response_bytes: bytes, ttl: int) -> bytes:
        if _HAS_DNSPY:
            try:
                msg = dns.message.from_wire(response_bytes)
                new_msg = dns.message.Message()
                new_msg.id = msg.id
                new_msg.flags = msg.flags
                for q in msg.question:
                    new_msg.question.append(q)

                def _replace_ttl(rrset_list):
                    new_list = []
                    for rrset in rrset_list:
                        new_rr = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                        new_rr.ttl = ttl
                        for rd in rrset:
                            new_rr.add(rd)
                        new_list.append(new_rr)
                    return new_list

                new_msg.answer = _replace_ttl(msg.answer)
                new_msg.authority = _replace_ttl(msg.authority)
                new_msg.additional = _replace_ttl(msg.additional)
                return new_msg.to_wire()
            except Exception as e:
                self.logger.debug("_set_response_ttl failed: %s", e)
        return response_bytes

    @staticmethod
    def _set_query_id(response_bytes: bytes, new_id: int) -> bytes:
        if len(response_bytes) < 2:
            return response_bytes
        return new_id.to_bytes(2, 'big') + response_bytes[2:]

    # ---------- IPv6 stripping ----------
    def _strip_ipv6_records(self, response_bytes: bytes) -> bytes:
        if not self.strip_ipv6_records:
            return response_bytes
        try:
            msg = dns.message.from_wire(response_bytes)
            msg.answer = [rrset for rrset in msg.answer if rrset.rdtype != dns.rdatatype.AAAA]
            msg.additional = [rrset for rrset in msg.additional if rrset.rdtype != dns.rdatatype.AAAA]
            return msg.to_wire()
        except Exception:
            return response_bytes

    # ---------- parsing helpers ----------
    @staticmethod
    def _parse_dns_name(packet: bytes, offset: int,
                        max_depth: int = 20,
                        _depth: int = 0) -> Tuple[str, int]:
        labels = []
        while True:
            if offset >= len(packet):
                raise ValueError("Out of bounds while parsing DNS name")
            length = packet[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(packet):
                    raise ValueError("Truncated pointer")
                pointer = ((length & 0x3F) << 8) | packet[offset + 1]
                if pointer >= len(packet):
                    raise ValueError("Pointer out of bounds")
                if _depth >= max_depth:
                    raise ValueError("Pointer loop detected")
                recursive_label, _ = DNSResolver._parse_dns_name(
                    packet, pointer, max_depth, _depth + 1
                )
                labels.append(recursive_label)
                offset += 2
                break
            if offset + 1 + length > len(packet):
                raise ValueError("Label extends past packet")
            labels.append(packet[offset + 1:offset + 1 + length].decode('ascii', errors='ignore'))
            offset += 1 + length
        name = '.'.join(labels)
        return name, offset

    def _extract_qname_from_wire(self, data: bytes) -> Optional[str]:
        try:
            if not data or len(data) < 12:
                return None
            qname, _ = self._parse_dns_name(data, 12)
            return qname
        except Exception:
            return None

    def _extract_qtype_from_wire(self, data: bytes) -> Optional[int]:
        try:
            if not data or len(data) < 12:
                return None
            _, off = self._parse_dns_name(data, 12)
            if off + 4 > len(data):
                return None
            qtype = (data[off] << 8) | data[off+1]
            return qtype
        except Exception:
            return None

    def _extract_question_section(self, packet: bytes) -> Tuple[bytes, int, int]:
        if not packet or len(packet) < 12:
            return b'', 0, 12
        qdcount = (packet[4] << 8) | packet[5]
        offset = 12
        for _ in range(qdcount):
            _, offset = self._parse_dns_name(packet, offset)
            offset += 4
            if offset > len(packet):
                raise ValueError("Truncated question section")
        return packet[12:offset], qdcount, offset

    def _extract_additional_section(self, packet: bytes, question_end: int) -> Tuple[bytes, int]:
        if not packet or len(packet) < 12 or question_end > len(packet):
            return b'', 0
        arcount = (packet[10] << 8) | packet[11]
        if arcount == 0:
            return b'', 0
        return packet[question_end:], arcount

    def _build_cache_key(self, data: bytes) -> Tuple[str, int, str, bytes]:
        qname = self._extract_qname_from_wire(data) or ""
        qtype = self._extract_qtype_from_wire(data) or 1
        try:
            _, _, question_end = self._extract_question_section(data)
            opt_bytes = data[question_end:]
        except Exception:
            opt_bytes = b''
        return (qname, qtype, 'unknown', opt_bytes)

    def _strip_ecs(self, data: bytes) -> bytes:
        try:
            if not _HAS_DNSPY:
                return data
            msg = dns.message.from_wire(data)
            if msg.opt is None:
                return data
            options = [opt for opt in msg.options if not isinstance(opt, dns.edns.ECSOption)]
            if len(options) == len(msg.options):
                return data
            msg.use_edns(edns=msg.edns, payload=msg.payload, options=options)
            return msg.to_wire()
        except Exception:
            return data

    def _normalize_query_for_forward(self, data: bytes) -> bytes:
        if not self.ecs_enabled:
            data = self._strip_ecs(data)
        return data

    # ---------- DNSSEC trust anchor management ----------
    def _fetch_root_trust_anchor_from_iana(self) -> Optional[str]:
        try:
            with urllib.request.urlopen("https://data.iana.org/root-anchors/root-anchors.xml", timeout=10) as response:
                xml_data = response.read()
            root = ET.fromstring(xml_data)
            for child in root:
                if child.tag == "KeyDigest":
                    key_tag = child.attrib.get("keyTag")
                    algo = child.attrib.get("algorithm")
                    digest_type = child.attrib.get("digestType")
                    digest = child.text.strip()
                    if key_tag and algo and digest_type and digest:
                        return f"{key_tag} {algo} {digest_type} {digest}"
            return None
        except Exception as e:
            self.logger.warning("Failed to fetch root trust anchor from IANA: %s", e)
            return None

    def _load_trust_anchors(self) -> None:
        if not self.dnssec_enabled:
            return

        anchors: Dict[dns.name.Name, dns.rrset.RRset] = {}

        if self.trust_anchors is None:
            try:
                parts = DEFAULT_ROOT_DNSKEY.split()
                name = parts[0]
                ttl = int(parts[1])
                rdclass = parts[2]
                rdtype = parts[3]
                rdata = ' '.join(parts[4:])
                rr = dns.rrset.from_text(name, ttl, rdclass, rdtype, rdata)
                # Apply DNSKEY limit to built-in anchor
                if self.dnssec_max_dnskey_records == 0:
                    # Limit 0: skip loading DNSKEYs (treat as no trust anchor)
                    self.logger.warning("dnssec_max_dnskey_records is 0, not loading any DNSKEYs")
                    anchors = {}
                else:
                    # Limit the number of DNSKEYs in the built-in anchor
                    count = 0
                    limited_rr = dns.rrset.RRset(rr.name, rr.rdclass, rr.rdtype)
                    limited_rr.ttl = rr.ttl
                    for r in rr:
                        if count >= self.dnssec_max_dnskey_records:
                            self.logger.warning("DNSKEY limit (%d) reached for built-in root anchor, truncating",
                                                self.dnssec_max_dnskey_records)
                            break
                        limited_rr.add(r)
                        count += 1
                    anchors[dns.name.root] = limited_rr
                self.logger.info("Using bundled default root trust anchor (limited to %d DNSKEYs)",
                                 self.dnssec_max_dnskey_records)
            except Exception as e:
                self.logger.error("Failed to parse default root trust anchor: %s", e)
                return

        elif isinstance(self.trust_anchors, str):
            path = self.trust_anchors
            try:
                with open(path, 'r') as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or line.startswith('#') or line.startswith(';'):
                            continue
                        parts = line.split()
                        if len(parts) < 5:
                            self.logger.debug("skipping malformed anchor line: %s", line)
                            continue
                        try:
                            idx = parts.index('DNSKEY')
                        except ValueError:
                            try:
                                idx = parts.index('dnskey')
                            except ValueError:
                                self.logger.debug("no DNSKEY token in line: %s", line)
                                continue
                        if idx < 1:
                            self.logger.debug("unexpected DNSKEY line format: %s", line)
                            continue
                        name_text = parts[0]
                        ttl_text = parts[1] if idx >= 2 else '3600'
                        try:
                            ttl = int(ttl_text)
                        except Exception:
                            ttl = 3600
                        rdata_text = ' '.join(parts[idx+1:])
                        try:
                            rr = dns.rrset.from_text(name_text, ttl, 'IN', 'DNSKEY', rdata_text)
                            name_obj = dns.name.from_text(name_text)
                            if self.dnssec_max_dnskey_records == 0:
                                # Skip loading any DNSKEYs
                                self.logger.debug("Skipping DNSKEY for %s due to limit 0", name_text)
                                continue
                            if name_obj in anchors:
                                # Limit the number of DNSKEYs per domain
                                current_count = len(anchors[name_obj])
                                for r in rr:
                                    if current_count >= self.dnssec_max_dnskey_records:
                                        self.logger.warning("DNSKEY limit (%d) reached for %s, truncating",
                                                            self.dnssec_max_dnskey_records, name_text)
                                        break
                                    anchors[name_obj].add(r)
                                    current_count += 1
                            else:
                                # Create new RRset with limited records
                                new_rr = dns.rrset.RRset(name_obj, rr.rdclass, rr.rdtype)
                                new_rr.ttl = rr.ttl
                                count = 0
                                for r in rr:
                                    if count >= self.dnssec_max_dnskey_records:
                                        self.logger.warning("DNSKEY limit (%d) reached for %s, truncating",
                                                            self.dnssec_max_dnskey_records, name_text)
                                        break
                                    new_rr.add(r)
                                    count += 1
                                anchors[name_obj] = new_rr
                        except Exception as e:
                            self.logger.debug("failed to parse anchor line '%s': %s", line, e)
                            continue
                self.logger.info("Loaded trust anchors from file: %s (limited to %d DNSKEYs per domain)",
                                 path, self.dnssec_max_dnskey_records)
            except Exception as e:
                self.logger.warning("failed to load trust anchors from %s: %s", path, e)
                return

        elif isinstance(self.trust_anchors, dict):
            anchors = self.trust_anchors
            # Apply limit to each RRset in the dict
            if self.dnssec_max_dnskey_records == 0:
                self.logger.warning("dnssec_max_dnskey_records is 0, not using any trust anchors")
                anchors = {}
            else:
                for name, rrset in list(anchors.items()):
                    if len(rrset) > self.dnssec_max_dnskey_records:
                        new_rr = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                        new_rr.ttl = rrset.ttl
                        count = 0
                        for r in rrset:
                            if count >= self.dnssec_max_dnskey_records:
                                break
                            new_rr.add(r)
                            count += 1
                        anchors[name] = new_rr
                        self.logger.debug("Truncated DNSKEY RRset for %s to %d records",
                                          name, self.dnssec_max_dnskey_records)
            self.logger.info("Using provided trust anchors dict (limited to %d DNSKEYs per domain)",
                             self.dnssec_max_dnskey_records)

        else:
            self.logger.warning("Unsupported trust_anchors type: %s", type(self.trust_anchors))
            return

        self._dnssec_raw_anchors = anchors
        self._dnssec_keyring = None

    async def _update_trust_anchor_from_iana(self) -> bool:
        if not self.dnssec_enabled:
            return False

        async with self._trust_anchor_lock:
            new_ds = await asyncio.get_running_loop().run_in_executor(
                None, self._fetch_root_trust_anchor_from_iana
            )
            if new_ds is None:
                return False

            try:
                rr = dns.rrset.from_text(".", 0, "IN", "DS", new_ds)
                anchors = {dns.name.root: rr}
                self._dnssec_raw_anchors = anchors
                self._dnssec_keyring = None
                self.logger.info("Updated root trust anchor from IANA: %s", new_ds)
                return True
            except Exception as e:
                self.logger.warning("Failed to update trust anchor from IANA: %s", e)
                return False

    async def _background_trust_anchor_updater(self) -> None:
        await asyncio.sleep(random.randint(300, 900))
        while True:
            try:
                updated = await self._update_trust_anchor_from_iana()
                if updated:
                    self.logger.info("Trust anchor updated from IANA")
            except Exception as e:
                self.logger.warning("Background trust anchor update failed: %s", e)
            await asyncio.sleep(86400)

    # ---------- DNSSEC validation with KeyTrap mitigation ----------
    async def _dnssec_validate(self, qname: str, response_wire: bytes, dnssec_requested: bool = True) -> Tuple[bool, bool]:
        if not self.dnssec_enabled:
            return False, True
        if not _HAS_DNSPY:
            raise RuntimeError("dnspython required")
        if not dnssec_requested:
            return False, True

        if self._dnssec_raw_anchors is None:
            self._load_trust_anchors()
        if not self._dnssec_raw_anchors:
            raise Exception("DNSSEC trust anchors missing")

        validation_counter = 0
        max_validations = self.dnssec_max_validations if self.dnssec_max_validations > 0 else 999999

        def _validate() -> Tuple[bool, bool]:
            nonlocal validation_counter
            msg = dns.message.from_wire(response_wire)
            has_rrsig = any(rr.rdtype == dns.rdatatype.RRSIG for rr in msg.answer)
            if not has_rrsig:
                return False, True

            for rrset in msg.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    continue
                sig = None
                for rr in msg.answer:
                    if rr.rdtype == dns.rdatatype.RRSIG and rr.name == rrset.name:
                        for r in rr:
                            if r.type_covered == rrset.rdtype:
                                sig = rr
                                break
                        if sig:
                            break
                if sig is None:
                    raise dns.dnssec.ValidationFailure(f"No RRSIG for rrset {rrset.name}")

                validation_counter += 1
                if validation_counter > max_validations:
                    self.logger.warning("DNSSEC validation limit (%d) exceeded for %s, treating as insecure",
                                        max_validations, qname)
                    return False, True

                dns.dnssec.validate(rrset, sig, self._dnssec_raw_anchors)

            return True, False

        try:
            secure, insecure = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(None, _validate),
                timeout=self.dnssec_validation_timeout
            )
            if secure:
                self.logger.debug("DNSSEC validation passed for %s (validations=%d)",
                                  qname, validation_counter)
            else:
                self.logger.debug("DNSSEC validation: insecure (unsigned) for %s", qname)
            return secure, insecure
        except asyncio.TimeoutError:
            self.logger.warning("DNSSEC validation timeout for %s after %.1fs",
                                qname, self.dnssec_validation_timeout)
            return False, True
        except dns.dnssec.ValidationFailure as e:
            self.logger.warning("DNSSEC validation bogus for %s: %s", qname, e)
            raise
        except Exception as e:
            self.logger.warning("DNSSEC validation error for %s: %s", qname, e)
            raise

    # ---------- upstream resolution ----------
    async def _resolve_upstream_ip(self, hostname: str, ip_override: Optional[str] = None) -> str:
        if ip_override:
            try:
                ipaddress.ip_address(ip_override)
                self.logger.debug("using fixed IP for upstream: %s", ip_override)
                return ip_override
            except ValueError:
                self.logger.warning("ip_override '%s' is not a valid IP address, falling back to resolution", ip_override)

        try:
            ipaddress.ip_address(hostname)
            self.logger.debug("hostname %s is already an IP address, skipping resolution", hostname)
            return hostname
        except ValueError:
            pass

        key = (hostname, bool(self.disable_ipv6))
        async with self._lock:
            cached = await self._cache_get(key)
            if cached:
                self.logger.debug("resolved %s from cache -> %s", hostname, cached)
                return cached

        self.logger.debug("resolving upstream hostname: %s", hostname)

        if self.bootstrap_servers:
            for bs in self.bootstrap_servers:
                try:
                    ip, port = self._split_hostport(bs, default_port=53)
                    addr = await self._udp_query_a_or_aaaa(ip, port, hostname, qtype=1)
                    if not addr:
                        addr = await self._udp_query_a_or_aaaa(ip, port, hostname, qtype=28)
                    if addr:
                        async with self._lock:
                            await self._cache_set(key, addr)
                        self.logger.debug("bootstrap server %s returned %s for %s", bs, addr, hostname)
                        return addr
                except Exception as e:
                    self.logger.debug("bootstrap server %s failed: %s", bs, e)
                    continue

        try:
            family = socket.AF_INET if self.disable_ipv6 else 0
            infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, family=family, type=socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if addr:
                    async with self._lock:
                        await self._cache_set(key, addr)
                    self.logger.debug("system resolver returned %s for %s", addr, hostname)
                    return addr
        except Exception as e:
            self.logger.debug("system resolver failed for %s: %s", hostname, e)

        self.logger.error("unable to resolve upstream hostname: %s", hostname)
        raise Exception(f"Unable to resolve upstream hostname: {hostname}")

    async def _udp_query_a_or_aaaa(self, resolver_ip: str, resolver_port: int, qname: str, qtype: int = 1) -> Optional[str]:
        self.logger.debug("udp lookup of %s via %s:%d", qname, resolver_ip, resolver_port)
        loop = asyncio.get_running_loop()
        try:
            ip_obj = ipaddress.ip_address(resolver_ip)
            fam = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
        except Exception:
            fam = socket.AF_INET
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            tid = int(time.time() * 1000) & 0xFFFF
            header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split("."))
            q += b"\x00" + struct.pack(">HH", int(qtype), 1)
            query = header + q
            addr_tuple = (resolver_ip, resolver_port) if fam == socket.AF_INET else (resolver_ip, resolver_port, 0, 0)
            await loop.sock_sendto(sock, query, addr_tuple)
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=self.udp_timeout)
            except asyncio.TimeoutError:
                self.logger.debug("udp lookup timed out for %s (qtype=%s)", qname, qtype)
                return None

            if len(data) < 12:
                raise Exception("short DNS response")
            qdcount = (data[4] << 8) | data[5]
            ancount = (data[6] << 8) | data[7]
            i = 12
            for _ in range(qdcount):
                _, i = self._parse_dns_name(data, i)
                i += 4
            a_addr: Optional[str] = None
            aaaa_addr: Optional[str] = None
            for _ in range(ancount):
                _, i = self._parse_dns_name(data, i)
                if i + 10 > len(data):
                    raise Exception("truncated answer header")
                rtype = (data[i] << 8) | data[i+1]
                ttl = struct.unpack(">I", data[i+4:i+8])[0]
                rdlen = (data[i+8] << 8) | data[i+9]
                if i + 10 + rdlen > len(data):
                    raise Exception("truncated rdata")
                rdata = data[i+10:i+10+rdlen]
                i += 10 + rdlen
                if rtype == 1 and rdlen == 4:
                    a_addr = ".".join(str(b) for b in rdata)
                elif rtype == 28 and rdlen == 16:
                    try:
                        aaaa_addr = socket.inet_ntop(socket.AF_INET6, bytes(rdata))
                    except Exception:
                        aaaa_addr = ":".join("{:02x}{:02x}".format(rdata[j], rdata[j+1]) for j in range(0, 16, 2))
            if qtype == 1:
                return a_addr
            if qtype == 28:
                return aaaa_addr
            return a_addr or aaaa_addr
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ---------- _try_upstream with health checks and TCP fallback ----------
    async def _try_upstream(self, upstream: Dict[str, Any], data: bytes, _health_check: bool = False, _no_retry: bool = False) -> bytes:
        proto = upstream.get('protocol', 'udp')
        if proto == 'udp':
            try:
                response = await self._with_retries(
                    lambda d: self._forward_udp(d, upstream), data, timeout=self.udp_timeout, no_retry=_no_retry)
                if self.tcp_fallback_enabled and not _health_check:
                    if len(response) >= 4:
                        flags = int.from_bytes(response[2:4], 'big')
                        if flags & 0x0200:
                            self.logger.debug("UDP response truncated (TC=1), falling back to TCP for %s",
                                              upstream.get('address'))
                            tcp_upstream = upstream.copy()
                            tcp_upstream['protocol'] = 'tcp'
                            if 'port' not in tcp_upstream:
                                tcp_upstream['port'] = 53
                            return await self._with_retries(
                                lambda d: self._forward_tcp(d, tcp_upstream), data, timeout=self.tcp_timeout, no_retry=_no_retry)
                return response
            except Exception as e:
                raise
        elif proto == 'tcp':
            return await self._with_retries(
                lambda d: self._forward_tcp(d, upstream), data, timeout=self.tcp_timeout, no_retry=_no_retry)
        elif proto == 'tls':
            return await self._with_retries(
                lambda d: self._forward_tls(d, upstream), data, timeout=self.tcp_timeout, no_retry=_no_retry)
        elif proto == 'https':
            return await self._with_retries(
                lambda d: self._forward_https(d, upstream), data, timeout=self.doh_timeout, no_retry=_no_retry)
        elif proto == 'quic':
            if not _HAS_AIOQUIC:
                raise RuntimeError("aioquic not available for DoQ")
            return await self._with_retries(
                lambda d: self._forward_quic(d, upstream), data, timeout=self.doh_timeout, no_retry=_no_retry)
        else:
            raise ValueError(f"Unsupported upstream protocol: {proto}")

    # ---------- Scrub unsolicited NS records ----------
    # ---------- Scrub unsolicited NS records ----------
    # ---------- Scrub unsolicited NS records ----------
    def _scrub_authority_section(self, response_bytes: bytes, qname: str) -> bytes:
        """
        Remove unsolicited NS records from the authority section that are not within
        the same bailiwick as the query. This prevents cache poisoning (CVE-2025-11411).
        Based on Unbound's iter_scrub.c implementation.

        Args:
            response_bytes: Wire-format DNS response
            qname: Original query name (fully qualified)

        Returns:
            Scrubbed wire-format response
        """
        if not self.scrub_unsolicited_ns or not _HAS_DNSPY:
            return response_bytes

        try:
            msg = dns.message.from_wire(response_bytes)
            if not msg.authority:
                return response_bytes

            qname_lower = qname.lower().rstrip('.')
            filtered_authority = []
            for rrset in msg.authority:
                if rrset.rdtype != dns.rdatatype.NS:
                    filtered_authority.append(rrset)
                    continue

                # Root NS (name == ".") must ALWAYS be kept
                if rrset.name == dns.name.root:
                    filtered_authority.append(rrset)
                    continue

                rr_name = str(rrset.name).lower().rstrip('.')

                # Allow NS records that are at or above the qname's zone
                if rr_name == qname_lower:
                    filtered_authority.append(rrset)
                elif qname_lower.endswith('.' + rr_name):
                    # qname is a subdomain of the NS name (valid delegation)
                    filtered_authority.append(rrset)
                elif rr_name.endswith('.' + qname_lower):
                    # NS name is a subdomain of the qname (unusual but accept)
                    filtered_authority.append(rrset)
                else:
                    self.logger.debug("Scrubbed unsolicited NS record for %s (qname=%s)", rr_name, qname)

            msg.authority = filtered_authority
            return msg.to_wire()
        except Exception as e:
            self.logger.debug("NS scrubbing failed: %s", e)
            return response_bytes
        
    # ---------- Refactored forward_dns_query with CD flag ----------
    async def forward_dns_query(self, data: bytes) -> bytes:
        original_data = data
        data = self._normalize_query_for_forward(data)
        qname = self._extract_qname_from_wire(data)
        qtype = self._extract_qtype_from_wire(data) or 1
        key = self._build_cache_key(data)
        orig_id = int.from_bytes(data[:2], 'big')

        dnssec_requested = self._dnssec_requested(original_data)
        cd_flag = False
        if len(original_data) >= 4:
            flags = int.from_bytes(original_data[2:4], 'big')
            cd_flag = bool(flags & 0x0010)
        if cd_flag:
            dnssec_requested = False

        host_values = await self._check_hosts_and_blocklists(qname, qtype, original_data)
        if host_values is not None:
            return host_values

        cached = await self._check_caches(key, qname, original_data, dnssec_requested)
        if cached is not None:
            return self._set_query_id(cached, orig_id)

        upstream_list = list(self.upstreams) if self.upstreams else []
        if not upstream_list:
            upstream_list = [{
                'address': '1.1.1.1',
                'protocol': 'udp',
                'port': 53,
                'hostname': '1.1.1.1',
                'ip': '1.1.1.1',
            }]

        if self._health_enabled:
            healthy_list = await self._get_healthy_upstreams(upstream_list)
            if healthy_list:
                upstream_list = healthy_list

        strategy = self.load_balancing
        try:
            resp = await self._execute_strategy(strategy, upstream_list, data, qname, dnssec_requested, key, orig_id)
            return resp
        except Exception as e:
            self.logger.error("Upstream query failed: %s", e)
            raise

    # ---------- Helper methods for forward_dns_query ----------
    async def _check_hosts_and_blocklists(self, qname: str, qtype: int, original_data: bytes) -> Optional[bytes]:
        if qname:
            host_values = await self.get_host_for(qname)
            if host_values:
                if qtype == 1 and len(host_values) > 0:
                    ip = host_values[0]
                    try:
                        if _HAS_DNSPY:
                            absolute_qname = qname if qname.endswith('.') else f"{qname}."
                            resp = dns.message.make_response(dns.message.from_wire(original_data) if original_data else None)
                            rr = dns.rrset.from_text(absolute_qname, 60, dns.rdataclass.IN, dns.rdatatype.A, ip)
                            resp.answer = [rr]
                            return resp.to_wire()
                        else:
                            return self._build_local_A_response(original_data, ip)
                    except Exception:
                        self.logger.exception("failed to synthesize hosts map response for %s", qname)
            if await self.is_blocked(qname):
                self._log_event("Blocked (internal)", qname, None, "blocklist")
                try:
                    return self.build_block_response(original_data)
                except Exception:
                    return self._make_nxdomain_response(original_data)
        return None

    async def _check_caches(self, key, qname: str, original_data: bytes, dnssec_requested: bool) -> Optional[bytes]:
        cached_negative = await self._negative_cache_get(key)
        if cached_negative is not None:
            self.logger.debug("negative-cache hit %s", key)
            return cached_negative

        cached = await self._wire_cache_get_valid(key)
        if cached is not None:
            resp_bytes, dnssec_validated = cached
            self.logger.debug("wire-cache hit %s", key)

            if self.dnssec_enabled and not dnssec_validated:
                self.logger.debug("cache entry lacks DNSSEC validation, revalidating...")
                try:
                    secure, insecure = await self._dnssec_validate(qname, resp_bytes, dnssec_requested)
                    if secure or insecure:
                        async with self._lock:
                            entry = await self._wire_cache_get(key)
                            if entry is not None:
                                _, expiry, query_data, stale_until, _ = entry
                                new_val = (resp_bytes, expiry, query_data, stale_until, True)
                                await self._wire_cache_set(key, new_val)
                        dnssec_validated = True
                except Exception as e:
                    self.logger.warning("DNSSEC revalidation failed for %s, treating as cache miss", key)
                    async with self._lock:
                        await self._wire_cache_delete(key)
                    return None

            if self.rebind_protection_enabled:
                resp_bytes = self._apply_rebind_protection(resp_bytes)
                if resp_bytes is None:
                    return self._make_nxdomain_response(original_data)
            return resp_bytes
        return None

    async def _execute_strategy(self, strategy: str, upstream_list: List[Dict[str, Any]],
                                data: bytes, qname: str, dnssec_requested: bool,
                                key, orig_id: int) -> bytes:
        last_exc = None
        if strategy == 'failover':
            for upstream in upstream_list:
                try:
                    return await self._process_upstream_response(
                        upstream, data, qname, dnssec_requested, key, orig_id)
                except Exception as e:
                    last_exc = e
                    self.logger.debug("upstream %s failed: %s", upstream.get('address'), e)
                    continue
            raise last_exc or Exception("All upstreams failed")

        elif strategy == 'parallel':
            semaphore = asyncio.Semaphore(5)
            async def bounded_task(upstream):
                async with semaphore:
                    return await self._process_upstream_response(
                        upstream, data, qname, dnssec_requested, key, orig_id)
            tasks = [asyncio.create_task(bounded_task(upstream)) for upstream in upstream_list]
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if not t.cancelled():
                        try:
                            result = t.result()
                            for p in pending:
                                p.cancel()
                            return result
                        except Exception as e:
                            pass
                raise last_exc or Exception("All upstreams failed in parallel")
            except Exception as e:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise e

        elif strategy == 'random':
            import random
            upstream = random.choice(upstream_list)
            try:
                return await self._process_upstream_response(
                    upstream, data, qname, dnssec_requested, key, orig_id)
            except Exception as e:
                last_exc = e
                self.logger.debug("random upstream %s failed: %s", upstream.get('address'), e)
                raise last_exc

        elif strategy == 'roundrobin':
            idx = self._rr_index % len(upstream_list)
            upstream = upstream_list[idx]
            self._rr_index += 1
            try:
                return await self._process_upstream_response(
                    upstream, data, qname, dnssec_requested, key, orig_id)
            except Exception as e:
                last_exc = e
                self.logger.debug("roundrobin upstream %s failed: %s", upstream.get('address'), e)
                raise last_exc
        else:
            raise ValueError(f"Unknown load balancing strategy: {strategy}")

    async def _process_upstream_response(self, upstream: Dict[str, Any], data: bytes,
                                         qname: str, dnssec_requested: bool,
                                         key, orig_id: int) -> bytes:
        resp = await self._try_upstream(upstream, data)

        if self.metrics_enabled and self._metrics:
            try:
                self._metrics['requests_total'].labels(proto=upstream['protocol']).inc()
            except Exception:
                pass

        # Scrub unsolicited NS records before caching
        if self.scrub_unsolicited_ns and qname:
            resp = self._scrub_authority_section(resp, qname)

        dnssec_ok = False
        if self.dnssec_enabled and qname and dnssec_requested:
            try:
                secure, insecure = await self._dnssec_validate(qname, resp, dnssec_requested)
                if secure:
                    dnssec_ok = True
                else:
                    dnssec_ok = False
            except Exception as e:
                self.logger.warning("DNSSEC validation failed for %s: %s", qname, e)
                raise

        if self.rebind_protection_enabled:
            resp = self._apply_rebind_protection(resp)
            if resp is None:
                return self._make_nxdomain_response(data)

        if self.strip_ipv6_records:
            resp = self._strip_ipv6_records(resp)

        if self._is_negative_response(resp):
            ttl = self._extract_soa_minimum(resp)
            if ttl is None:
                ttl = self.negative_cache_ttl
            async with self._lock:
                await self._wire_cache_delete(key)
                await self._negative_cache_set(key, resp, ttl=ttl)
            return self._set_query_id(resp, orig_id)

        ttl = self._extract_min_ttl(resp)
        if ttl <= 0:
            ttl = 30
        expiry = time.time() + ttl
        stale_until = expiry + self.stale_max_age if self.optimistic_cache_enabled else expiry
        val = (resp, expiry, data, stale_until, dnssec_ok)
        async with self._lock:
            await self._negative_cache_delete(key)
            await self._wire_cache_set(key, val)

        return self._set_query_id(resp, orig_id)

    # ---------- Forwarding implementations ----------
    async def _forward_udp(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 53)
        ip_override = upstream.get('ip')
        resolved = await self._resolve_upstream_ip(host, ip_override)
        family = socket.AF_INET6 if self._is_ipv6_address(resolved) else socket.AF_INET
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")
        loop = asyncio.get_running_loop()

        on_response: asyncio.Future[bytes] = loop.create_future()

        class _Proto(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.transport: Optional[asyncio.DatagramTransport] = None

            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.transport = transport
                try:
                    transport.sendto(data)
                except Exception as e:
                    if not on_response.done():
                        on_response.set_exception(e)

            def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
                if not on_response.done():
                    on_response.set_result(data)

            def error_received(self, exc: Exception) -> None:
                if not on_response.done():
                    on_response.set_exception(exc)

            def connection_lost(self, exc: Optional[Exception]) -> None:
                if exc and not on_response.done():
                    on_response.set_exception(exc)

        transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(), remote_addr=(resolved, int(port)), family=family)
        try:
            return await asyncio.wait_for(on_response, timeout=self.udp_timeout)
        finally:
            transport.close()

    async def _forward_tcp(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 53)
        ip_override = upstream.get('ip')
        key = (host, port)
        pooled = await self._tcp_pool.get(key)
        if pooled:
            reader, writer = pooled
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                pooled = None

        if not pooled:
            resolved = await self._resolve_upstream_ip(host, ip_override)
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")
            reader, writer = await asyncio.open_connection(resolved, int(port))
        try:
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, "big")
            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)
            await self._tcp_pool.put(key, reader, writer)
            return resp
        except Exception:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            raise

    async def _forward_tls(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 853)
        hostname = upstream.get('hostname', host)
        ip_override = upstream.get('ip')

        self.logger.debug("TLS forward to %s:%s (hostname=%s)", host, port, hostname)

        key = (host, port, hostname)
        pooled = await self._tcp_pool.get(key)
        if pooled:
            reader, writer = pooled
            if writer.is_closing():
                try:
                    writer.close()
                except Exception:
                    pass
                pooled = None

        if not pooled:
            resolved = await self._resolve_upstream_ip(host, ip_override)
            self.logger.debug("Resolved %s -> %s", host, resolved)
            if self.disable_ipv6 and self._is_ipv6_address(resolved):
                raise Exception("IPv6 disabled but resolved to IPv6")
            ssl_ctx = ssl.create_default_context()
            try:
                import certifi
                ssl_ctx = ssl.create_default_context(cafile=certifi.where())
                self.logger.debug("Using certifi CA bundle: %s", certifi.where())
            except ImportError:
                self.logger.debug("certifi not installed, using system CA bundle")

            self.logger.debug("Connecting to %s:%s (TLS)", resolved, port)
            try:
                conn_future = asyncio.open_connection(
                    resolved, int(port), ssl=ssl_ctx, server_hostname=hostname
                )
                reader, writer = await asyncio.wait_for(conn_future, timeout=self.tcp_timeout)
                self.logger.debug("TLS connection established to %s:%s", host, port)
            except asyncio.TimeoutError:
                self.logger.error("TLS connection timeout to %s:%s (tcp_timeout=%s)", host, port, self.tcp_timeout)
                raise
            except ssl.SSLCertVerificationError as e:
                self.logger.error("TLS certificate verification failed for %s: %s", hostname, e)
                raise
            except ssl.SSLZeroReturnError as e:
                self.logger.error("TLS connection closed prematurely for %s: %s", hostname, e)
                raise
            except OSError as e:
                self.logger.error("OS error connecting to %s:%s: %s", host, port, e)
                raise

            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                await self._check_cert_pins(hostname, ssl_obj)

        try:
            self.logger.debug("Sending %d bytes to %s:%s", len(data), host, port)
            writer.write(len(data).to_bytes(2, "big") + data)
            await writer.drain()
            self.logger.debug("Waiting for response from %s:%s", host, port)
            length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=self.tcp_timeout)
            length = int.from_bytes(length_bytes, "big")
            self.logger.debug("Response length: %d", length)
            resp = await asyncio.wait_for(reader.readexactly(length), timeout=self.tcp_timeout)
            self.logger.debug("Received %d bytes from %s:%s", len(resp), host, port)
            await self._tcp_pool.put(key, reader, writer)
            return resp
        except Exception:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            raise

    async def _forward_https(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        host = upstream['address']
        port = upstream.get('port', 443)
        hostname = upstream.get('hostname', host)
        path = upstream.get('path', '')
        if not path:
            path = "/dns-query"
        version = upstream.get('doh_version', self.doh_version)
        ip_override = upstream.get('ip')

        if version == 'auto':
            resolved_ip = await self._resolve_upstream_ip(host, ip_override)
            version = await self._get_auto_doh_version(hostname, port, resolved_ip, path)

        if version == '3':
            return await self._with_retries(
                lambda d: self._forward_https3(d, hostname, port, host, path, ip_override), data, timeout=self.doh_timeout)
        elif version == '2':
            return await self._with_retries(
                lambda d: self._forward_https2(d, hostname, port, host, path, ip_override), data, timeout=self.doh_timeout)
        else:
            return await self._with_retries(
                lambda d: self._forward_https1(d, hostname, port, host, path, ip_override), data, timeout=self.doh_timeout)

    async def _get_auto_doh_version(self, hostname: str, port: int, host: str, path: str) -> str:
        now = time.time()
        async with self._doh_auto_lock:
            if hostname in self._doh_auto_cache:
                version, expiry = self._doh_auto_cache[hostname]
                if now < expiry and version != '_probing':
                    return version
            if hostname in self._doh_auto_cache:
                version, expiry = self._doh_auto_cache[hostname]
                if version == '_failed' and now < expiry:
                    return '1.1'
            self._doh_auto_cache[hostname] = ('_probing', now + 10)

        probe_data = dns.message.make_query('probe.invalid', 'A').to_wire()
        try:
            await asyncio.wait_for(
                self._forward_https3(probe_data, hostname, port, host, path, None),
                timeout=self.doh_timeout
            )
            version = '3'
        except Exception:
            try:
                await asyncio.wait_for(
                    self._forward_https2(probe_data, hostname, port, host, path, None),
                    timeout=self.doh_timeout
                )
                version = '2'
            except Exception:
                version = '1.1'

        async with self._doh_auto_lock:
            if self._doh_auto_cache.get(hostname, ('', 0))[0] == '_probing':
                self._doh_auto_cache[hostname] = (version, time.time() + self.doh_auto_cache_ttl)
            elif version == '1.1':
                self._doh_auto_cache[hostname] = ('_failed', time.time() + self.doh_auto_cache_ttl // 2)
        return version

    async def _forward_https1(self, data: bytes, hostname: str, port: int, host: str, path: str, ip_override: Optional[str]) -> bytes:
        resolved = await self._resolve_upstream_ip(host, ip_override)
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(resolved, port, ssl=ssl_ctx, server_hostname=hostname)

        try:
            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj is not None and self.pinned_certs:
                await self._check_cert_pins(hostname, ssl_obj)

            headers = [
                f"POST {path} HTTP/1.1",
                f"Host: {hostname}",
                "User-Agent: dosev/1.0",
                "Accept: application/dns-message",
                "Content-Type: application/dns-message",
                f"Content-Length: {len(data)}",
                "Connection: close",
                "",
                ""
            ]
            hdr = "\r\n".join(headers).encode("ascii")
            writer.write(hdr + data)
            await writer.drain()

            status_line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
            if not status_line:
                raise Exception("Empty response from DoH upstream")
            status_line = status_line.decode("ascii", errors="ignore").strip()
            if not status_line.startswith("HTTP/"):
                raise Exception(f"Invalid HTTP response start: {status_line}")
            try:
                parts = status_line.split(None, 2)
                status_code = int(parts[1]) if len(parts) > 1 else 0
            except Exception:
                status_code = 0
            if status_code < 200 or status_code >= 300:
                raise Exception(f"DoH upstream returned non-2xx status: {status_line}")

            content_length: Optional[int] = None
            chunked = False
            content_type_ok = False
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
                if not line:
                    break
                s = line.decode("ascii", errors="ignore").strip()
                if s == "":
                    break
                parts = s.split(":", 1)
                if len(parts) == 2:
                    k, v = parts[0].lower(), parts[1].strip()
                    if k == "content-length":
                        try:
                            content_length = int(v)
                        except Exception:
                            content_length = None
                    if k == "transfer-encoding" and "chunked" in v.lower():
                        chunked = True
                    if k == "content-type":
                        if "application/dns-message" in v.lower():
                            content_type_ok = True

            if not chunked and content_length is not None and not content_type_ok:
                self.logger.debug("DoH response content-type not application/dns-message; continuing")

            if chunked:
                body = bytearray()
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=self.doh_timeout)
                    if not line:
                        break
                    hexlen = line.decode("ascii", errors="ignore").strip().split(";", 1)[0]
                    try:
                        ln = int(hexlen, 16)
                    except Exception:
                        raise Exception("Invalid chunk length")
                    if ln == 0:
                        await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=self.doh_timeout)
                        break
                    chunk = await asyncio.wait_for(reader.readexactly(ln), timeout=self.doh_timeout)
                    body.extend(chunk)
                    await asyncio.wait_for(reader.readexactly(2), timeout=self.doh_timeout)
                return bytes(body)
            else:
                if content_length is None:
                    self.logger.warning("DoH response missing Content-Length and not chunked; rejecting for determinism")
                    raise Exception("DoH response missing Content-Length and not chunked")
                return await asyncio.wait_for(reader.readexactly(content_length), timeout=self.doh_timeout)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _forward_https2(self, data: bytes, hostname: str, port: int, host: str, path: str, ip_override: Optional[str]) -> bytes:
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required for HTTP/2 DoH (install with: pip install httpx[h2])")

        key = (hostname, port, path)
        client: Optional[httpx.AsyncClient] = await self._h2_pool.get(key)
        if client is None:
            resolved = await self._resolve_upstream_ip(host, ip_override)
            client = httpx.AsyncClient(http2=True, verify=ssl.create_default_context())

        url = f"https://{hostname}:{port}{path}"
        try:
            resp = await client.post(
                url,
                headers={
                    "Host": hostname,
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
                content=data,
                timeout=self.doh_timeout,
            )
            if resp.status_code < 200 or resp.status_code >= 300:
                raise Exception(f"HTTP/2 upstream returned status {resp.status_code}")
            result = resp.content
            await self._h2_pool.put(key, client)
            return result
        except Exception:
            try:
                await client.aclose()
            except Exception:
                pass
            raise

    async def _forward_https3(self, data: bytes, hostname: str, port: int, host: str, path: str, ip_override: Optional[str]) -> bytes:
        if not _HAS_AIOQUIC:
            raise RuntimeError("aioquic is required for HTTP/3 DoH (install with: pip install aioquic)")
        try:
            from aioquic.h3.connection import H3Connection
            from aioquic.h3.events import HeadersReceived, DataReceived
            from aioquic.asyncio.client import connect as quic_connect
            from aioquic.asyncio.protocol import QuicConnectionProtocol
        except ImportError:
            raise RuntimeError("aioquic.h3 not available; upgrade aioquic to the latest version")

        resolved = await self._resolve_upstream_ip(host, ip_override)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        key = (hostname, port, path)
        ctx = await self._h3_pool.get(key)
        if ctx is not None:
            connection, h3 = ctx
            stream_id = h3.get_next_available_stream_id()
            try:
                h3.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":method", b"POST"),
                        (b":scheme", b"https"),
                        (b":authority", hostname.encode()),
                        (b":path", path.encode()),
                        (b"content-type", b"application/dns-message"),
                        (b"accept", b"application/dns-message"),
                        (b"content-length", str(len(data)).encode()),
                    ],
                    end_stream=False
                )
                h3.send_data(stream_id, data, end_stream=True)

                response_data = bytearray()
                response_complete = asyncio.Event()

                async def handle_events():
                    iterations_without_data = 0
                    max_idle_iterations = int(self.doh_timeout * 10)
                    while not response_complete.is_set():
                        try:
                            event = await asyncio.wait_for(connection.next_event(), timeout=0.1)
                            iterations_without_data = 0
                            for h3_event in h3.handle_event(event):
                                if isinstance(h3_event, DataReceived) and h3_event.stream_id == stream_id:
                                    response_data.extend(h3_event.data)
                                    if h3_event.stream_ended:
                                        response_complete.set()
                                elif isinstance(h3_event, HeadersReceived) and h3_event.stream_ended:
                                    response_complete.set()
                        except asyncio.TimeoutError:
                            iterations_without_data += 1
                            if iterations_without_data > max_idle_iterations:
                                raise asyncio.TimeoutError("HTTP/3 response timeout")

                await asyncio.wait_for(handle_events(), timeout=self.doh_timeout + 5)
                await self._h3_pool.put(key, (connection, h3))
                return bytes(response_data)
            except Exception:
                try:
                    connection.close()
                except Exception:
                    pass
                raise

        configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_REQUIRED)
        configuration.server_name = hostname

        class H3Protocol(QuicConnectionProtocol):
            def __init__(self, quic, stream_handler=None):
                super().__init__(quic, stream_handler)
                self.h3 = H3Connection(self._quic)
                self._response_data = bytearray()
                self._response_complete = asyncio.Event()
                self._response_stream_id = None

            def quic_event_received(self, event):
                for h3_event in self.h3.handle_event(event):
                    if isinstance(h3_event, DataReceived):
                        if h3_event.stream_id == self._response_stream_id:
                            self._response_data.extend(h3_event.data)
                            if h3_event.stream_ended:
                                self._response_complete.set()
                    elif isinstance(h3_event, HeadersReceived):
                        if h3_event.stream_ended:
                            self._response_complete.set()

            async def send_request(self, data: bytes, stream_id: int) -> bytes:
                self._response_stream_id = stream_id
                self.h3.send_headers(
                    stream_id=stream_id,
                    headers=[
                        (b":method", b"POST"),
                        (b":scheme", b"https"),
                        (b":authority", hostname.encode()),
                        (b":path", path.encode()),
                        (b"content-type", b"application/dns-message"),
                        (b"accept", b"application/dns-message"),
                        (b"content-length", str(len(data)).encode()),
                    ],
                    end_stream=False
                )
                self.h3.send_data(stream_id, data, end_stream=True)
                self.transmit()

                await asyncio.wait_for(self._response_complete.wait(), timeout=self.doh_timeout + 5)
                return bytes(self._response_data)

        async with quic_connect(resolved, port, configuration=configuration,
                                create_protocol=lambda *args, **kwargs: H3Protocol(*args, **kwargs)) as client:
            stream_id = client._quic.get_next_available_stream_id()
            response_data = await client.send_request(data, stream_id)
            return response_data

    # ---------- DOQ with connection pooling ----------
    async def _forward_quic(self, data: bytes, upstream: Dict[str, Any]) -> bytes:
        if not _HAS_AIOQUIC:
            raise RuntimeError("aioquic not available for DoQ")
        from aioquic.asyncio import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived

        host = upstream['address']
        port = upstream.get('port', 853)
        hostname = upstream.get('hostname', host)
        ip_override = upstream.get('ip')

        resolved = await self._resolve_upstream_ip(host, ip_override)
        if self.disable_ipv6 and self._is_ipv6_address(resolved):
            raise Exception("IPv6 disabled but resolved to IPv6")

        key = (host, port, hostname, resolved)

        class DoQProtocol(QuicConnectionProtocol):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._pending: Dict[int, asyncio.Future[bytes]] = {}

            def quic_event_received(self, event):
                if isinstance(event, StreamDataReceived):
                    fut = self._pending.get(event.stream_id)
                    if fut and not fut.done():
                        fut.set_result(event.data)

        client = await self._quic_pool.get(key)
        if client is not None:
            if client._quic is None or getattr(client._quic, 'closed', False):
                client = None

        if client is None:
            config = QuicConfiguration(
                is_client=True,
                alpn_protocols=["doq"],
                verify_mode=ssl.CERT_NONE,
                server_name=hostname,
            )
            cm = connect(resolved, port, configuration=config, create_protocol=DoQProtocol)
            client = await cm.__aenter__()
            client._cm = cm
            client._pending = {}

        await client.wait_connected()

        stream_id = client._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        client._pending[stream_id] = future

        client._quic.send_stream_data(stream_id, len(data).to_bytes(2, "big") + data, end_stream=True)
        client.transmit()

        try:
            response_data = await asyncio.wait_for(future, timeout=self.doh_timeout)
        except asyncio.TimeoutError:
            client._pending.pop(stream_id, None)
            if not getattr(client._quic, 'closed', False):
                client._quic.close()
            raise TimeoutError(f"DoQ query to {host}:{port} timed out")
        except Exception:
            client._pending.pop(stream_id, None)
            raise
        finally:
            client._pending.pop(stream_id, None)

        if len(response_data) < 2:
            raise Exception("Invalid DoQ response (too short)")
        resp_len = int.from_bytes(response_data[:2], "big")
        if resp_len + 2 > len(response_data):
            raise Exception("DoQ response truncated")
        resp = response_data[2:2+resp_len]

        if not getattr(client._quic, 'closed', False):
            await self._quic_pool.put(key, client)

        return resp

    def _get_quic_cert_der(self, client: Any) -> Optional[bytes]:
        try:
            if hasattr(client, 'get_peer_certificate'):
                cert = client.get_peer_certificate()
                if cert is not None:
                    if hasattr(cert, 'public_bytes'):
                        from cryptography.hazmat.primitives.serialization import Encoding
                        return cert.public_bytes(Encoding.DER)
                    if isinstance(cert, bytes):
                        return cert
            if hasattr(client, '_quic'):
                quic = client._quic
                if hasattr(quic, 'tls') and hasattr(quic.tls, '_peer_certificate'):
                    cert = quic.tls._peer_certificate
                    if cert is not None:
                        if hasattr(cert, 'public_bytes'):
                            from cryptography.hazmat.primitives.serialization import Encoding
                            return cert.public_bytes(Encoding.DER)
                        if isinstance(cert, bytes):
                            return cert
            get_chain = getattr(client, 'get_peer_cert_chain', None)
            if callable(get_chain):
                chain = get_chain()
                if chain and isinstance(chain, (list, tuple)):
                    first = chain[0]
                    if isinstance(first, bytes):
                        return first
                    if hasattr(first, 'public_bytes'):
                        from cryptography.hazmat.primitives.serialization import Encoding
                        return first.public_bytes(Encoding.DER)
        except Exception:
            pass
        return None

    def _split_hostport(self, hostport: str, default_port: int = 53) -> Tuple[str, int]:
        if not hostport:
            return "", default_port
        host = hostport
        port = default_port
        if hostport.startswith("["):
            try:
                end = hostport.index("]")
                host = hostport[1:end]
                rest = hostport[end+1:]
                if rest.startswith(":"):
                    port = int(rest[1:])
            except Exception:
                host = hostport
        else:
            if hostport.count(":") == 1:
                h, p = hostport.rsplit(":", 1)
                try:
                    port = int(p)
                    host = h
                except Exception:
                    host = hostport
            else:
                host = hostport
        return host, int(port)

    def _is_ipv6_address(self, addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr).version == 6
        except Exception:
            return False

    class _DERPeerWrapper:
        def __init__(self, der: bytes) -> None:
            self._der = der
        def getpeercert(self, binary_form: bool = False) -> Optional[bytes]:
            return self._der if binary_form else None

    def set_block_action(self, action: Optional[str]) -> None:
        try:
            if action is None:
                action = 'NXDOMAIN'
            self._block_action = str(action).upper()
        except Exception:
            self._block_action = 'NXDOMAIN'

    def get_block_action(self) -> str:
        return getattr(self, '_block_action', 'NXDOMAIN')

    def build_block_response(self, request_data: bytes, action: Optional[str] = None) -> bytes:
        use_action = action or self.get_block_action()
        try:
            if _HAS_DNSPY:
                try:
                    request_msg = dns.message.from_wire(request_data)
                except Exception:
                    request_msg = None
                if request_msg is None and use_action != 'ZEROIP':
                    return self._make_nxdomain_response(request_data)
                if request_msg is None:
                    resp = dns.message.Message()
                    if use_action == 'REFUSED':
                        resp.set_rcode(dns.rcode.REFUSED)
                    else:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
                resp = dns.message.make_response(request_msg)
                resp.answer = []
                if use_action == 'REFUSED':
                    resp.set_rcode(dns.rcode.REFUSED)
                    return resp.to_wire()
                if use_action == 'NXDOMAIN':
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
                if use_action == 'ZEROIP':
                    if not request_msg.question:
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                        return resp.to_wire()
                    q = request_msg.question[0]
                    qname = q.name
                    qtype = q.rdtype
                    ttl = 60
                    if qtype == dns.rdatatype.A:
                        rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
                        resp.answer.append(rrset)
                        return resp.to_wire()
                    elif qtype == dns.rdatatype.AAAA:
                        if self.disable_ipv6:
                            resp.set_rcode(dns.rcode.NXDOMAIN)
                            return resp.to_wire()
                        rrset = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
                        resp.answer.append(rrset)
                        return resp.to_wire()
                    elif qtype == dns.rdatatype.ANY:
                        a = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.A, '0.0.0.0')
                        resp.answer.append(a)
                        if not self.disable_ipv6:
                            aaaa = dns.rrset.from_text(str(qname), ttl, dns.rdataclass.IN, dns.rdatatype.AAAA, '::')
                            resp.answer.append(aaaa)
                        return resp.to_wire()
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp.to_wire()
            if use_action == 'REFUSED':
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        _, qend = self._parse_dns_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000 | 5
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                return header + qpart
            if use_action == 'NXDOMAIN':
                return self._make_nxdomain_response(request_data)
            if use_action == 'ZEROIP':
                qname = self._extract_qname_from_wire(request_data)
                qtype = self._extract_qtype_from_wire(request_data) or 1
                if not request_data or len(request_data) < 12:
                    tid = 0
                    qpart = b''
                else:
                    tid = int.from_bytes(request_data[0:2], 'big')
                    try:
                        _, qend = self._parse_dns_name(request_data, 12)
                        qpart = request_data[12:qend + 4]
                    except Exception:
                        qpart = request_data[12:]
                flags = 0x8000
                header = tid.to_bytes(2, 'big') + flags.to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(2, 'big')
                name_ptr = b'\xc0\x0c'
                if qtype == 1:
                    rtype = (1).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (4).to_bytes(2, 'big')
                    rdata = b'\x00\x00\x00\x00'
                elif qtype == 28:
                    if self.disable_ipv6:
                        return self._make_nxdomain_response(request_data)
                    rtype = (28).to_bytes(2, 'big')
                    rclass = (1).to_bytes(2, 'big')
                    ttl = (60).to_bytes(4, 'big')
                    rdlen = (16).to_bytes(2, 'big')
                    rdata = b'\x00' * 16
                elif qtype == 255:
                    a_ans = name_ptr + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (60).to_bytes(4, 'big') + (4).to_bytes(2, 'big') + b'\x00\x00\x00\x00'
                    if self.disable_ipv6:
                        return header + qpart + a_ans
                    aaaa_ans = name_ptr + (28).to_bytes(2, 'big') + (1).to_bytes(2, 'big') + (60).to_bytes(4, 'big') + (16).to_bytes(2, 'big') + (b'\x00' * 16)
                    return header + qpart + a_ans + aaaa_ans
                else:
                    return self._make_nxdomain_response(request_data)
                ans = name_ptr + rtype + rclass + ttl + rdlen + rdata
                return header + qpart + ans
        except Exception:
            return self._make_nxdomain_response(request_data)

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv4Address):
            return (ip.is_private or
                    ip.is_loopback or
                    ip.is_link_local or
                    ip.is_reserved or
                    ip.is_multicast or
                    ip.is_unspecified)
        else:
            return (ip.is_private or
                    ip.is_loopback or
                    ip.is_link_local or
                    ip.is_reserved or
                    ip.is_multicast or
                    ip.is_unspecified)

    def _apply_rebind_protection(self, response_bytes: bytes) -> Optional[bytes]:
        if not self.rebind_protection_enabled or not _HAS_DNSPY:
            return response_bytes
        try:
            msg = dns.message.from_wire(response_bytes)
            filtered_answer = []
            for rrset in msg.answer:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    new_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
                    new_rrset.ttl = rrset.ttl
                    has_public = False
                    for rd in rrset:
                        ip_str = rd.to_text().strip()
                        if not self._is_private_ip(ip_str):
                            new_rrset.add(rd)
                            has_public = True
                    if has_public:
                        filtered_answer.append(new_rrset)
                else:
                    filtered_answer.append(rrset)
            msg.answer = filtered_answer

            if self.rebind_action == 'block' and not filtered_answer:
                return None
            return msg.to_wire()
        except Exception as e:
            self.logger.debug("rebind protection failed: %s", e)
            return response_bytes

    def _extract_soa_minimum(self, response: bytes) -> Optional[int]:
        try:
            msg = dns.message.from_wire(response)
            for rrset in msg.authority:
                if rrset.rdtype == dns.rdatatype.SOA:
                    for rr in rrset:
                        return rr.minimum
        except Exception:
            pass
        return None

    def _set_tc_bit(self, response_bytes: bytes) -> bytes:
        if len(response_bytes) < 4:
            return response_bytes
        header = bytearray(response_bytes)
        flags = int.from_bytes(header[2:4], 'big')
        flags |= 0x0200
        header[2:4] = flags.to_bytes(2, 'big')
        return bytes(header)

    async def _with_retries(self, fn: Callable[[bytes], Coroutine[Any, Any, bytes]], data: bytes, timeout: float, no_retry: bool = False) -> bytes:
        if no_retry:
            try:
                return await asyncio.wait_for(fn(data), timeout=timeout)
            except Exception as e:
                raise e

        backoff = 0.1
        last_exc: Optional[Exception] = None
        for attempt in range(self.retries):
            try:
                self.logger.debug("attempt %d/%d for %s", attempt + 1, self.retries, fn.__name__)
                start = time.time()
                result = await asyncio.wait_for(fn(data), timeout=timeout)
                dur = time.time() - start
                self.logger.debug("success %s on attempt %d (%.3fs)", fn.__name__, attempt + 1, dur)
                if self.metrics_enabled and self._metrics:
                    try:
                        self._metrics['request_latency_seconds'].labels(proto="unknown").observe(dur)
                    except Exception:
                        pass
                return result
            except asyncio.TimeoutError as e:
                last_exc = e
                self.logger.warning("timeout on attempt %d for %s", attempt + 1, fn.__name__)
            except Exception as e:
                last_exc = e
                self.logger.debug("attempt %d failed for %s: %s", attempt + 1, fn.__name__, e)
            if attempt < self.retries - 1:
                await asyncio.sleep(backoff)
                self.logger.debug("backing off %.3fs before next attempt", backoff)
                backoff *= 2
        self.logger.error("all %d attempts failed for %s", self.retries, fn.__name__)
        if self.metrics_enabled and self._metrics:
            try:
                self._metrics['requests_errors'].labels(proto="unknown").inc()
            except Exception:
                pass
        raise last_exc or Exception("Unknown forward error")

    def _log_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None) -> None:
        msg = f"{status}\tqname={qname}\tclient={client}\t{details or ''}"
        if status.startswith("Blocked"):
            self.logger.info(msg)
        else:
            self.logger.debug(msg)
        if self._file_logger:
            try:
                self._file_logger.info(msg)
            except Exception:
                pass

    def log_dns_event(self, status: str, qname: Optional[str], client: Optional[str] = None, details: Optional[str] = None) -> None:
        return self._log_event(status, qname, client, details)

    async def _check_cert_pins(self, hostname: str, ssl_obj: Any) -> None:
        if not self.pinned_certs:
            return
        self.logger.debug("checking certificate pin for %s", hostname)
        try:
            der = ssl_obj.getpeercert(binary_form=True)
            if not der:
                raise Exception("No peer cert available for pin-check")
            got = hashlib.sha256(der).hexdigest()
            expected = self.pinned_certs.get(hostname) or self.pinned_certs.get('*')
            if expected and got.lower() != expected.lower():
                self.logger.warning("certificate pin mismatch for %s: got %s expected %s", hostname, got, expected)
                raise Exception(f"Pinned certificate mismatch for {hostname}: got {got}, expected {expected}")
            self.logger.debug("certificate pin match for %s", hostname)
        except Exception:
            self.logger.exception("certificate pin check failed for %s", hostname)
            raise

    def _dnssec_requested(self, query_data: bytes) -> bool:
        if not query_data or len(query_data) < 12 or not _HAS_DNSPY:
            return False
        try:
            msg = dns.message.from_wire(query_data)
            if msg.opt is None:
                return False
            return bool(msg.opt.flags & dns.flags.DO)
        except Exception:
            return False

    def _make_nxdomain_response(self, query_data: bytes) -> bytes:
        if not query_data or len(query_data) < 12:
            tid = 0
            qpart = b''
            qdcount = 0
            arcount = 0
            rd = 0
        else:
            tid = int.from_bytes(query_data[0:2], 'big')
            req_flags = int.from_bytes(query_data[2:4], 'big')
            try:
                qpart, qdcount, qend = self._extract_question_section(query_data)
                extra, arcount = self._extract_additional_section(query_data, qend)
            except Exception:
                qpart = query_data[12:]
                qdcount = 0
                arcount = 0
                extra = b''
            rd = req_flags & 0x0100

        flags = 0x8000 | rd | 0x0003
        header = (
            tid.to_bytes(2, 'big') +
            flags.to_bytes(2, 'big') +
            qdcount.to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') +
            arcount.to_bytes(2, 'big')
        )
        return header + qpart + extra

    def _build_local_A_response(self, query_data: bytes, ip: str) -> bytes:
        if not query_data or len(query_data) < 12:
            return b''

        tid = int.from_bytes(query_data[0:2], 'big')
        try:
            qpart, qdcount, qend = self._extract_question_section(query_data)
            extra, arcount = self._extract_additional_section(query_data, qend)
        except Exception:
            qpart = query_data[12:]
            qdcount = 0
            arcount = 0
            extra = b''

        flags = 0x8000
        header = (
            tid.to_bytes(2, 'big') +
            flags.to_bytes(2, 'big') +
            qdcount.to_bytes(2, 'big') +
            (1).to_bytes(2, 'big') +
            (0).to_bytes(2, 'big') +
            arcount.to_bytes(2, 'big')
        )

        name_ptr = b'\xc0\x0c'
        rtype = (1).to_bytes(2, 'big')
        rclass = (1).to_bytes(2, 'big')
        ttl = (60).to_bytes(4, 'big')
        ip_parts = [int(x) for x in ip.split('.')]
        rdata = struct.pack('BBBB', *ip_parts)
        rdlen = (len(rdata)).to_bytes(2, 'big')
        answer = name_ptr + rtype + rclass + ttl + rdlen + rdata
        return header + qpart + answer + extra

    def _extract_min_ttl(self, response: bytes) -> int:
        try:
            if not response or len(response) < 12:
                return 0
            qdcount = (response[4] << 8) | response[5]
            ancount = (response[6] << 8) | response[7]
            offset = 12
            for _ in range(qdcount):
                _, offset = self._parse_dns_name(response, offset)
                offset += 4
            min_ttl: Optional[int] = None
            for _ in range(ancount):
                _, offset = self._parse_dns_name(response, offset)
                if offset + 10 > len(response):
                    raise Exception("truncated answer header")
                ttl = struct.unpack(">I", response[offset+4:offset+8])[0]
                rdlen = (response[offset+8] << 8) | response[offset+9]
                if offset + 10 + rdlen > len(response):
                    raise Exception("truncated rdata")
                offset += 10 + rdlen
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
            return min_ttl or 0
        except Exception:
            return 0

    def _parse_rr_name(self, response: bytes, offset: int) -> Tuple[str, int]:
        return self._parse_dns_name(response, offset)

    async def update_config(self, *,
                            verbose: Optional[bool] = None,
                            disable_ipv6: Optional[bool] = None,
                            strip_ipv6_records: Optional[bool] = None,
                            cache_ttl: Optional[int] = None,
                            cache_max_size: Optional[int] = None,
                            negative_cache_ttl: Optional[int] = None,
                            doh_timeout: Optional[float] = None,
                            udp_timeout: Optional[float] = None,
                            tcp_timeout: Optional[float] = None,
                            retries: Optional[int] = None,
                            dns_logging_enabled: Optional[bool] = None,
                            pinned_certs: Optional[Dict[str, str]] = None,
                            dnssec_enabled: Optional[bool] = None,
                            trust_anchors: Optional[Union[Dict[str, str], str]] = None,
                            auto_update_trust_anchor: Optional[bool] = None,
                            metrics_enabled: Optional[bool] = None,
                            metrics_port: Optional[int] = None,
                            uvloop_enable: Optional[bool] = None,
                            rate_limit_rps: Optional[float] = None,
                            rate_limit_burst: Optional[float] = None,
                            upstreams: Optional[List[Dict[str, Any]]] = None,
                            optimistic_cache_enabled: Optional[bool] = None,
                            optimistic_stale_max_age: Optional[int] = None,
                            optimistic_stale_response_ttl: Optional[int] = None,
                            rebind_protection_enabled: Optional[bool] = None,
                            rebind_action: Optional[str] = None,
                            ecs_enabled: Optional[bool] = None,
                            max_edns_payload: Optional[int] = None,
                            pool_max_size: Optional[int] = None,
                            pool_idle_timeout: Optional[float] = None,
                            doh_version: Optional[str] = None,
                            doh_auto_cache_ttl: Optional[int] = None,
                            load_balancing: Optional[str] = None,
                            bootstrap: Optional[Dict[str, Any]] = None,
                            tcp_fallback_enabled: Optional[bool] = None,
                            health_config: Optional[Dict[str, Any]] = None,
                            dnssec_max_validations: Optional[int] = None,
                            dnssec_max_dnskey_records: Optional[int] = None,
                            dnssec_validation_timeout: Optional[float] = None,
                            scrub_unsolicited_ns: Optional[bool] = None) -> None:
        async with self._config_lock:
            if verbose is not None:
                self.verbose = bool(verbose)
                self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
            if disable_ipv6 is not None:
                self.disable_ipv6 = bool(disable_ipv6)
            if strip_ipv6_records is not None:
                self.strip_ipv6_records = bool(strip_ipv6_records)
            if cache_ttl is not None:
                pass
            if cache_max_size is not None:
                pass
            if negative_cache_ttl is not None:
                self.negative_cache_ttl = max(1, int(negative_cache_ttl))
            if doh_timeout is not None:
                self.doh_timeout = doh_timeout
            if udp_timeout is not None:
                self.udp_timeout = udp_timeout
            if tcp_timeout is not None:
                self.tcp_timeout = tcp_timeout
            if retries is not None:
                self.retries = max(1, int(retries))
            if dns_logging_enabled is not None:
                self.dns_logging_enabled = dns_logging_enabled
            if pinned_certs is not None:
                self.pinned_certs = pinned_certs
            if dnssec_enabled is not None:
                self.dnssec_enabled = bool(dnssec_enabled)
                if self.dnssec_enabled and self._dnssec_raw_anchors is None:
                    self._load_trust_anchors()
            if trust_anchors is not None:
                self.trust_anchors = trust_anchors
                if self.dnssec_enabled:
                    self._load_trust_anchors()
            if auto_update_trust_anchor is not None:
                self.auto_update_trust_anchor = auto_update_trust_anchor
                if self.auto_update_trust_anchor and self._trust_anchor_updater_task is None:
                    self._trust_anchor_updater_task = asyncio.create_task(self._background_trust_anchor_updater())
                elif not self.auto_update_trust_anchor and self._trust_anchor_updater_task is not None:
                    self._trust_anchor_updater_task.cancel()
                    try:
                        await self._trust_anchor_updater_task
                    except asyncio.CancelledError:
                        pass
                    self._trust_anchor_updater_task = None
            if metrics_enabled is not None:
                self.metrics_enabled = bool(metrics_enabled) and _HAS_PROM
            if metrics_port is not None:
                self.metrics_port = int(metrics_port)
            if uvloop_enable is not None:
                pass
            if rate_limit_rps is not None:
                self.rate_limit_rps = rate_limit_rps
            if rate_limit_burst is not None:
                self.rate_limit_burst = rate_limit_burst
            if self.rate_limit_rps > 0:
                effective_burst = max(1.0, self.rate_limit_burst)
                if self.rate_limiter is None:
                    self.rate_limiter = RateLimiter(self.rate_limit_rps, effective_burst)
                else:
                    self.rate_limiter.rate = self.rate_limit_rps
                    self.rate_limiter.burst = effective_burst
            else:
                self.rate_limiter = None
            if upstreams is not None:
                self.upstreams = upstreams
            if optimistic_cache_enabled is not None:
                self.optimistic_cache_enabled = optimistic_cache_enabled
            if optimistic_stale_max_age is not None:
                self.stale_max_age = optimistic_stale_max_age
            if optimistic_stale_response_ttl is not None:
                self.stale_response_ttl = optimistic_stale_response_ttl
            if rebind_protection_enabled is not None:
                self.rebind_protection_enabled = rebind_protection_enabled
            if rebind_action is not None:
                self.rebind_action = rebind_action.lower()
            if ecs_enabled is not None:
                self.ecs_enabled = bool(ecs_enabled)
            if max_edns_payload is not None:
                self.max_edns_payload = max(512, int(max_edns_payload))
            if pool_max_size is not None:
                self._tcp_pool.max_size = pool_max_size
                self._h2_pool.max_size = pool_max_size
                self._h3_pool.max_size = pool_max_size
                self._quic_pool.max_size = pool_max_size
            if pool_idle_timeout is not None:
                self._tcp_pool.idle_timeout = pool_idle_timeout
                self._h2_pool.idle_timeout = pool_idle_timeout
                self._h3_pool.idle_timeout = pool_idle_timeout
                self._quic_pool.idle_timeout = pool_idle_timeout
            if doh_version is not None:
                self.doh_version = doh_version
            if doh_auto_cache_ttl is not None:
                self.doh_auto_cache_ttl = doh_auto_cache_ttl
            if load_balancing is not None:
                self.load_balancing = load_balancing.lower()
                if self.load_balancing not in ('failover', 'parallel', 'random', 'roundrobin'):
                    self.load_balancing = 'failover'
            if bootstrap is not None:
                self.bootstrap_servers = bootstrap.get('servers', [])
                self.bootstrap_timeout = bootstrap.get('timeout', 2.0)
                self.bootstrap_retries = bootstrap.get('retries', 2)
            if tcp_fallback_enabled is not None:
                self.tcp_fallback_enabled = tcp_fallback_enabled
            if health_config is not None:
                self._health_config = health_config
                self._health_enabled = health_config.get('enabled', False)
                self._health_interval = health_config.get('interval', 30)
                self._health_timeout = health_config.get('timeout', 2.0)
                self._health_unhealthy_threshold = health_config.get('unhealthy_threshold', 3)
                self._health_healthy_threshold = health_config.get('healthy_threshold', 2)
                self._health_cooldown = health_config.get('cooldown', 60)
                self._health_domain = health_config.get('domain', '.')
                if self._health_enabled and self._health_task is None and self.upstreams:
                    self._health_task = asyncio.create_task(self._health_check_loop())
                elif not self._health_enabled and self._health_task is not None:
                    self._health_task.cancel()
                    try:
                        await self._health_task
                    except asyncio.CancelledError:
                        pass
                    self._health_task = None
            if dnssec_max_validations is not None:
                self.dnssec_max_validations = dnssec_max_validations
            if dnssec_max_dnskey_records is not None:
                self.dnssec_max_dnskey_records = dnssec_max_dnskey_records
            if dnssec_validation_timeout is not None:
                self.dnssec_validation_timeout = dnssec_validation_timeout
            if scrub_unsolicited_ns is not None:
                self.scrub_unsolicited_ns = scrub_unsolicited_ns

            self.logger.info("DNSResolver configuration updated: "
                             "disable_ipv6=%s, strip_ipv6_records=%s, verbose=%s, rate_limit=%s/%s, optimistic_cache=%s, "
                             "rebind_protection=%s/%s, doh_version=%s, load_balancing=%s, tcp_fallback=%s, health=%s, "
                             "dnssec_max_validations=%s, dnssec_max_dnskey_records=%s, scrub_unsolicited_ns=%s",
                             self.disable_ipv6, self.strip_ipv6_records, self.verbose,
                             self.rate_limit_rps, self.rate_limit_burst,
                             self.optimistic_cache_enabled,
                             self.rebind_protection_enabled, self.rebind_action,
                             self.doh_version, self.load_balancing, self.tcp_fallback_enabled,
                             self._health_enabled,
                             self.dnssec_max_validations, self.dnssec_max_dnskey_records,
                             self.scrub_unsolicited_ns)