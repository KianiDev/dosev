# Bug Fixes Summary

## Issues Fixed

### 1. **Memory Leak in TCP/TLS Connection Handlers** (HIGH)
**Files:** `resolver.py` (`_forward_tcp` and `_forward_tls`)
**Issue:** When `writer.write()` or `writer.drain()` fails, the exception handler wasn't closing the writer, causing connection leaks.
**Fix:** Added comprehensive error handling with `writer.close()` and `await writer.wait_closed()` in all exception paths.

```python
except Exception:
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    raise
```

### 2. **Connection Pool Reuse After Close** (MEDIUM)
**Files:** `resolver.py` (`_forward_tcp` and `_forward_tls`)
**Issue:** Pooled connections that were closed by remote servers weren't validated before reuse, causing potential data corruption.
**Fix:** Added validation to check `writer.is_closing()` before using pooled connections. Invalid connections are discarded and new ones are created.

```python
if pooled:
    reader, writer = pooled
    if writer.is_closing():
        try:
            writer.close()
        except Exception:
            pass
        pooled = None

if not pooled:
    # Create new connection
```

### 3. **Race Condition in HTTP/3 DoH Version Negotiation** (MEDIUM)
**Files:** `resolver.py` (`_get_auto_doh_version`)
**Issue:** TOCTOU race where multiple concurrent requests could trigger redundant DoH version probes.
**Fix:** Added probe marker to cache entry to prevent duplicate probes:

```python
# Mark as probing to prevent duplicate probes
self._doh_auto_cache[hostname] = ('_probing', now + 60)

# Later: only update if still marked as probing
if self._doh_auto_cache.get(hostname, ('', 0))[0] == '_probing':
    self._doh_auto_cache[hostname] = (version, now + self.doh_auto_cache_ttl)
```

### 4. **HTTP/3 Infinite Loop Risk** (MEDIUM)
**Files:** `resolver.py` (`_forward_https3` - both pooled and new connection cases)
**Issue:** Event handling loop could hang indefinitely if no response events were received.
**Fix:** Added iteration counter with timeout detection:

```python
async def handle_events():
    iterations_without_data = 0
    max_idle_iterations = int(self.doh_timeout * 10)
    while not response_complete.is_set():
        try:
            event = await asyncio.wait_for(connection.next_event(), timeout=0.1)
            iterations_without_data = 0  # Reset on event
            # process event...
        except asyncio.TimeoutError:
            iterations_without_data += 1
            if iterations_without_data > max_idle_iterations:
                raise asyncio.TimeoutError("HTTP/3 response timeout")

await asyncio.wait_for(handle_events(), timeout=self.doh_timeout + 5)
```

### 5. **Config Update Race Condition** (HIGH)
**Files:** `resolver.py` (`forward_dns_query`)
**Issue:** Race between reading `self.upstreams` in queries and updating it via `update_config`. Could cause TOCTOU issues and list iteration problems.
**Fix:** Protected upstream list read with `_config_lock` and created a snapshot copy:

```python
async with self._config_lock:
    upstream_list = list(self.upstreams) if self.upstreams else [
        {'address': self.upstream_dns, 'protocol': self.protocol, 'hostname': self.upstream_dns}
    ]
```

### 6. **Blocklist Reload Race Conditions** (HIGH)
**Files:** `server.py` (`periodic_reload` and `reload_resolver`)
**Issue:** Blocklists were updated without synchronization while DNS queries read them, causing TOCTOU races and potential set/dict mutation during iteration.
**Fix:** Protected blocklist updates with `_config_lock`:

```python
async with resolver._config_lock:
    resolver.set_blocklist(domains)
    resolver.set_hosts_map(hosts_map)
```

### 7. **UDP Socket Resource Cleanup** (LOW)
**Files:** `resolver.py` (`_udp_query_a_or_aaaa`)
**Issue:** Socket closure not guaranteed if exceptions occur before finally block.
**Fix:** Enhanced exception handling in finally block:

```python
finally:
    try:
        sock.close()
    except Exception:
        pass
```

## Summary of Changes

| Issue | Severity | Type | Status |
|-------|----------|------|--------|
| TCP/TLS memory leak | HIGH | Memory Leak | ✅ Fixed |
| Connection pool reuse | MEDIUM | Data Corruption | ✅ Fixed |
| DoH version cache race | MEDIUM | Race Condition | ✅ Fixed |
| HTTP/3 infinite loop | MEDIUM | Deadlock Risk | ✅ Fixed |
| Config update race | HIGH | Race Condition | ✅ Fixed |
| Blocklist reload race | HIGH | Race Condition | ✅ Fixed |
| Socket cleanup | LOW | Resource Leak | ✅ Enhanced |

## Testing Recommendations

1. **Memory leak testing:** Run with sustained DNS query load for 1+ hours and monitor memory usage
2. **Concurrency testing:** Test with 1000+ concurrent queries while performing config updates
3. **Connection pooling:** Verify connections are properly cleaned up when remote servers close them
4. **HTTP/3 timeout:** Test DoH/3 with non-responsive servers to verify timeout handling
5. **Blocklist updates:** Perform blocklist reloads while under high query load

## Files Modified

- `e:\Code\dosev\dosev\resolver.py` - Core fixes
- `e:\Code\dosev\dosev\server.py` - Server-level synchronization
