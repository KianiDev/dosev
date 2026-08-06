# [1.9.1] – 2026-08-06

## Fixed

- **DoQ (DNS over QUIC) `StreamDataReceived` attribute error** – The `DoQProtocol` inside `_forward_quic()` incorrectly referenced `event.stream_ended`; the aioquic event uses `event.end_stream`. This caused `AttributeError` exceptions on every DoQ response, preventing successful DoQ queries. The attribute has been corrected to `event.end_stream`, restoring full DoQ functionality.

## Changed

- **Health check protocol detection** – Added recognition for the `doq` protocol alias (now treated as `quic`) in `_try_upstream()` to prevent "Unsupported upstream protocol: doq" warnings when health checks target DoQ upstreams configured with protocol `doq`.

## Security

- No security fixes in this release.
