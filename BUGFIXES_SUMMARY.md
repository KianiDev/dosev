# [1.7.1] – 2026-07-08

## Fixed

- **HTTP/3 client** – fixed `create_protocol` lambda to accept extra arguments passed by `aioquic` (e.g., `stream_handler`). This removes harmless error logs during HTTP/3 auto‑detection.
