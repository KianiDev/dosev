# [1.9.5] – 2026-08-07

## Fixed

- **Transaction ID mismatch in coalesced DNS responses** – When multiple identical queries were coalesced (single‑flight deduplication), the followers received the response with the leader's original transaction ID instead of their own. This caused clients to reject the response with "answer does not represent the original request". The fix stamps the coalesced response with the follower's query ID before returning it, preserving the existing retry-on-failure logic.
