# [1.9.3] – 2026-08-06

## Fixed

- **HTTP/2 DoH SNI mismatch causing certificate verification failure** – When an upstream used a fixed IP (`ip` option) with the HTTPS protocol, the HTTP/2 client (`httpx`) constructed the URL using the IP address, causing the SNI (Server Name Indication) to be the IP instead of the domain name. This resulted in certificate verification errors (`IP address mismatch`) and prevented the upstream from being marked healthy. The fix uses httpx's `sni_hostname` request extension to explicitly set the correct SNI while still connecting to the fixed IP.
