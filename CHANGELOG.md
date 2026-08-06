# [1.9.2] – 2026-08-06

## Fixed

- **HTTP/2 DoH SNI mismatch causing certificate verification failure** – When an upstream used a fixed IP (`ip` option) with the HTTPS protocol, the HTTP/2 client (`httpx`) constructed the URL using the IP address, causing the SNI (Server Name Indication) to be the IP instead of the domain name. This resulted in certificate verification errors (`IP address mismatch`) and prevented the upstream from being marked healthy. The fix explicitly sets `server_hostname` to the domain name in the HTTP/2 transport, ensuring the correct SNI is sent while still connecting to the fixed IP.
