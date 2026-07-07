# v1.2.0 (2026-07-07)

## Features

- **Auto‑generate default configuration**: On first run, dosev creates a default `dosev.conf` in the OS‑specific user config directory:
  - Windows: `%APPDATA%\dosev\dosev.conf`
  - macOS: `~/Library/Application Support/dosev/dosev.conf`
  - Linux: `~/.config/dosev/dosev.conf`
- The server exits with instructions to edit the config and restart.

## Improvements

- `--config` now defaults to the OS‑specific config path.
- Improved user experience for new pip installations.
