# agentmon desktop

Tauri 2 desktop client for [agentmon](../../README.md). It reads the local
SQLite database (read-only) and renders the audit views: overview, egress
destinations, file read audit, captured request classification, findings and
per-agent profiles.

```bash
pnpm install
pnpm tauri dev     # development (starts Vite on :1420)
pnpm tauri build   # bundle a standalone app
```

The Rust side exposes only read queries plus a small set of write operations
(ignoring/restoring a finding, running the static scan).
