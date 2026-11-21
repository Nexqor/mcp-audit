# Changelog

All notable changes to this project are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.1.0] - 2026-11-21

### Added
- Auto-discovery of MCP configs for Claude Desktop (Windows / macOS / Linux), `~/.claude.json`, Cursor, VS Code, Windsurf and project `.mcp.json`.
- Config rules: `plaintext-secret`, `secret-in-args`, `secret-in-url`, `unpinned-package`, `auto-install`, `broad-filesystem`, `shell-launcher`, `remote-code-at-launch`, `insecure-transport`, `auto-approve`, `docker-privileged`, `docker-broad-mount`, `docker-host-net`, `docker-unpinned`, `remote-server`.
- Tool dump rules: `hidden-characters`, `tool-poisoning` (6 patterns), `long-description`.
- `--json` report, `--min` filter and `--fail-on` CI gate.
- Example risky config and poisoned tool dump.
