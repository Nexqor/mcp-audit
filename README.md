<p align="center">
  <img src="https://raw.githubusercontent.com/Nexqor/Nexqor/main/banner.png" alt="Nexqor" width="100%">
</p>

<h1 align="center">mcp-audit 🔍</h1>

<p align="center">
  <b>Static security audit for MCP (Model Context Protocol) configs.</b><br/>
  Find plaintext secrets, unpinned packages, remote code at launch, over-broad filesystem access,<br/>
  insecure transports, auto-approve flags and <b>tool poisoning</b> before your agent does.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-c41237?style=for-the-badge&logo=python&logoColor=white" alt="python"/>
  <img src="https://img.shields.io/badge/dependencies-0-c41237?style=for-the-badge" alt="deps"/>
  <img src="https://img.shields.io/badge/mode-read--only-000000?style=for-the-badge" alt="read-only"/>
  <a href="https://nexqor.github.io/playbook.html#mcp"><img src="https://img.shields.io/badge/why-playbook%2009-000000?style=for-the-badge" alt="playbook"/></a>
</p>

---

## Why

Every MCP server you add is code that runs with your permissions and text that your model trusts. In 2026, MCP became one of the fastest-growing attack surfaces for AI agents: poisoned tool descriptions, configs auto-loaded from cloned repos, and servers fetched unpinned from npm on every launch.

`mcp-audit` reads your configs **without starting anything** and tells you what to fix.

## Quick start

```bash
git clone https://github.com/Nexqor/mcp-audit && cd mcp-audit
python mcp_audit.py                                  # auto-discovers known config locations
python mcp_audit.py example_risky_mcp.json          # audit a specific file
python mcp_audit.py --tools example_poisoned_tools.json   # scan a tools/list dump for poisoning
```

Auto-discovery checks: Claude Desktop (Windows / macOS / Linux), `~/.claude.json`, Cursor (`~/.cursor/mcp.json`, `.cursor/mcp.json`), VS Code (`.vscode/mcp.json`), Windsurf, and `.mcp.json` in the current project.

## What it checks

| Rule | Severity | Finding |
|------|----------|---------|
| `remote-code-at-launch` | 🔴 critical | `curl … \| sh` or remote downloads in the launch command |
| `docker-privileged` | 🔴 critical | MCP container runs `--privileged` |
| `hidden-characters` | 🔴 critical | Unicode tag / zero-width / bidi characters in tool metadata |
| `plaintext-secret` | 🟠 high | API keys and tokens inlined in `env` or `headers` |
| `secret-in-args` / `secret-in-url` | 🟠 high | Credentials on the command line or in the server URL |
| `broad-filesystem` | 🟠 high | Filesystem server pointed at `/`, `~`, `C:\` or your home dir |
| `docker-broad-mount` | 🟠 high | Host root, home or Docker socket mounted into the container |
| `insecure-transport` | 🟠 high | Remote MCP over plain `http://` |
| `auto-approve` | 🟠 high | `alwaysAllow` / `autoApprove` skips human approval |
| `tool-poisoning` | 🟠 high | Override phrases, fake `<IMPORTANT>` tags, secret-file references, exfiltration directives in tool descriptions |
| `unpinned-package` | 🟡 medium | `npx` / `uvx` / `bunx` package without an exact version |
| `docker-unpinned` | 🟡 medium | Image without digest or with `:latest` |
| `shell-launcher` | 🟡 medium | Server launched through `bash` / `cmd` / `powershell` |
| `auto-install`, `long-description` | 🔵 low | `-y` auto-install, suspiciously long tool descriptions |

## Example

Running against [`example_risky_mcp.json`](example_risky_mcp.json) flags, among others:

```text
[CRITICAL] helper: Launch command downloads and/or executes remote code
[CRITICAL] sandbox: Container runs --privileged
[HIGH    ] filesystem: Filesystem access granted to '/'
[HIGH    ] github: env.GITHUB_PERSONAL_ACCESS_TOKEN holds a plaintext secret
[HIGH    ] remote-notes: Remote MCP server over plain HTTP
[HIGH    ] remote-notes: Credential embedded in server URL
[HIGH    ] remote-notes: 'alwaysAllow' skips human approval for all tools
[MEDIUM  ] filesystem: 'npx @modelcontextprotocol/server-filesystem' runs the latest version on every launch
```

…while `safe-weather` (pinned `uvx` package, secret referenced from env) passes clean.

And [`example_poisoned_tools.json`](example_poisoned_tools.json) shows the classic tool-poisoning pattern: an innocent `add_numbers` tool whose description tells the model to read `~/.ssh/id_rsa` and hide it from the user.

## CI usage

```yaml
- name: Audit MCP configs
  run: python mcp_audit.py .vscode/mcp.json .cursor/mcp.json --fail-on high --json mcp-audit.json
```

## Hardening checklist

1. Pin every MCP server to an exact version or image digest.
2. Keep secrets in env vars backed by a secret store, never inline.
3. Scope filesystem servers to one project directory.
4. Never auto-approve tools that write, send or execute.
5. Disable auto-loading of workspace MCP configs from untrusted repos.
6. Re-audit tool descriptions on every server update (rug pulls).

Full background: [Playbook 09 · MCP Tool Poisoning](https://github.com/Nexqor/ai-attack-playbook/blob/main/09-mcp-tool-poisoning.md) · [AI Agent Security Checklist](https://nexqor.github.io/checklist.html)

## Limitations

Static analysis of configs and tool dumps only. It does not connect to servers, verify package integrity, or catch a payload that is paraphrased beyond its heuristics. Treat a clean result as "no known red flags", not "safe".

---

MIT License · Part of the [Nexqor](https://github.com/Nexqor) AI security toolkit · [@whyNexqor](https://x.com/whyNexqor)
