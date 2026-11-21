#!/usr/bin/env python3
"""
mcp-audit - static security audit for Model Context Protocol (MCP) client configs.

Finds risky MCP server setups in Claude Desktop, Cursor, VS Code, Windsurf and
similar JSON configs: plaintext secrets, unpinned packages, remote code fetched
at launch, over-broad filesystem access, insecure transports, and prompt-injection
payloads hidden in tool descriptions.

Stdlib only. Read-only: it never starts a server or sends anything anywhere.

Usage:
  python mcp_audit.py                       # auto-discover known config locations
  python mcp_audit.py path/to/mcp.json ...  # audit specific files
  python mcp_audit.py --tools tools.json    # also audit a tools/list dump
  python mcp_audit.py --json report.json    # machine-readable output
  python mcp_audit.py --fail-on high        # CI gate (exit 1)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, asdict
from pathlib import Path

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    file: str
    server: str
    rule: str
    severity: str
    message: str
    fix: str


# ---------------------------------------------------------------- discovery
def known_config_paths() -> list[Path]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    cands = [
        appdata / "Claude" / "claude_desktop_config.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".config" / "Claude" / "claude_desktop_config.json",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / ".claude.json",
        Path.cwd() / ".cursor" / "mcp.json",
        Path.cwd() / ".vscode" / "mcp.json",
        Path.cwd() / ".mcp.json",
    ]
    return [p for p in cands if p.is_file()]


def extract_servers(cfg: dict) -> dict:
    """Support the common shapes: {mcpServers:{}}, {servers:{}} (VS Code), nested projects."""
    servers: dict = {}
    if isinstance(cfg.get("mcpServers"), dict):
        servers.update(cfg["mcpServers"])
    if isinstance(cfg.get("servers"), dict):
        servers.update(cfg["servers"])
    if isinstance(cfg.get("projects"), dict):  # ~/.claude.json style
        for proj, pc in cfg["projects"].items():
            if isinstance(pc, dict) and isinstance(pc.get("mcpServers"), dict):
                for k, v in pc["mcpServers"].items():
                    servers[f"{k} ({Path(proj).name})"] = v
    return servers


# ---------------------------------------------------------------- rules
SECRET_KEY = re.compile(r"(api[_-]?key|token|secret|passw(or)?d|private[_-]?key|credential|auth)", re.I)
SECRET_VAL = [
    (re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$"), "OpenAI/Anthropic-style API key"),
    (re.compile(r"^gh[pousr]_[A-Za-z0-9]{30,}$"), "GitHub token"),
    (re.compile(r"^github_pat_[A-Za-z0-9_]{40,}$"), "GitHub fine-grained token"),
    (re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"), "Slack token"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "AWS access key ID"),
    (re.compile(r"^AIza[0-9A-Za-z_\-]{35}$"), "Google API key"),
]
ENV_REF = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_:]*\}?$|^\$\{input:|^\$\{env:")

RUNNERS = {"npx", "npx.cmd", "bunx", "pnpx", "uvx", "pipx", "dlx"}
PINNED = re.compile(r"@\d+\.\d+\.\d+|==\d|@sha256:|:[0-9a-f]{7,}$|@v?\d+\.\d+")
BROAD_PATHS = {"/", "~", "c:\\", "c:/", "/home", "/users", "/etc", "/root", "%userprofile%", "$home"}
SHELL_BINS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
REMOTE_FETCH = re.compile(r"(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(ba|z)?sh|\b(curl|wget)\b.*https?://", re.I)

INJECTION = [
    (re.compile(r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|all|system)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?)\b", re.I), "instruction override"),
    (re.compile(r"<\s*(important|system|instructions?|secret)\s*>", re.I), "fake priority tag"),
    (re.compile(r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show)\b[^.\n]{0,20}\buser\b", re.I), "hide-from-user instruction"),
    (re.compile(r"(~/\.ssh|id_rsa|\.env\b|\.aws/credentials|mcp\.json|claude_desktop_config)", re.I), "reference to secret files"),
    (re.compile(r"\b(before|first)\b[^.\n]{0,40}\b(read|call|use|run)\b[^.\n]{0,40}\b(file|tool|command)\b", re.I), "cross-tool directive"),
    (re.compile(r"\b(send|upload|post|forward|include)\b[^.\n]{0,50}\b(contents?|keys?|tokens?|credentials|conversation|history)\b", re.I), "exfiltration directive"),
]


def has_hidden_chars(s: str) -> str | None:
    for ch in s:
        o = ord(ch)
        if 0xE0000 <= o <= 0xE007F:
            return f"Unicode tag character U+{o:05X}"
        if ch in "\u200b\u200c\u200d\u2060\ufeff\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069":
            return f"invisible/bidi character U+{o:04X}"
        if unicodedata.category(ch) == "Co":
            return f"private-use character U+{o:04X}"
    return None


def audit_server(file: str, name: str, srv: dict) -> list[Finding]:
    out: list[Finding] = []

    def add(rule, sev, msg, fix):
        out.append(Finding(file, name, rule, sev, msg, fix))

    if not isinstance(srv, dict):
        add("malformed", "low", "Server entry is not an object", "Fix the config structure")
        return out

    if srv.get("disabled") is True:
        add("disabled", "info", "Server is disabled", "Remove unused servers entirely")

    cmd = str(srv.get("command", "") or "")
    args = [str(a) for a in (srv.get("args") or []) if a is not None]
    url = str(srv.get("url", "") or srv.get("serverUrl", "") or "")
    env = srv.get("env") or {}
    headers = srv.get("headers") or {}
    base = Path(cmd.replace("\\", "/")).name.lower()

    # --- secrets in env / headers / args
    for src, kv in (("env", env), ("headers", headers)):
        if not isinstance(kv, dict):
            continue
        for k, v in kv.items():
            v = str(v)
            if not v or ENV_REF.search(v):
                continue
            kind = next((label for rx, label in SECRET_VAL if rx.match(v)), None)
            if kind or (SECRET_KEY.search(k) and len(v) >= 12):
                add("plaintext-secret", "high",
                    f"{src}.{k} holds a plaintext {'' if not kind else kind + ' / '}secret",
                    "Reference an environment variable or OS keychain instead of inlining the value")
    for a in args:
        if any(rx.match(a) for rx, _ in SECRET_VAL) or re.search(r"(--?(api[-_]?key|token|password|secret))=\S{8,}", a, re.I):
            add("secret-in-args", "high", "A secret is passed on the command line (visible in process lists)",
                "Pass secrets through env vars that reference a secret store")

    # --- supply chain: unpinned packages via runners
    if base in RUNNERS:
        pkgs = [a for a in args if not a.startswith("-")]
        if pkgs:
            pkg = pkgs[0]
            if not PINNED.search(pkg):
                add("unpinned-package", "medium", f"'{base} {pkg}' runs the latest version on every launch",
                    f"Pin an exact version, e.g. {pkg}@1.2.3, and review updates before bumping")
        if "-y" in args or "--yes" in args:
            add("auto-install", "low", f"'{base}' auto-confirms package install (-y)",
                "Install and review the package once, then run the pinned local copy")

    # --- docker
    if base in {"docker", "docker.exe", "podman"}:
        joined = " ".join(args)
        if "--privileged" in joined:
            add("docker-privileged", "critical", "Container runs --privileged", "Drop --privileged; grant only needed capabilities")
        if re.search(r"(-v|--volume)\s+(/|~|\$HOME|%USERPROFILE%|C:\\)[^:]*:", joined) or re.search(r"/var/run/docker\.sock", joined):
            add("docker-broad-mount", "high", "Container mounts the host root/home or the Docker socket",
                "Mount only the specific project directory, read-only where possible")
        if re.search(r"--network[= ]host", joined):
            add("docker-host-net", "medium", "Container uses host networking", "Use the default bridge network")
        img = next((a for a in args if re.match(r"^[\w./-]+(:[\w.-]+)?(@sha256:[0-9a-f]+)?$", a) and "/" in a), None)
        if img and "@sha256:" not in img and (":" not in img or img.endswith(":latest")):
            add("docker-unpinned", "medium", f"Image '{img}' is not pinned", "Pin by digest: image@sha256:...")

    # --- shells and remote fetch
    if base in SHELL_BINS:
        add("shell-launcher", "medium", f"Server is launched through a shell ({base})",
            "Invoke the server binary directly with explicit args")
    full = " ".join([cmd] + args)
    if REMOTE_FETCH.search(full):
        add("remote-code-at-launch", "critical", "Launch command downloads and/or executes remote code",
            "Vendor a reviewed, pinned copy of the server instead")

    # --- filesystem breadth
    for a in args:
        norm = a.strip().strip('"').rstrip("/\\").lower() or "/"
        if norm in BROAD_PATHS or re.fullmatch(r"[a-z]:", norm) or norm in {str(Path.home()).lower()}:
            add("broad-filesystem", "high", f"Filesystem access granted to '{a}'",
                "Scope access to a single project directory")

    # --- transport
    if url:
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
            add("insecure-transport", "high", f"Remote MCP server over plain HTTP: {url}", "Use https://")
        if re.search(r"[?&](api[_-]?key|token|key|secret)=", url, re.I):
            add("secret-in-url", "high", "Credential embedded in server URL (ends up in logs)",
                "Send credentials in a header referencing a secret store")
        if url.startswith("https://") or url.startswith("http://"):
            add("remote-server", "info", f"Remote server: {url}", "Confirm the operator is trusted and allowlisted")

    # --- auto-approval
    for key in ("alwaysAllow", "autoApprove", "trust"):
        val = srv.get(key)
        if val is True or (isinstance(val, list) and val):
            add("auto-approve", "high" if val is True or "*" in (val or []) else "medium",
                f"'{key}' skips human approval for {'all tools' if val is True or '*' in (val or []) else ', '.join(map(str, val))}",
                "Require approval for any tool that writes, sends or executes")

    return out


def audit_tools(file: str, tools: list) -> list[Finding]:
    """Audit a tools/list dump: [{name, description, inputSchema}, ...]."""
    out: list[Finding] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "?"))
        text = json.dumps(t, ensure_ascii=False)
        hidden = has_hidden_chars(text)
        if hidden:
            out.append(Finding(file, name, "hidden-characters", "critical",
                               f"Tool metadata contains {hidden}", "Reject the server; hidden text targets the model, not you"))
        norm = unicodedata.normalize("NFKC", text)
        for rx, label in INJECTION:
            if rx.search(norm):
                out.append(Finding(file, name, "tool-poisoning", "high",
                                   f"Tool description contains a {label}", "Review the full description before approving this server"))
        desc = str(t.get("description", ""))
        if len(desc) > 1500:
            out.append(Finding(file, name, "long-description", "low",
                               f"Unusually long description ({len(desc)} chars)", "Long descriptions are a common hiding place for instructions"))
    return out


# ---------------------------------------------------------------- main
def load_json(p: Path):
    txt = p.read_text(encoding="utf-8", errors="replace")
    txt = re.sub(r"^\s*//.*$", "", txt, flags=re.M)  # tolerate // comments (VS Code)
    return json.loads(txt)


def run(paths: list[Path], tool_dumps: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        try:
            cfg = load_json(p)
        except Exception as e:  # noqa: BLE001
            findings.append(Finding(str(p), "-", "parse-error", "low", f"Cannot parse: {e}", "Fix the JSON"))
            continue
        servers = extract_servers(cfg) if isinstance(cfg, dict) else {}
        if not servers:
            findings.append(Finding(str(p), "-", "no-servers", "info", "No MCP servers found", "-"))
        for name, srv in servers.items():
            findings += audit_server(str(p), name, srv)
    for p in tool_dumps:
        try:
            data = load_json(p)
        except Exception as e:  # noqa: BLE001
            findings.append(Finding(str(p), "-", "parse-error", "low", f"Cannot parse: {e}", "Fix the JSON"))
            continue
        tools = data.get("tools", data) if isinstance(data, dict) else data
        findings += audit_tools(str(p), tools if isinstance(tools, list) else [])
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Static security audit for MCP client configs.")
    ap.add_argument("configs", nargs="*", type=Path, help="MCP config files (default: auto-discover)")
    ap.add_argument("--tools", nargs="*", type=Path, default=[], help="tools/list JSON dumps to scan for poisoning")
    ap.add_argument("--json", metavar="FILE", help="write findings as JSON")
    ap.add_argument("--min", default="low", choices=SEV, help="hide findings below this severity")
    ap.add_argument("--fail-on", default="high", choices=SEV, help="exit 1 at or above this severity")
    a = ap.parse_args(argv)

    paths = a.configs or known_config_paths()
    if not paths and not a.tools:
        print("No MCP configs found in known locations. Pass a path explicitly.")
        return 0

    findings = [f for f in run(paths, a.tools) if SEV[f.severity] >= SEV[a.min]]
    findings.sort(key=lambda f: (-SEV[f.severity], f.file, f.server))

    tty = sys.stdout.isatty()
    col = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[37m"}
    print(f"mcp-audit · {len(paths)} config(s), {len(a.tools)} tool dump(s)\n")
    for f in findings:
        tag = f"[{f.severity.upper():8}]"
        print(f"{col[f.severity] + tag + chr(27) + '[0m' if tty else tag} {f.server}: {f.message}\n{'':11}fix: {f.fix}   ({f.rule})")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV}
    print("\nSummary: " + "  ".join(f"{s}={n}" for s, n in counts.items() if n))

    if a.json:
        Path(a.json).write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    worst = max((SEV[f.severity] for f in findings), default=0)
    return 1 if worst >= SEV[a.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
