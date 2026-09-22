# jev-proxy

**A policy firewall for MCP tool calls.** Put it between an MCP client and any
stdio MCP server. Every `tools/call` is allowed, denied, or held for a one-time
human approval before it reaches the server.

[![Tests](https://github.com/gbesse/jev-proxy/actions/workflows/test.yml/badge.svg)](https://github.com/gbesse/jev-proxy/actions/workflows/test.yml) ![MIT](https://img.shields.io/badge/license-MIT-blue) ![Node](https://img.shields.io/badge/node-22%2B-green) ![Public alpha](https://img.shields.io/badge/status-public_alpha-orange)

```text
MCP client  ──stdio──>  jev-proxy  ──stdio──>  MCP server
                          │
                          ├─ ordered policy rules
                          ├─ one-time approvals
                          └─ append-only JSONL audit
```

Jev Proxy forwards the rest of the MCP conversation unchanged. It does not
need to know the upstream server's schemas and it never sends policy data to a
model or hosted service.

The stdio framing and `tools/call` shape are unchanged across MCP
`2025-11-25` and `2026-07-28`, so the proxy supports both protocol eras without
terminating or rewriting their lifecycle messages.

## Quick start

Requires Node.js 22 or newer.

```bash
npm install
npm run build

# See the decision without running a server.
node ./dist/cli.js check \
  --config examples/jev.config.yaml \
  --tool shell.exec \
  --arguments '{"command":"git status"}'

# Put the proxy in front of a stdio MCP server.
node ./dist/cli.js run --config examples/jev.config.yaml -- \
  npx -y @modelcontextprotocol/server-filesystem "$PWD"
```

In an MCP client configuration, replace the server command with the proxy and
move the original command after `--`:

```json
{
  "mcpServers": {
    "guarded-filesystem": {
      "command": "/absolute/path/to/jev-proxy/dist/cli.js",
      "args": [
        "run",
        "--config", "/absolute/path/to/jev.config.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/absolute/path/to/workspace"
      ]
    }
  }
}
```

## Policies

Rules are evaluated from top to bottom; the first match wins. Use a deny-by-
default policy so a newly exposed tool cannot silently bypass review.

```yaml
version: 1
default: deny

rules:
  - id: deny-destructive-shell
    action: deny
    match:
      tools: [shell.exec]
      arguments:
        command:
          matches: '(^|[;&|]\s*)(rm\s+-[^\n]*r|sudo\b)'

  - id: review-shell
    action: require_approval
    match:
      tools: [shell.exec]

  - id: allow-reads
    action: allow
    match:
      tools: [read_text_file, list_directory, search_files]
```

Tool names support `*` and `?` globs. Argument paths use dot notation. A value
may be matched directly or with `equals`, `notEquals`, `matches`, `contains`,
`startsWith`, `endsWith`, `oneOf`, and `exists`.

`review` is accepted as a shorter alias for `require_approval`.

## Approval flow

When a call needs approval, the client receives MCP error `-32002` containing
an audit ID. Approve that exact call from another terminal:

```bash
jev-proxy approve 8b2d... --config /absolute/path/to/jev.config.yaml
```

Retrying the identical call consumes the approval. A different tool or any
changed argument gets a different SHA-256 fingerprint and remains blocked.

## Audit

Every tool call produces one JSON object in `.jev/audit.jsonl`. Arguments are
excluded by default. If `audit.includeArguments` is enabled, common secret
fields (`token`, `password`, `api_key`, cookies, and authorization) are always
redacted; add more paths with `audit.redact`.

```yaml
audit:
  path: .jev/audit.jsonl
  includeArguments: true
  redact:
    - arguments.customer.email
```

The log records the policy decision, matching rule, fingerprint, approval
status, and stable audit ID. Approval grants and consumptions are recorded in
a separate append-only JSONL file.

## Security model and limits

- The proxy controls MCP `tools/call` requests. It does not sandbox the
  upstream process or inspect resources, prompts, sampling, or arbitrary HTTP.
- The upstream server runs with the proxy process's operating-system
  permissions. Combine Jev Proxy with normal filesystem and container
  isolation.
- MCP JSON-RPC batches containing `tools/call` are rejected so batching cannot
  bypass policy.
- Policy regexes run locally using JavaScript regular expressions. Treat policy
  files as trusted configuration.
- Approval storage is designed for one proxy operator on one machine. Shared
  multi-user deployments need a transactional approval backend.

## Development

```bash
npm run release:check
```

Configuration is validated before the upstream process starts. Unknown match
fields, malformed condition operators, and invalid regular expressions fail
closed with an error instead of being interpreted as a broader policy.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development contract and
[SECURITY.md](SECURITY.md) for the supported security boundary and reporting
instructions.
