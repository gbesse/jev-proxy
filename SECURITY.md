# Security policy

## Supported versions

The latest tagged release and the current `main` branch receive security
fixes. This project is a public alpha; pin an exact version and review its
policy and operating-system permissions before production use.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. If
that option is unavailable, contact the repository owner privately through the
contact method on their GitHub profile. Do not include credentials, customer
data or an active exploit against a third-party system.

Useful reports include the affected version, a minimal policy and tool call,
the observed result, the expected result and any practical bypass impact. You
should receive an acknowledgement within seven days.

## Security boundary

Jev Proxy authorizes MCP `tools/call` messages on a stdio connection. It does
not sandbox the upstream process, inspect resources or prompts, authenticate
multiple operators, or make an unsafe tool safe. The upstream server keeps the
operating-system permissions of the proxy process.

Approval storage is intended for one proxy operator on one machine. Do not
share an approvals file between mutually untrusted users or proxy processes.
Audit logs can contain tool names, argument keys and, when explicitly enabled,
redacted arguments; protect and retain them according to your own data policy.
