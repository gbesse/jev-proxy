# Contributing

Jev Proxy is a security boundary, so changes should stay small, explicit and
covered by a regression test.

## Local validation

Requires Node.js 22 or newer.

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run release:check
```

The release check type-checks the source and tests, runs the complete test
suite, builds the distributable files and inspects the npm tarball.

## Pull requests

- Add a focused test for policy matching, approval consumption, audit output,
  configuration parsing or stdio behavior changes.
- Keep deny-by-default examples deny-by-default.
- Treat malformed configuration as an error; do not silently widen a rule.
- Do not add real credentials or live service calls to tests.
- Update the README when behavior or the security boundary changes.

Use security reporting rather than a public issue for a suspected bypass; see
[SECURITY.md](SECURITY.md).
