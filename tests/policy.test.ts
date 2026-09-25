import assert from "node:assert/strict";
import { test } from "node:test";
import { validateConfig } from "../src/config.js";
import { evaluatePolicy } from "../src/policy.js";
import type { ProxyConfig } from "../src/types.js";

const config: ProxyConfig = {
  version: 1,
  default: "deny",
  rules: [
    {
      id: "deny-rm",
      action: "deny",
      match: { tools: ["shell.*"], arguments: { command: { matches: "(^|\\s)rm\\s" } } },
    },
    { id: "review-shell", action: "review", match: { tools: ["shell.*"] } },
    { id: "allow-read", action: "allow", match: { tools: ["read_*"] } },
  ],
};

test("uses first-match-wins and evaluates argument regexes", () => {
  const result = evaluatePolicy(config, { name: "shell.exec", arguments: { command: "rm -rf ./tmp" } });
  assert.deepEqual(result, { decision: "deny", ruleId: "deny-rm", reason: "matched rule deny-rm" });
});

test("normalizes review to require_approval", () => {
  const result = evaluatePolicy(config, { name: "shell.exec", arguments: { command: "git status" } });
  assert.equal(result.decision, "require_approval");
  assert.equal(result.ruleId, "review-shell");
});

test("supports tool globs and a deny-by-default fallback", () => {
  assert.equal(evaluatePolicy(config, { name: "read_file", arguments: {} }).decision, "allow");
  assert.equal(evaluatePolicy(config, { name: "unknown", arguments: {} }).decision, "deny");
});

test("supports nested argument paths", () => {
  const nested: ProxyConfig = {
    version: 1,
    default: "deny",
    rules: [{ id: "prod", action: "allow", match: { arguments: { "target.environment": { equals: "production" } } } }],
  };
  assert.equal(evaluatePolicy(nested, { name: "deploy", arguments: { target: { environment: "production" } } }).decision, "allow");
});

test("matches JSON payload types without treating them as schemas", () => {
  const typed: ProxyConfig = {
    version: 1,
    default: "deny",
    rules: [
      {
        id: "typed-write",
        action: "allow",
        match: {
          tools: ["write_record"],
          arguments: {
            "record.id": { isType: "string" },
            "record.tags": { isType: "array" },
            dryRun: { isType: "boolean" },
          },
        },
      },
    ],
  };
  assert.equal(
    evaluatePolicy(typed, { name: "write_record", arguments: { record: { id: "42", tags: ["reviewed"] }, dryRun: true } }).decision,
    "allow",
  );
  assert.equal(
    evaluatePolicy(typed, { name: "write_record", arguments: { record: { id: 42, tags: ["reviewed"] }, dryRun: true } }).decision,
    "deny",
  );
});

test("rejects malformed policy operators before the proxy starts", () => {
  assert.throws(
    () =>
      validateConfig({
        version: 1,
        default: "deny",
        rules: [{ id: "unsafe", action: "allow", match: { arguments: { command: { matches: [] } } } }],
      }),
    /matches must be a string/,
  );
  assert.throws(
    () =>
      validateConfig({
        version: 1,
        default: "deny",
        rules: [{ id: "unsafe", action: "allow", match: { arguments: { command: { oneOf: "read" } } } }],
      }),
    /oneOf must be an array/,
  );
  assert.throws(
    () =>
      validateConfig({
        version: 1,
        default: "deny",
        rules: [{ id: "unsafe", action: "allow", match: { arguments: { payload: { isType: "integer" } } } }],
      }),
    /isType must be/,
  );
  assert.throws(
    () =>
      validateConfig({
        version: 1,
        default: "deny",
        rules: [{ id: "unsafe", action: "allow", match: { tool: ["read_file"] } }],
      }),
    /unknown keys: tool/,
  );
});

test("rejects invalid regular expressions and malformed audit settings", () => {
  assert.throws(
    () =>
      validateConfig({
        version: 1,
        default: "deny",
        rules: [{ id: "bad-regex", action: "deny", match: { arguments: { command: { matches: "[" } } } }],
      }),
    /valid regular expression/,
  );
  assert.throws(
    () => validateConfig({ version: 1, default: "deny", rules: [], audit: { includeArguments: "yes" } }),
    /includeArguments must be a boolean/,
  );
  assert.throws(
    () => validateConfig({ version: 1, default: "deny", rules: [], audit: { includeArgument: true } }),
    /audit has unknown keys: includeArgument/,
  );
});

test("allows literal object matches and well-formed conditions", () => {
  const validated = validateConfig({
    version: 1,
    default: "deny",
    audit: { includeArguments: true, redact: ["arguments.customer.email"] },
    approvals: { path: ".jev/approvals.jsonl" },
    rules: [
      { id: "literal", action: "allow", match: { arguments: { metadata: { role: "reader" } } } },
      { id: "condition", action: "review", match: { arguments: { command: { matches: "^git ", exists: true } } } },
    ],
  });
  assert.equal(validated.rules.length, 2);
});
