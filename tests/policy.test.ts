import assert from "node:assert/strict";
import { test } from "node:test";
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
