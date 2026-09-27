import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { grantApproval } from "../src/approval.js";
import { fingerprint, inspectToolCall } from "../src/proxy.js";
import type { ProxyConfig, ToolCall } from "../src/types.js";

const config: ProxyConfig = {
  version: 1,
  default: "deny",
  audit: { includeArguments: true },
  rules: [{ id: "review-write", action: "require_approval", match: { tools: ["write_file"] } }],
};

test("review approvals are scoped to one exact call and consumed once", async () => {
  const directory = await mkdtemp(join(tmpdir(), "jev-proxy-"));
  const audit = join(directory, "audit.jsonl");
  const approvals = join(directory, "approvals.jsonl");
  const call: ToolCall = { name: "write_file", arguments: { path: "a.txt", content: "hello" } };

  const first = await inspectToolCall(config, call, audit, approvals);
  assert.equal(first.forward, false);
  assert.equal(first.record.decision, "require_approval");

  await grantApproval(approvals, fingerprint(call), first.record.id);
  const second = await inspectToolCall(config, call, audit, approvals);
  assert.equal(second.forward, true);
  assert.equal(second.record.approved, true);

  const third = await inspectToolCall(config, call, audit, approvals);
  assert.equal(third.forward, false);
  assert.equal(third.record.approved, false);
});

test("audit output redacts common secret fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "jev-proxy-"));
  const audit = join(directory, "audit.jsonl");
  await inspectToolCall(
    { ...config, default: "allow", rules: [] },
    { name: "http", arguments: { token: "secret", nested: { password: "hunter2", keep: "ok" } } },
    audit,
    join(directory, "approvals.jsonl"),
  );
  const record = JSON.parse(await readFile(audit, "utf8")) as { arguments: Record<string, unknown> };
  assert.deepEqual(record.arguments, { token: "[REDACTED]", nested: { password: "[REDACTED]", keep: "ok" } });
});

test("fingerprints do not depend on object key order", () => {
  const left = { name: "tool", arguments: { a: 1, b: 2 } } satisfies ToolCall;
  const right = { name: "tool", arguments: { b: 2, a: 1 } } satisfies ToolCall;
  assert.equal(fingerprint(left), fingerprint(right));
});

test("fingerprints bind nested payload values and their JSON types", () => {
  const approved = { name: "write_record", arguments: { record: { id: "42", enabled: true } } } satisfies ToolCall;
  const changedValue = { name: "write_record", arguments: { record: { id: "43", enabled: true } } } satisfies ToolCall;
  const changedType = { name: "write_record", arguments: { record: { id: 42, enabled: true } } } satisfies ToolCall;
  assert.notEqual(fingerprint(approved), fingerprint(changedValue));
  assert.notEqual(fingerprint(approved), fingerprint(changedType));
});
