import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PassThrough } from "node:stream";
import { runProxy } from "../src/proxy.js";
import type { ProxyConfig } from "../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const upstream = join(here, "fixtures", "echo-mcp.mjs");

function collect(stream: PassThrough): Promise<string> {
  let value = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk: string) => {
    value += chunk;
  });
  return new Promise((resolve) => stream.on("end", () => resolve(value)));
}

test("stdio proxy forwards allowed calls and answers blocked calls itself", async () => {
  const directory = await mkdtemp(join(tmpdir(), "jev-proxy-integration-"));
  const input = new PassThrough();
  const output = new PassThrough();
  const error = new PassThrough();
  const config: ProxyConfig = {
    version: 1,
    default: "deny",
    rules: [{ id: "read", action: "allow", match: { tools: ["read_file"] } }],
  };

  const running = runProxy(process.execPath, [upstream], {
    config,
    auditPath: join(directory, "audit.jsonl"),
    approvalsPath: join(directory, "approvals.jsonl"),
    input,
    output,
    error,
    spawnProcess: (command, args) => spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] }),
  });
  const outputDone = collect(output);
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "delete_file", arguments: { path: "x" } } })}\n`);
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: { path: "x" } } })}\n`);
  input.end();

  assert.equal(await running, 0);
  output.end();
  const messages = (await outputDone).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(messages.length, 2);
  const denied = messages.find((message) => message.id === 1) as { error: { code: number } };
  const allowed = messages.find((message) => message.id === 2) as { result: unknown };
  assert.equal(denied.error.code, -32001);
  assert.ok(allowed.result);
  assert.equal((await readFile(join(directory, "audit.jsonl"), "utf8")).trim().split("\n").length, 2);
});
