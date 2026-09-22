#!/usr/bin/env node
import { basename } from "node:path";
import { readJsonLines } from "./audit.js";
import { grantApproval } from "./approval.js";
import { loadConfig, resolveConfigPath } from "./config.js";
import { evaluatePolicy } from "./policy.js";
import { fingerprint, runProxy } from "./proxy.js";
import type { AuditRecord, JsonValue, ToolCall } from "./types.js";

const VERSION = "0.1.1";

function usage(): string {
  return `jev-proxy ${VERSION} — policy firewall for MCP tools

Usage:
  jev-proxy run --config <file> [--audit <file>] [--approvals <file>] -- <command> [args...]
  jev-proxy check --config <file> --tool <name> [--arguments <json>]
  jev-proxy approve <audit-id> --config <file> [--audit <file>] [--approvals <file>]

Aliases:
  "review" is accepted as an alias for "require_approval" in policy files.
`;
}

interface ParsedArgs {
  positionals: string[];
  options: Map<string, string>;
  command: string[];
}

function parseArgs(args: string[]): ParsedArgs {
  const separator = args.indexOf("--");
  const head = separator === -1 ? args : args.slice(0, separator);
  const command = separator === -1 ? [] : args.slice(separator + 1);
  const positionals: string[] = [];
  const options = new Map<string, string>();
  for (let index = 0; index < head.length; index += 1) {
    const item = head[index]!;
    if (!item.startsWith("--")) {
      positionals.push(item);
      continue;
    }
    const value = head[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${item}`);
    options.set(item.slice(2), value);
    index += 1;
  }
  return { positionals, options, command };
}

function required(options: Map<string, string>, key: string): string {
  const value = options.get(key);
  if (!value) throw new Error(`--${key} is required`);
  return value;
}

function paths(configPath: string, config: Awaited<ReturnType<typeof loadConfig>>["config"], options: Map<string, string>) {
  return {
    auditPath: resolveConfigPath(configPath, options.get("audit") ?? config.audit?.path, ".jev/audit.jsonl"),
    approvalsPath: resolveConfigPath(configPath, options.get("approvals") ?? config.approvals?.path, ".jev/approvals.jsonl"),
  };
}

async function main(): Promise<number> {
  const raw = process.argv.slice(2);
  if (raw.length === 0 || raw.includes("--help") || raw.includes("-h")) {
    process.stdout.write(usage());
    return 0;
  }
  if (raw.includes("--version") || raw.includes("-v")) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const subcommand = raw[0];
  const parsed = parseArgs(raw.slice(1));
  const loaded = await loadConfig(required(parsed.options, "config"));
  const resolved = paths(loaded.configPath, loaded.config, parsed.options);

  if (subcommand === "run") {
    if (parsed.command.length === 0) throw new Error("an upstream command is required after --");
    return runProxy(parsed.command[0]!, parsed.command.slice(1), { config: loaded.config, ...resolved });
  }

  if (subcommand === "check") {
    const tool = required(parsed.options, "tool");
    const rawArguments = parsed.options.get("arguments") ?? "{}";
    const args = JSON.parse(rawArguments) as unknown;
    if (!args || typeof args !== "object" || Array.isArray(args)) throw new Error("--arguments must be a JSON object");
    const call = { name: tool, arguments: args as Record<string, JsonValue> };
    process.stdout.write(`${JSON.stringify({ ...evaluatePolicy(loaded.config, call), fingerprint: fingerprint(call) }, null, 2)}\n`);
    return 0;
  }

  if (subcommand === "approve") {
    const auditId = parsed.positionals[0];
    if (!auditId) throw new Error("an audit id is required");
    const records = (await readJsonLines(resolved.auditPath)) as AuditRecord[];
    const record = records.find((candidate) => candidate.id === auditId && candidate.type === "tool_call");
    if (!record) throw new Error(`audit record not found: ${auditId}`);
    if (record.configuredDecision !== "require_approval") throw new Error(`audit record ${auditId} does not require approval`);
    await grantApproval(resolved.approvalsPath, record.fingerprint, auditId);
    process.stdout.write(`Approved one retry of ${record.tool} (${auditId}).\n`);
    return 0;
  }

  throw new Error(`unknown command: ${subcommand}`);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${basename(process.argv[1] ?? "jev-proxy")}: ${message}\n`);
    process.exitCode = 1;
  },
);
