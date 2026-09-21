import { createHash, randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import { appendAudit, redactArguments } from "./audit.js";
import { consumeApproval } from "./approval.js";
import { evaluatePolicy } from "./policy.js";
import type { AuditRecord, JsonRpcRequest, JsonValue, ProxyConfig, ToolCall } from "./types.js";

export interface ProxyOptions {
  config: ProxyConfig;
  auditPath: string;
  approvalsPath: string;
  input?: Readable;
  output?: Writable;
  error?: Writable;
  spawnProcess?: (command: string, args: string[]) => ChildProcessWithoutNullStreams;
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${stableStringify(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function fingerprint(call: ToolCall): string {
  return createHash("sha256").update(stableStringify(call)).digest("hex");
}

function parseToolCall(message: JsonRpcRequest): ToolCall | null {
  if (message.method !== "tools/call" || !message.params || typeof message.params !== "object") return null;
  const params = message.params as Record<string, unknown>;
  if (typeof params.name !== "string") return null;
  const args = params.arguments;
  if (args !== undefined && (!args || typeof args !== "object" || Array.isArray(args))) return null;
  return { name: params.name, arguments: (args ?? {}) as Record<string, JsonValue> };
}

function errorResponse(message: JsonRpcRequest, code: number, text: string, data?: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id: message.id ?? null, error: { code, message: text, data } });
}

export async function inspectToolCall(
  config: ProxyConfig,
  call: ToolCall,
  auditPath: string,
  approvalsPath: string,
): Promise<{ record: AuditRecord; forward: boolean }> {
  const policy = evaluatePolicy(config, call);
  const callFingerprint = fingerprint(call);
  const approvalId = policy.decision === "require_approval" ? await consumeApproval(approvalsPath, callFingerprint) : null;
  const approved = approvalId !== null;
  const decision = approved ? "allow" : policy.decision;
  const record: AuditRecord = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    type: "tool_call",
    tool: call.name,
    decision,
    configuredDecision: policy.decision,
    ruleId: policy.ruleId,
    reason: approved ? `approved by ${approvalId}` : policy.reason,
    fingerprint: callFingerprint,
    approved,
    argumentKeys: Object.keys(call.arguments).sort(),
  };
  if (config.audit?.includeArguments) record.arguments = redactArguments(call.arguments, config.audit.redact);
  await appendAudit(auditPath, record);
  return { record, forward: decision === "allow" };
}

export async function runProxy(command: string, args: string[], options: ProxyOptions): Promise<number> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const error = options.error ?? process.stderr;
  const spawnProcess = options.spawnProcess ?? ((cmd, cmdArgs) => spawn(cmd, cmdArgs, { stdio: ["pipe", "pipe", "pipe"] }));
  const child = spawnProcess(command, args);
  const childExit = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) error.write(`jev-proxy: upstream exited with signal ${signal}\n`);
      resolve(code ?? 1);
    });
  });
  child.stderr.pipe(error);

  const upstreamLines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  upstreamLines.on("line", (line) => output.write(`${line}\n`));

  const clientLines = createInterface({ input, crlfDelay: Infinity });
  for await (const line of clientLines) {
    if (!line.trim()) continue;
    let message: unknown;
    try {
      message = JSON.parse(line) as unknown;
    } catch {
      output.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`);
      continue;
    }
    if (Array.isArray(message)) {
      const containsToolCall = message.some((item) => item && typeof item === "object" && (item as JsonRpcRequest).method === "tools/call");
      if (containsToolCall) {
        output.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Batched tools/call requests are not supported by jev-proxy" } })}\n`);
      } else {
        child.stdin.write(`${line}\n`);
      }
      continue;
    }
    if (!message || typeof message !== "object") {
      child.stdin.write(`${line}\n`);
      continue;
    }
    const request = message as JsonRpcRequest;
    const call = parseToolCall(request);
    if (request.method === "tools/call" && !call) {
      output.write(`${errorResponse(request, -32602, "Invalid tools/call parameters")}\n`);
      continue;
    }
    if (!call) {
      child.stdin.write(`${line}\n`);
      continue;
    }
    const result = await inspectToolCall(options.config, call, options.auditPath, options.approvalsPath);
    if (result.forward) {
      child.stdin.write(`${line}\n`);
    } else if (result.record.decision === "deny") {
      output.write(`${errorResponse(request, -32001, "Tool call denied by jev-proxy", { jev: result.record })}\n`);
    } else {
      output.write(
        `${errorResponse(request, -32002, "Tool call requires approval", {
          jev: result.record,
          next: `jev-proxy approve ${result.record.id}`,
        })}\n`,
      );
    }
  }
  child.stdin.end();
  return childExit;
}
