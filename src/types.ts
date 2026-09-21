export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type Decision = "allow" | "deny" | "require_approval";

export interface ArgumentCondition {
  equals?: JsonValue;
  notEquals?: JsonValue;
  matches?: string;
  contains?: string;
  startsWith?: string;
  endsWith?: string;
  oneOf?: JsonValue[];
  exists?: boolean;
}

export interface PolicyMatch {
  tools?: string[];
  arguments?: Record<string, ArgumentCondition | JsonValue>;
}

export interface PolicyRule {
  id: string;
  description?: string;
  action: Decision | "review";
  reason?: string;
  match?: PolicyMatch;
}

export interface ProxyConfig {
  version: 1;
  default: Decision | "review";
  rules: PolicyRule[];
  audit?: {
    path?: string;
    includeArguments?: boolean;
    redact?: string[];
  };
  approvals?: {
    path?: string;
  };
}

export interface ToolCall {
  name: string;
  arguments: Record<string, JsonValue>;
}

export interface PolicyResult {
  decision: Decision;
  ruleId: string | null;
  reason: string;
}

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface AuditRecord {
  id: string;
  timestamp: string;
  type: "tool_call";
  tool: string;
  decision: Decision;
  configuredDecision: Decision;
  ruleId: string | null;
  reason: string;
  fingerprint: string;
  approved: boolean;
  argumentKeys: string[];
  arguments?: Record<string, JsonValue>;
}
