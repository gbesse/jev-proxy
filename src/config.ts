import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parse } from "yaml";
import type { Decision, JsonValue, ProxyConfig } from "./types.js";

const ACTIONS = new Set(["allow", "deny", "require_approval", "review"]);
const CONDITION_KEYS = new Set(["equals", "notEquals", "matches", "contains", "startsWith", "endsWith", "oneOf", "exists"]);
const MATCH_KEYS = new Set(["tools", "arguments"]);
const AUDIT_KEYS = new Set(["path", "includeArguments", "redact"]);
const APPROVAL_KEYS = new Set(["path"]);

function assertAction(value: unknown, where: string): asserts value is Decision | "review" {
  if (typeof value !== "string" || !ACTIONS.has(value)) {
    throw new Error(`${where} must be allow, deny, or require_approval`);
  }
}

export function normalizeDecision(value: Decision | "review"): Decision {
  return value === "review" ? "require_approval" : value;
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  return Boolean(value && typeof value === "object" && Object.values(value).every(isJsonValue));
}

function validateCondition(value: unknown, where: string): void {
  if (!isJsonValue(value)) throw new Error(`${where} must be a JSON value or condition`);
  if (!value || typeof value !== "object" || Array.isArray(value)) return;

  const condition = value as Record<string, unknown>;
  const conditionKeys = Object.keys(condition).filter((key) => CONDITION_KEYS.has(key));
  if (conditionKeys.length === 0) return;

  const unknown = Object.keys(condition).filter((key) => !CONDITION_KEYS.has(key));
  if (unknown.length > 0) {
    throw new Error(`${where} mixes condition operators with unknown keys: ${unknown.join(", ")}`);
  }
  for (const key of ["matches", "contains", "startsWith", "endsWith"] as const) {
    if (condition[key] !== undefined && typeof condition[key] !== "string") {
      throw new Error(`${where}.${key} must be a string`);
    }
  }
  if (condition.exists !== undefined && typeof condition.exists !== "boolean") {
    throw new Error(`${where}.exists must be a boolean`);
  }
  if (condition.oneOf !== undefined && (!Array.isArray(condition.oneOf) || !condition.oneOf.every(isJsonValue))) {
    throw new Error(`${where}.oneOf must be an array of JSON values`);
  }

  // Validate expressions while loading so a malformed allow rule cannot fail
  // only after the proxy has started handling requests.
  if (typeof condition.matches === "string") {
    try {
      new RegExp(condition.matches);
    } catch {
      throw new Error(`${where}.matches must be a valid regular expression`);
    }
  }
}

function validateOptionalString(value: unknown, where: string): void {
  if (value !== undefined && typeof value !== "string") throw new Error(`${where} must be a string`);
}

export function validateConfig(input: unknown): ProxyConfig {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("configuration must be an object");
  }
  const value = input as Record<string, unknown>;
  if (value.version !== 1) throw new Error("configuration version must be 1");
  assertAction(value.default, "default");
  if (!Array.isArray(value.rules)) throw new Error("rules must be an array");

  const ids = new Set<string>();
  for (const [index, raw] of value.rules.entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error(`rules[${index}] must be an object`);
    }
    const rule = raw as Record<string, unknown>;
    if (typeof rule.id !== "string" || rule.id.length === 0) {
      throw new Error(`rules[${index}].id must be a non-empty string`);
    }
    if (ids.has(rule.id)) throw new Error(`duplicate rule id: ${rule.id}`);
    ids.add(rule.id);
    assertAction(rule.action, `rules[${index}].action`);
    validateOptionalString(rule.description, `rules[${index}].description`);
    validateOptionalString(rule.reason, `rules[${index}].reason`);
    if (rule.match !== undefined && (!rule.match || typeof rule.match !== "object" || Array.isArray(rule.match))) {
      throw new Error(`rules[${index}].match must be an object`);
    }
    const match = rule.match as Record<string, unknown> | undefined;
    const unknownMatchKeys = match ? Object.keys(match).filter((key) => !MATCH_KEYS.has(key)) : [];
    if (unknownMatchKeys.length > 0) {
      throw new Error(`rules[${index}].match has unknown keys: ${unknownMatchKeys.join(", ")}`);
    }
    if (match?.tools !== undefined && (!Array.isArray(match.tools) || !match.tools.every((tool) => typeof tool === "string"))) {
      throw new Error(`rules[${index}].match.tools must be an array of strings`);
    }
    if (match?.arguments !== undefined && (!match.arguments || typeof match.arguments !== "object" || Array.isArray(match.arguments))) {
      throw new Error(`rules[${index}].match.arguments must be an object`);
    }
    if (match?.arguments && typeof match.arguments === "object" && !Array.isArray(match.arguments)) {
      for (const [path, condition] of Object.entries(match.arguments)) {
        if (path.length === 0) throw new Error(`rules[${index}].match.arguments paths must be non-empty`);
        validateCondition(condition, `rules[${index}].match.arguments.${path}`);
      }
    }
  }

  if (value.audit !== undefined && (!value.audit || typeof value.audit !== "object" || Array.isArray(value.audit))) {
    throw new Error("audit must be an object");
  }
  if (value.audit && typeof value.audit === "object" && !Array.isArray(value.audit)) {
    const audit = value.audit as Record<string, unknown>;
    const unknownAuditKeys = Object.keys(audit).filter((key) => !AUDIT_KEYS.has(key));
    if (unknownAuditKeys.length > 0) throw new Error(`audit has unknown keys: ${unknownAuditKeys.join(", ")}`);
    validateOptionalString(audit.path, "audit.path");
    if (audit.includeArguments !== undefined && typeof audit.includeArguments !== "boolean") {
      throw new Error("audit.includeArguments must be a boolean");
    }
    if (audit.redact !== undefined && (!Array.isArray(audit.redact) || !audit.redact.every((path) => typeof path === "string"))) {
      throw new Error("audit.redact must be an array of strings");
    }
  }
  if (value.approvals !== undefined && (!value.approvals || typeof value.approvals !== "object" || Array.isArray(value.approvals))) {
    throw new Error("approvals must be an object");
  }
  if (value.approvals && typeof value.approvals === "object" && !Array.isArray(value.approvals)) {
    const approvals = value.approvals as Record<string, unknown>;
    const unknownApprovalKeys = Object.keys(approvals).filter((key) => !APPROVAL_KEYS.has(key));
    if (unknownApprovalKeys.length > 0) throw new Error(`approvals has unknown keys: ${unknownApprovalKeys.join(", ")}`);
    validateOptionalString(approvals.path, "approvals.path");
  }
  return input as ProxyConfig;
}

export async function loadConfig(path: string): Promise<{ config: ProxyConfig; configPath: string }> {
  const configPath = resolve(path);
  const text = await readFile(configPath, "utf8");
  const input = configPath.endsWith(".json") ? JSON.parse(text) : parse(text);
  return { config: validateConfig(input), configPath };
}

export function resolveConfigPath(configPath: string, candidate: string | undefined, fallback: string): string {
  return resolve(dirname(configPath), candidate ?? fallback);
}
