import { isDeepStrictEqual } from "node:util";
import { normalizeDecision } from "./config.js";
import type { ArgumentCondition, JsonValue, PolicyResult, ProxyConfig, ToolCall } from "./types.js";

const CONDITION_KEYS = new Set(["equals", "notEquals", "matches", "contains", "startsWith", "endsWith", "oneOf", "exists", "isType"]);

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

function getPath(object: Record<string, JsonValue>, path: string): JsonValue | undefined {
  let current: JsonValue | undefined = object;
  for (const part of path.split(".")) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = current[part];
  }
  return current;
}

function isCondition(value: ArgumentCondition | JsonValue): value is ArgumentCondition {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).some((key) => CONDITION_KEYS.has(key)));
}

function jsonType(value: JsonValue | undefined): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function matchesCondition(actual: JsonValue | undefined, expected: ArgumentCondition | JsonValue): boolean {
  if (!isCondition(expected)) return isDeepStrictEqual(actual, expected);
  if (expected.exists !== undefined && expected.exists !== (actual !== undefined)) return false;
  if (expected.isType !== undefined && expected.isType !== jsonType(actual)) return false;
  if (expected.equals !== undefined && !isDeepStrictEqual(actual, expected.equals)) return false;
  if (expected.notEquals !== undefined && isDeepStrictEqual(actual, expected.notEquals)) return false;
  if (expected.oneOf !== undefined && !expected.oneOf.some((item) => isDeepStrictEqual(actual, item))) return false;
  if (expected.matches !== undefined) {
    if (typeof actual !== "string") return false;
    try {
      if (!new RegExp(expected.matches).test(actual)) return false;
    } catch {
      throw new Error(`invalid policy regular expression: ${expected.matches}`);
    }
  }
  if (expected.contains !== undefined && (typeof actual !== "string" || !actual.includes(expected.contains))) return false;
  if (expected.startsWith !== undefined && (typeof actual !== "string" || !actual.startsWith(expected.startsWith))) return false;
  if (expected.endsWith !== undefined && (typeof actual !== "string" || !actual.endsWith(expected.endsWith))) return false;
  return true;
}

export function evaluatePolicy(config: ProxyConfig, call: ToolCall): PolicyResult {
  for (const rule of config.rules) {
    const toolMatches = !rule.match?.tools || rule.match.tools.some((pattern) => globToRegExp(pattern).test(call.name));
    if (!toolMatches) continue;
    const argumentsMatch = !rule.match?.arguments || Object.entries(rule.match.arguments).every(([path, condition]) =>
      matchesCondition(getPath(call.arguments, path), condition),
    );
    if (!argumentsMatch) continue;
    return {
      decision: normalizeDecision(rule.action),
      ruleId: rule.id,
      reason: rule.reason ?? rule.description ?? `matched rule ${rule.id}`,
    };
  }
  const decision = normalizeDecision(config.default);
  return { decision, ruleId: null, reason: `no rule matched; default is ${decision}` };
}
