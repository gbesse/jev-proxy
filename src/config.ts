import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parse } from "yaml";
import type { Decision, ProxyConfig } from "./types.js";

const ACTIONS = new Set(["allow", "deny", "require_approval", "review"]);

function assertAction(value: unknown, where: string): asserts value is Decision | "review" {
  if (typeof value !== "string" || !ACTIONS.has(value)) {
    throw new Error(`${where} must be allow, deny, or require_approval`);
  }
}

export function normalizeDecision(value: Decision | "review"): Decision {
  return value === "review" ? "require_approval" : value;
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
    if (rule.match !== undefined && (!rule.match || typeof rule.match !== "object" || Array.isArray(rule.match))) {
      throw new Error(`rules[${index}].match must be an object`);
    }
    const match = rule.match as Record<string, unknown> | undefined;
    if (match?.tools !== undefined && (!Array.isArray(match.tools) || !match.tools.every((tool) => typeof tool === "string"))) {
      throw new Error(`rules[${index}].match.tools must be an array of strings`);
    }
    if (match?.arguments !== undefined && (!match.arguments || typeof match.arguments !== "object" || Array.isArray(match.arguments))) {
      throw new Error(`rules[${index}].match.arguments must be an object`);
    }
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
