import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditRecord, JsonValue } from "./types.js";

const SECRET_KEY = /(^|_)(authorization|api[-_]?key|password|passwd|secret|token|cookie)($|_)/i;

async function appendJsonLine(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, `${JSON.stringify(value)}\n`, { encoding: "utf8", mode: 0o600 });
}

export async function appendAudit(path: string, record: AuditRecord): Promise<void> {
  await appendJsonLine(path, record);
}

export async function readJsonLines(path: string): Promise<unknown[]> {
  let content: string;
  try {
    content = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  return content
    .split("\n")
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        throw new Error(`invalid JSON on line ${index + 1} of ${path}`);
      }
    });
}

function redactValue(value: JsonValue, path: string, explicit: Set<string>): JsonValue {
  if (Array.isArray(value)) return value.map((item, index) => redactValue(item, `${path}.${index}`, explicit));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => {
        const childPath = path ? `${path}.${key}` : key;
        return [key, explicit.has(childPath) || SECRET_KEY.test(key) ? "[REDACTED]" : redactValue(child, childPath, explicit)];
      }),
    );
  }
  return value;
}

export function redactArguments(arguments_: Record<string, JsonValue>, paths: string[] = []): Record<string, JsonValue> {
  return redactValue(arguments_, "arguments", new Set(paths)) as Record<string, JsonValue>;
}

export { appendJsonLine };
