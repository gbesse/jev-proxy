import { appendJsonLine, readJsonLines } from "./audit.js";

interface ApprovalEvent {
  timestamp: string;
  type: "grant" | "consume";
  fingerprint: string;
  auditId: string;
}

function isApprovalEvent(value: unknown): value is ApprovalEvent {
  if (!value || typeof value !== "object") return false;
  const event = value as Record<string, unknown>;
  return (event.type === "grant" || event.type === "consume") && typeof event.fingerprint === "string" && typeof event.auditId === "string";
}

export async function grantApproval(path: string, fingerprint: string, auditId: string): Promise<void> {
  await appendJsonLine(path, { timestamp: new Date().toISOString(), type: "grant", fingerprint, auditId } satisfies ApprovalEvent);
}

export async function consumeApproval(path: string, fingerprint: string): Promise<string | null> {
  const events = (await readJsonLines(path)).filter(isApprovalEvent);
  const grants = events.filter((event) => event.type === "grant" && event.fingerprint === fingerprint);
  const consumed = new Set(events.filter((event) => event.type === "consume").map((event) => event.auditId));
  const grant = grants.find((event) => !consumed.has(event.auditId));
  if (!grant) return null;
  await appendJsonLine(path, {
    timestamp: new Date().toISOString(),
    type: "consume",
    fingerprint,
    auditId: grant.auditId,
  } satisfies ApprovalEvent);
  return grant.auditId;
}
