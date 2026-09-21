import { createInterface } from "node:readline";

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  const request = JSON.parse(line);
  if (request.method === "tools/call") {
    process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: request.params.name }] } })}\n`);
  } else {
    process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: request.id, result: {} })}\n`);
  }
}
