// Compare four local policy decisions without executing any MCP tool.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const policy = resolve(root, 'examples/jev.config.yaml');
const cases = [
  {name: 'read', tool: 'read_file', arguments: {path: 'README.md'}, expected: 'allow'},
  {name: 'ordinary_shell', tool: 'shell.exec', arguments: {command: 'git status'}, expected: 'require_approval'},
  {name: 'destructive_shell', tool: 'shell.exec', arguments: {command: 'sudo rm -rf /tmp/example'}, expected: 'deny'},
  {name: 'unknown_tool', tool: 'unknown.tool', arguments: {}, expected: 'deny'},
];
const results = cases.map(item => {
  const output = execFileSync(process.execPath, [resolve(root, 'dist/cli.js'), 'check', '--config', policy, '--tool', item.tool, '--arguments', JSON.stringify(item.arguments)], {encoding: 'utf8'});
  const decision = JSON.parse(output);
  if (decision.decision !== item.expected) throw new Error(`${item.name}: expected ${item.expected}, got ${decision.decision}`);
  return {case: item.name, decision: decision.decision, rule: decision.ruleId ?? null};
});
console.log(JSON.stringify({source: 'local policy fixture; no MCP server or tool execution', results}, null, 2));
