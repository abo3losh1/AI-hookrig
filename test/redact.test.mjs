import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { redactSecrets, redactDeep, auditLog } from '../src/hooks/builtins.mjs';

/**
 * The audit log records full command text. Anything that reaches it must not
 * contain a live credential, or the log leaks exactly what it exists to watch.
 */

const SECRETS = [
  ['sk-ant-api03-abcdefghijklmnop1234567890', 'anthropic-key'],
  ['sk-proj-abcdefghijklmnop1234567890', 'openai-key'],
  ['ghp_abcdefghijklmnopqrstuvwxyz0123', 'github-token'],
  ['github_pat_11ABCDEFG0abcdefghijklmno', 'github-token'],
  ['AKIAIOSFODNN7EXAMPLE', 'aws-key-id'],
  ['xoxb-123456789012-abcdefghijkl', 'slack-token'],
  ['sk_live_abcdefghijklmnop1234', 'stripe-key'],
  ['AIzaSyD-abcdefghijklmnopqrstuvwxyz01234567', 'google-key'],
  ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'jwt'],
];

for (const [secret, kind] of SECRETS) {
  test(`redacts a ${kind}`, () => {
    const out = redactSecrets(`curl -H "Authorization: ${secret}" https://api.example.com`);
    assert.ok(!out.includes(secret), `leaked: ${out}`);
    assert.match(out, /\[redacted:/);
  });
}

test('redacts an assignment regardless of the variable name casing', () => {
  for (const line of [
    'SECRET_KEY=sk-live-abc123',
    'export GITHUB_TOKEN="ghp_short"',
    "DB_PASSWORD='hunter2'",
    'MY_API_KEY=abc123def456',
  ]) {
    const out = redactSecrets(line);
    assert.match(out, /\[redacted:value\]/, `not redacted: ${line}`);
    assert.ok(!/hunter2|abc123def456|sk-live-abc123|ghp_short/.test(out), `leaked: ${out}`);
  }
});

test('redacts command-line credential flags', () => {
  const out = redactSecrets('mysql --password hunter2 --token=abc123 -u root');
  assert.ok(!out.includes('hunter2'));
  assert.ok(!out.includes('abc123'));
  assert.match(out, /--password \[redacted:value\]/);
});

test('redacts credentials embedded in a URL but keeps the scheme and host', () => {
  const out = redactSecrets('git clone https://user:s3cr3t@github.com/a/b.git');
  assert.ok(!out.includes('s3cr3t'));
  assert.match(out, /^git clone https:\/\/\[redacted:url-credentials\]@github\.com/);
});

test('redacts a Bearer header while keeping the scheme visible', () => {
  const out = redactSecrets('curl -H "Authorization: Bearer abcdefghijklmnopqrst"');
  assert.match(out, /Bearer \[redacted:value\]/);
});

test('redacts a whole private key block', () => {
  const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';
  const out = redactSecrets(`echo "${key}" > id_rsa`);
  assert.ok(!out.includes('MIIEowIBAAKCAQEA'));
  assert.match(out, /\[redacted:private-key\]/);
});

test('leaves ordinary commands untouched', () => {
  for (const line of [
    'npm test',
    'git commit -m "fix the parser"',
    'node scripts/build.mjs --watch',
    'grep -r TODO src/',
  ]) {
    assert.equal(redactSecrets(line), line, `over-redacted: ${line}`);
  }
});

test('redactDeep walks nested objects and arrays', () => {
  const out = redactDeep({ a: 'TOKEN=abc123', b: ['x', 'PASSWORD=y'], c: { d: 42 } });
  assert.match(out.a, /\[redacted:value\]/);
  assert.match(out.b[1], /\[redacted:value\]/);
  assert.equal(out.b[0], 'x');
  assert.equal(out.c.d, 42);
});

test('redactDeep accepts extra project patterns', () => {
  const out = redactDeep({ cmd: 'deploy --tenant acme-internal-42' }, [/acme-internal-\d+/g]);
  assert.match(out.cmd, /\[redacted:custom\]/);
});

/* --- the log itself ----------------------------------------------------- */

function project(t) {
  const dir = mkdtempSync(join(tmpdir(), 'hookrig-audit-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

const ctxFor = (dir) => ({ event: 'PostToolUse', projectDir: dir, pass: () => ({ decision: 'pass' }) });

test('the audit log redacts by default', (t) => {
  const dir = project(t);
  auditLog()({ tool_name: 'Bash', tool_input: { command: 'export API_KEY=ghp_abcdefghijklmnopqrstuvwxyz0123' } }, ctxFor(dir));
  const written = readFileSync(join(dir, '.claude', 'hookrig-audit.jsonl'), 'utf8');
  assert.ok(!written.includes('ghp_abcdefghijklmnopqrstuvwxyz0123'), `leaked: ${written}`);
  assert.match(written, /redacted/);
});

test('redaction can be turned off deliberately', (t) => {
  const dir = project(t);
  auditLog({ redact: false })({ tool_name: 'Bash', tool_input: { command: 'TOKEN=plain' } }, ctxFor(dir));
  assert.match(readFileSync(join(dir, '.claude', 'hookrig-audit.jsonl'), 'utf8'), /TOKEN=plain/);
});

test('the log rotates once it passes the cap, keeping one previous file', (t) => {
  const dir = project(t);
  const file = join(dir, 'audit.jsonl');
  const hook = auditLog({ file, maxBytes: 200 });
  const call = { tool_name: 'Bash', tool_input: { command: 'x'.repeat(120) } };

  hook(call, ctxFor(dir));
  assert.ok(!existsSync(`${file}.1`), 'must not rotate before the cap');

  for (let i = 0; i < 4; i++) hook(call, ctxFor(dir));
  assert.ok(existsSync(`${file}.1`), 'expected a rotated file');
  assert.ok(readFileSync(file, 'utf8').length < 400, 'the live file should have been restarted');
});

test('a log write that fails never breaks the session', (t) => {
  const dir = project(t);
  const blocked = join(dir, 'a-file');
  writeFileSync(blocked, 'not a directory');
  const result = auditLog({ file: join(blocked, 'nested.jsonl') })({ tool_name: 'Bash', tool_input: {} }, ctxFor(dir));
  assert.deepEqual(result, { decision: 'pass' });
});
