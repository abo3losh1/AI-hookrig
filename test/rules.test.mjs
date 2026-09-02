import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { analyze } from '../src/doctor/rules.mjs';

/** Build the shape collectHooks() produces, for one hook handler. */
function collected(event, handler, { matcher, file = '/repo/.claude/settings.json', strict = true } = {}) {
  return {
    projectDir: '/repo',
    files: [{ scope: 'project', file, strict }],
    entries: [{ scope: 'project', file, event, matcher, handler, pointer: `hooks.${event}[0].hooks[0]`, line: 3 }],
  };
}

function ids(findings) {
  return findings.map((f) => f.id);
}

function shell(command, extra = {}) {
  return { type: 'command', command, ...extra };
}

test('flags /dev/null as Windows-only breakage', () => {
  const f = analyze(collected('PreToolUse', shell('mycheck.exe 2>/dev/null')));
  const hit = f.find((x) => x.id === 'posix-devnull');
  assert.ok(hit, 'expected posix-devnull');
  assert.equal(hit.severity, 'error');
  assert.deepEqual(hit.platforms, ['win32']);
});

test('flags && as a PowerShell 5.1 parser error', () => {
  const f = analyze(collected('PostToolUse', shell('npm run lint && npm test')));
  assert.ok(ids(f).includes('ps-chain-operators'));
});

test('flags unbraced $CLAUDE_PROJECT_DIR but not the braced placeholder', () => {
  const bad = analyze(collected('PreToolUse', shell('node $CLAUDE_PROJECT_DIR/x.mjs')));
  const hit = bad.find((x) => x.id === 'unbraced-variable');
  assert.ok(hit);
  assert.match(hit.fix, /braces/);

  const good = analyze(collected('PreToolUse', shell('node "${CLAUDE_PROJECT_DIR}/x.mjs"')));
  assert.ok(!ids(good).includes('unbraced-variable'));
});

test('flags jq and other POSIX-only binaries', () => {
  const f = analyze(collected('PreToolUse', shell('jq -r .tool_name')));
  const hit = f.find((x) => x.id === 'posix-only-binary');
  assert.ok(hit);
  assert.match(hit.message, /jq/);
});

test('flags curl as a PowerShell alias, at error severity', () => {
  const f = analyze(collected('Stop', shell('curl -s https://example.com/ping')));
  const hit = f.find((x) => x.id === 'powershell-alias-shadow');
  assert.ok(hit);
  assert.equal(hit.severity, 'error');
  assert.match(hit.message, /Invoke-WebRequest/);
});

test('flags cat as an alias, at warning severity', () => {
  const f = analyze(collected('Stop', shell('cat notes.txt')));
  const hit = f.find((x) => x.id === 'powershell-alias-shadow');
  assert.ok(hit);
  assert.equal(hit.severity, 'warn');
});

test('flags direct .sh invocation', () => {
  const f = analyze(collected('PreToolUse', shell('./.claude/hooks/guard.sh')));
  assert.ok(ids(f).includes('shell-script-direct'));
});

test('flags python3 on Windows', () => {
  const f = analyze(collected('PreToolUse', shell('python3 hook.py')));
  assert.ok(ids(f).includes('python3-binary'));
});

test('flags heredocs and backticks', () => {
  const heredoc = analyze(collected('SessionStart', shell('node <<EOF\nconsole.log(1)\nEOF')));
  assert.ok(ids(heredoc).includes('heredoc'));

  const backtick = analyze(collected('SessionStart', shell('echo `date`')));
  assert.ok(ids(backtick).includes('backtick-substitution'));
});

test('flags inline environment assignment', () => {
  const f = analyze(collected('PreToolUse', shell('FOO=bar node x.mjs')));
  assert.ok(ids(f).includes('inline-env-assignment'));
});

test('flags Windows-only syntax as broken on macOS and Linux', () => {
  const f = analyze(collected('PreToolUse', shell('powershell -File C:\\hooks\\guard.ps1')));
  const hit = f.find((x) => x.id === 'windows-only-syntax');
  assert.ok(hit);
  assert.deepEqual(hit.platforms, ['darwin', 'linux']);
});

test('flags an unquoted path containing a space', () => {
  const f = analyze(collected('PreToolUse', shell('node C:/Users/me/My Projects/hook.mjs')));
  assert.ok(ids(f).includes('unquoted-path-with-space'));
});

test('target filter hides findings from other platforms', () => {
  const c = collected('PreToolUse', shell('mycheck.exe 2>/dev/null'));
  assert.equal(analyze(c, { target: 'linux' }).filter((x) => x.id === 'posix-devnull').length, 0);
  assert.equal(analyze(c, { target: 'win32' }).filter((x) => x.id === 'posix-devnull').length, 1);
});

test('catches an unknown event and suggests the real one', () => {
  const f = analyze(collected('PostToolUce', shell('node x.mjs')));
  const hit = f.find((x) => x.id === 'unknown-event');
  assert.ok(hit);
  assert.match(hit.fix, /PostToolUse/);
});

test('catches a matcher value the event can never emit', () => {
  const f = analyze(collected('SessionStart', shell('node x.mjs'), { matcher: 'startupp' }));
  const hit = f.find((x) => x.id === 'dead-matcher');
  assert.ok(hit);
  assert.match(hit.detail, /startup/);
});

test('accepts a valid matcher value', () => {
  const f = analyze(collected('SessionStart', shell('node x.mjs'), { matcher: 'resume' }));
  assert.ok(!ids(f).includes('dead-matcher'));
});

test('catches permission-rule syntax used as a matcher', () => {
  const f = analyze(collected('PreToolUse', shell('node x.mjs'), { matcher: 'Bash(git *)' }));
  const hit = f.find((x) => x.id === 'matcher-is-permission-rule');
  assert.ok(hit);
  assert.match(hit.fix, /"matcher": "Bash"/);
});

test('catches a glob used where a regex is required', () => {
  const f = analyze(collected('PreToolUse', shell('node x.mjs'), { matcher: '*.ts' }));
  assert.ok(ids(f).includes('matcher-bad-regex'));
});

test('catches shell operators in exec form', () => {
  const f = analyze(collected('PreToolUse', { type: 'command', command: 'node', args: ['x.mjs', '&&', 'echo done'] }));
  const hit = f.find((x) => x.id === 'exec-form-shell-syntax');
  assert.ok(hit);
  assert.equal(hit.severity, 'error');
});

test('catches http headers whose variables are not allowlisted', () => {
  const f = analyze(collected('PreToolUse', { type: 'http', url: 'https://x/y', headers: { Authorization: 'Bearer $TOKEN' } }));
  const hit = f.find((x) => x.id === 'http-env-not-allowed');
  assert.ok(hit);
  assert.match(hit.fix, /"TOKEN"/);
});

test('does not warn about a localhost http endpoint', () => {
  const f = analyze(collected('PreToolUse', { type: 'http', url: 'http://localhost:9000/hook' }));
  assert.ok(!ids(f).includes('http-plaintext'));
});

test('warns about exit 2 on an event that cannot block', () => {
  const f = analyze(collected('PostToolUse', shell('node check.mjs || exit 2')));
  const hit = f.find((x) => x.id === 'exit-2-on-nonblockable');
  assert.ok(hit);
  assert.match(hit.fix, /PreToolUse/);
});

test('warns when a slow command has no timeout', () => {
  const f = analyze(collected('PostToolUse', shell('npm test')));
  assert.ok(ids(f).includes('slow-hook-no-timeout'));
  const withTimeout = analyze(collected('PostToolUse', shell('npm test', { timeout: 60 })));
  assert.ok(!ids(withTimeout).includes('slow-hook-no-timeout'));
});

test('reports a settings file that is not strict JSON', () => {
  const c = collected('PreToolUse', shell('node x.mjs'), { strict: false });
  c.files[0].strictError = new Error('Unexpected token }');
  const hit = analyze(c).find((x) => x.id === 'json-strict');
  assert.ok(hit);
  assert.equal(hit.severity, 'error');
});

test('flags a hook whose script does not exist', () => {
  const f = analyze(
    collected('PreToolUse', {
      type: 'command',
      command: 'node',
      args: ['${CLAUDE_PROJECT_DIR}/.claude/hooks/gone.mjs'],
    }),
  );
  const hit = f.find((x) => x.id === 'script-missing');
  assert.ok(hit);
  assert.equal(hit.severity, 'error');
});

test('a clean exec-form hook pointing at a real script produces nothing', () => {
  const repo = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]$/, '');
  const c = collected('PreToolUse', {
    type: 'command',
    command: 'node',
    args: ['${CLAUDE_PROJECT_DIR}/src/runner/run.mjs', 'PreToolUse'],
    timeout: 30,
  });
  c.projectDir = repo;
  const f = analyze(c);
  assert.deepEqual(f, [], `unexpected findings: ${JSON.stringify(ids(f))}`);
});

test('alias fixes only point at an executable Windows actually ships', () => {
  const withExe = analyze(collected('Stop', shell('curl -s https://x/ping')))
    .find((x) => x.id === 'powershell-alias-shadow');
  assert.match(withExe.fix, /curl\.exe/);

  const withoutExe = analyze(collected('Stop', shell('echo done')))
    .find((x) => x.id === 'powershell-alias-shadow');
  assert.doesNotMatch(withoutExe.fix, /echo\.exe/, 'there is no echo.exe on Windows');
  assert.match(withoutExe.fix, /ships no echo executable/);
});
