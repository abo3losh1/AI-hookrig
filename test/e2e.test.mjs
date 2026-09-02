import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { init } from '../src/init.mjs';
import { collectHooks } from '../src/doctor/settings.mjs';
import { analyze } from '../src/doctor/rules.mjs';

/**
 * End to end: scaffold a project, run the real dispatcher as a child process
 * with hook JSON on stdin, and check the exit code and stdout Claude Code
 * would actually receive. This is the test that proves the whole path works
 * on whatever platform CI happens to be.
 */

function project() {
  const dir = mkdtempSync(join(tmpdir(), 'hookrig-'));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

/** Spawn the vendored runner exactly the way Claude Code does: exec form. */
function runHook(dir, event, input) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(dir, '.claude', 'hooks', 'hookrig', 'run.mjs'), event], {
      env: { ...process.env, CLAUDE_PROJECT_DIR: dir },
      stdio: ['pipe', 'pipe', 'pipe'],
      // No shell. That is the point.
      shell: false,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(input));
  });
}

const quiet = () => {
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = () => true;
  return () => { process.stdout.write = write; };
};

test('init scaffolds a runnable project and registers exec-form hooks', async (t) => {
  const p = project();
  t.after(p.cleanup);

  const restore = quiet();
  await init({ dir: p.dir });
  restore();

  for (const file of ['runtime.mjs', 'run.mjs', 'builtins.mjs']) {
    assert.ok(existsSync(join(p.dir, '.claude', 'hooks', 'hookrig', file)), `missing ${file}`);
  }
  assert.ok(existsSync(join(p.dir, '.claude', 'hooks', 'hookrig.config.mjs')));

  const settings = JSON.parse(readFileSync(join(p.dir, '.claude', 'settings.json'), 'utf8'));
  const handler = settings.hooks.PreToolUse.at(-1).hooks[0];
  assert.equal(handler.command, 'node');
  assert.ok(Array.isArray(handler.args), 'must be exec form, so no shell is involved');
  assert.match(handler.args[0], /hookrig\/run\.mjs$/);
  assert.equal(handler.args[1], 'PreToolUse');
});

test('the generated settings pass hookrig doctor with no findings of their own', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });
  restore();

  const collected = collectHooks(p.dir);
  const own = analyze(collected).filter((f) => f.entry.file.startsWith(p.dir));
  assert.deepEqual(own, [], `hookrig generated hooks it would itself flag: ${JSON.stringify(own.map((f) => f.id))}`);
});

test('a denying hook returns exit 2 and a permission decision', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });
  restore();

  const result = await runHook(p.dir, 'PreToolUse', {
    session_id: 's1',
    cwd: p.dir,
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'rm -rf /' },
  });

  assert.equal(result.code, 2, `expected a block; stderr was: ${result.stderr}`);
  const output = JSON.parse(result.stdout);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /recursive force delete/);
});

test('an ordinary command passes through with exit 0', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });
  restore();

  const result = await runHook(p.dir, 'PreToolUse', {
    tool_name: 'Bash',
    tool_input: { command: 'npm test' },
  });
  assert.equal(result.code, 0);
  assert.equal(result.stdout.trim(), '');
});

test('a custom handler in the config is honoured', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });

  writeFileSync(
    join(p.dir, '.claude', 'hooks', 'hookrig.config.mjs'),
    `export default {
       hooks: {
         UserPromptSubmit: [
           (input, ctx) => input.prompt.includes('deploy')
             ? ctx.deny('Deploys go through CI.')
             : ctx.context('project: demo'),
         ],
       },
     };`,
  );
  await init({ dir: p.dir });
  restore();

  const blocked = await runHook(p.dir, 'UserPromptSubmit', { prompt: 'please deploy to prod' });
  assert.equal(blocked.code, 2);
  assert.match(blocked.stderr, /Deploys go through CI/);

  const allowed = await runHook(p.dir, 'UserPromptSubmit', { prompt: 'fix the tests' });
  assert.equal(allowed.code, 0);
  assert.equal(JSON.parse(allowed.stdout).hookSpecificOutput.additionalContext, 'project: demo');
});

test('a handler that throws never breaks the session', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });
  writeFileSync(
    join(p.dir, '.claude', 'hooks', 'hookrig.config.mjs'),
    `export default { hooks: { PreToolUse: [() => { throw new Error('boom'); }] } };`,
  );
  await init({ dir: p.dir });
  restore();

  const result = await runHook(p.dir, 'PreToolUse', { tool_name: 'Bash', tool_input: { command: 'ls' } });
  assert.equal(result.code, 0, 'a thrown handler must not block the user');
  assert.ok(existsSync(join(p.dir, '.claude', 'hookrig-errors.log')));
  assert.match(readFileSync(join(p.dir, '.claude', 'hookrig-errors.log'), 'utf8'), /boom/);
});

test('a broken config never breaks the session', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });
  restore();

  writeFileSync(join(p.dir, '.claude', 'hooks', 'hookrig.config.mjs'), 'this is not javascript {{{');
  const result = await runHook(p.dir, 'PreToolUse', { tool_name: 'Bash', tool_input: { command: 'rm -rf /' } });
  assert.equal(result.code, 0);
});

test('re-running init is idempotent and keeps other hooks', async (t) => {
  const p = project();
  t.after(p.cleanup);
  const restore = quiet();
  await init({ dir: p.dir });

  const settingsPath = join(p.dir, '.claude', 'settings.json');
  const settings = JSON.parse(readFileSync(settingsPath, 'utf8'));
  settings.hooks.PreToolUse.unshift({ matcher: 'Bash', hooks: [{ type: 'command', command: 'node', args: ['other.mjs'] }] });
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

  await init({ dir: p.dir });
  await init({ dir: p.dir });
  restore();

  const after = JSON.parse(readFileSync(settingsPath, 'utf8'));
  const hookrigEntries = after.hooks.PreToolUse.filter((g) =>
    g.hooks.some((h) => Array.isArray(h.args) && h.args[0].includes('hookrig/run.mjs')));
  assert.equal(hookrigEntries.length, 1, 'init must not stack duplicate entries');
  assert.ok(
    after.hooks.PreToolUse.some((g) => g.hooks.some((h) => h.args?.[0] === 'other.mjs')),
    'init must leave hooks it did not create alone',
  );
});
