import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dispatch, buildOutput, merge, matches } from '../src/runner/runtime.mjs';

test('matcher semantics follow Claude Code: word lists are exact, anything else is a regex', () => {
  assert.equal(matches('Bash', 'Bash'), true);
  assert.equal(matches('Bash', 'bash'), false);
  assert.equal(matches('Edit|Write', 'Write'), true);
  assert.equal(matches('Edit|Write', 'Read'), false);
  assert.equal(matches('mcp__.*', 'mcp__github__search'), true);
  assert.equal(matches('*', 'anything'), true);
  assert.equal(matches(undefined, 'anything'), true);
  assert.equal(matches('[', 'anything'), false, 'an invalid regex must not throw');
});

test('a PreToolUse deny produces a permission decision and exit 2', async () => {
  const config = { hooks: { PreToolUse: [(input, ctx) => ctx.deny('nope')] } };
  const { output, exitCode } = await dispatch('PreToolUse', { tool_name: 'Bash' }, config);
  assert.equal(exitCode, 2);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(output.hookSpecificOutput.permissionDecisionReason, 'nope');
});

test('the same deny on PostToolUse becomes shouldStop with exit 0, because the tool already ran', async () => {
  const config = { hooks: { PostToolUse: [(input, ctx) => ctx.deny('too late')] } };
  const { output, exitCode } = await dispatch('PostToolUse', { tool_name: 'Bash' }, config);
  assert.equal(exitCode, 0);
  assert.equal(output.hookSpecificOutput.shouldStop, true);
});

test('a Stop deny asks the model to keep going', async () => {
  const config = { hooks: { Stop: [(input, ctx) => ctx.deny('not finished')] } };
  const { output, exitCode } = await dispatch('Stop', {}, config);
  assert.equal(exitCode, 2);
  assert.equal(output.hookSpecificOutput.shouldContinue, true);
});

test('ConfigChange uses shouldBlock rather than a permission decision', async () => {
  const config = { hooks: { ConfigChange: [(input, ctx) => ctx.deny('locked')] } };
  const { output } = await dispatch('ConfigChange', { source: 'user_settings' }, config);
  assert.equal(output.hookSpecificOutput.shouldBlock, true);
  assert.equal(output.hookSpecificOutput.reason, 'locked');
});

test('handlers run in order and the first deny wins', async () => {
  const calls = [];
  const config = {
    hooks: {
      PreToolUse: [
        (i, ctx) => { calls.push('a'); return ctx.pass(); },
        (i, ctx) => { calls.push('b'); return ctx.deny('stop here'); },
        (i, ctx) => { calls.push('c'); return ctx.pass(); },
      ],
    },
  };
  const { output } = await dispatch('PreToolUse', { tool_name: 'Bash' }, config);
  assert.deepEqual(calls, ['a', 'b']);
  assert.equal(output.hookSpecificOutput.permissionDecisionReason, 'stop here');
});

test('a handler match narrows by tool name', async () => {
  const seen = [];
  const config = {
    hooks: {
      PreToolUse: [{ match: { tool: 'Bash' }, run: (i, ctx) => { seen.push(i.tool_name); return ctx.pass(); } }],
    },
  };
  await dispatch('PreToolUse', { tool_name: 'Read' }, config);
  await dispatch('PreToolUse', { tool_name: 'Bash' }, config);
  assert.deepEqual(seen, ['Bash']);
});

test('context strings from several handlers are joined', () => {
  const merged = merge([{ decision: 'pass', additionalContext: 'one' }, { decision: 'pass', additionalContext: 'two' }]);
  assert.equal(merged.additionalContext, 'one\ntwo');
});

test('no decision and no context means no output at all', async () => {
  const config = { hooks: { PreToolUse: [(i, ctx) => ctx.pass()] } };
  const { output, exitCode } = await dispatch('PreToolUse', { tool_name: 'Bash' }, config);
  assert.equal(output, null);
  assert.equal(exitCode, 0);
});

test('an event with no handlers is a no-op', async () => {
  const { output, exitCode } = await dispatch('SessionStart', { reason: 'startup' }, { hooks: {} });
  assert.equal(output, null);
  assert.equal(exitCode, 0);
});

test('updatedInput is carried through on PreToolUse', () => {
  const out = buildOutput('PreToolUse', { decision: 'allow', updatedInput: { command: 'ls -la' } });
  assert.deepEqual(out.hookSpecificOutput.updatedInput, { command: 'ls -la' });
});

test('every output carries the event name back', () => {
  const out = buildOutput('UserPromptSubmit', { decision: 'pass', updatedPrompt: 'hi' });
  assert.equal(out.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.equal(out.hookSpecificOutput.updatedPrompt, 'hi');
});
