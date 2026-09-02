import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderText } from '../src/doctor/report.mjs';

const base = { projectDir: '/repo', files: [{ scope: 'user', file: '/home/u/.claude/settings.json' }] };

test('a project with no hooks says so instead of claiming a clean bill of health', () => {
  const out = renderText([], { ...base, entries: [] });
  assert.match(out, /No hooks configured/);
  assert.doesNotMatch(out, /portable/, 'must not imply a check ran when there was nothing to check');
  assert.match(out, /hookrig init/);
});

test('a project with clean hooks does report them as portable', () => {
  const entries = [{ scope: 'user', file: base.files[0].file, event: 'PreToolUse', pointer: 'x', line: 1 }];
  const out = renderText([], { ...base, entries });
  assert.match(out, /No problems found/);
});
