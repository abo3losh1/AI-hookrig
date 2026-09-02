#!/usr/bin/env node
/**
 * Test runner.
 *
 * `node --test "test/**\/*.test.mjs"` looks portable and is not. Glob patterns
 * after --test only work from Node 21, and npm scripts run through cmd.exe on
 * Windows, which does not expand globs at all. Both failures are silent in the
 * sense that they blame a missing file rather than the shell.
 *
 * So resolve the file list in Node and pass explicit paths, which every
 * supported version accepts. Same reasoning as exec form for hooks: do the
 * work in a language that behaves identically everywhere, rather than hoping
 * two shells agree.
 */

import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const testDir = join(root, 'test');

const files = readdirSync(testDir)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => join(testDir, name));

if (files.length === 0) {
  process.stderr.write('No test files found in test/\n');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files, ...process.argv.slice(2)], {
  cwd: root,
  stdio: 'inherit',
});

process.exit(result.status ?? 1);
