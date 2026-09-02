#!/usr/bin/env node
/**
 * Entry point Claude Code calls, in exec form:
 *   "command": "node",
 *   "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/hookrig/run.mjs", "<Event>"]
 */
import { main } from './runtime.mjs';

main().then(
  (code) => process.exit(code ?? 0),
  // A broken hook must never stop the user's session.
  () => process.exit(0),
);
