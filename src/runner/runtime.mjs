/**
 * hookrig runtime - the dispatcher every hook event is routed through.
 *
 * This file is vendored into .claude/hooks/hookrig/ by `hookrig init`, so a
 * repo can commit it and every teammate gets identical behaviour with no
 * install step. It imports nothing outside the Node standard library.
 *
 * Claude Code invokes it in exec form:
 *
 *   { "type": "command",
 *     "command": "node",
 *     "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/hookrig/run.mjs", "PreToolUse"] }
 *
 * Exec form means no shell is involved, which is the entire reason hooks
 * written this way behave the same on Windows, macOS and Linux.
 */

import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

/* -------------------------------------------------------------------------
 * Output shapes, per event.
 *
 * Claude Code expects a different field name for "block this" depending on
 * the event. Handlers return a neutral decision and the runtime translates.
 * ---------------------------------------------------------------------- */

const DECISION_STYLE = {
  PreToolUse: 'permission',
  PermissionRequest: 'permissionRequest',
  PermissionDenied: 'retry',
  UserPromptSubmit: 'prompt',
  Stop: 'continue',
  SubagentStop: 'continue',
  TeammateIdle: 'continue',
  PostToolUse: 'postTool',
  PostToolUseFailure: 'postTool',
  UserPromptExpansion: 'block',
  PreModelSwitch: 'block',
  ConfigChange: 'block',
  TaskCreated: 'block',
  TaskCompleted: 'block',
  PostToolBatch: 'block',
  WorktreeCreate: 'exitOnly',
};

/** Events where exit code 2 actually stops something. */
const BLOCKABLE = new Set([
  'PreToolUse', 'UserPromptSubmit', 'UserPromptExpansion', 'Stop', 'SubagentStop',
  'TeammateIdle', 'TaskCreated', 'TaskCompleted', 'ConfigChange', 'PostToolBatch',
  'PreModelSwitch', 'WorktreeCreate',
]);

/* -------------------------------------------------------------------------
 * Handler context
 * ---------------------------------------------------------------------- */

function makeContext(input, event) {
  return {
    event,
    input,
    cwd: input.cwd ?? process.cwd(),
    projectDir: process.env.CLAUDE_PROJECT_DIR ?? input.cwd ?? process.cwd(),
    sessionId: input.session_id,
    toolName: input.tool_name,
    toolInput: input.tool_input ?? {},
    platform: process.platform,

    /** Let the action through. */
    allow: (reason) => ({ decision: 'allow', reason }),
    /** Stop the action. On non-blockable events this degrades to a message. */
    deny: (reason) => ({ decision: 'deny', reason: reason ?? 'Blocked by a hookrig hook.' }),
    /** Do nothing. */
    pass: () => ({ decision: 'pass' }),
    /** Add text the model will see. */
    context: (text) => ({ decision: 'pass', additionalContext: text }),
    /** Show a line to the user without involving the model. */
    message: (text) => ({ decision: 'pass', systemMessage: text }),
    /** Rewrite the tool input before it runs (PreToolUse only). */
    updateInput: (updated) => ({ decision: 'allow', updatedInput: updated }),
    /** Rewrite the user's prompt (UserPromptSubmit only). */
    updatePrompt: (updated) => ({ decision: 'pass', updatedPrompt: updated }),
    /** Ring the terminal bell. Works in every terminal that supports it. */
    bell: () => ({ decision: 'pass', terminalSequence: '\u0007' }),
  };
}

/* -------------------------------------------------------------------------
 * Matching
 * ---------------------------------------------------------------------- */

/**
 * Same semantics Claude Code uses for `matcher`: a plain word list is an
 * exact, case-sensitive comparison; anything else is an unanchored regex.
 */
export function matches(pattern, value) {
  if (pattern === undefined || pattern === null || pattern === '' || pattern === '*') return true;
  if (typeof value !== 'string') return false;
  if (/^[a-zA-Z0-9_\-\s,|]+$/.test(pattern)) {
    return pattern.split('|').map((p) => p.trim()).filter(Boolean).includes(value);
  }
  try {
    return new RegExp(pattern).test(value);
  } catch {
    return false;
  }
}

function handlerApplies(handler, input) {
  const only = handler?.match;
  if (!only) return true;
  if (typeof only === 'function') return Boolean(only(input));
  if (only.tool !== undefined && !matches(only.tool, input.tool_name)) return false;
  if (only.reason !== undefined && !matches(only.reason, input.reason)) return false;
  if (only.agent !== undefined && !matches(only.agent, input.agent_type)) return false;
  return true;
}

/* -------------------------------------------------------------------------
 * Result -> Claude Code JSON
 * ---------------------------------------------------------------------- */

export function buildOutput(event, merged) {
  const specific = { hookEventName: event };
  const style = DECISION_STYLE[event] ?? 'none';
  const denied = merged.decision === 'deny';

  switch (style) {
    case 'permission':
      if (denied) {
        specific.permissionDecision = 'deny';
        specific.permissionDecisionReason = merged.reason;
      } else if (merged.decision === 'allow') {
        specific.permissionDecision = 'allow';
        if (merged.reason) specific.permissionDecisionReason = merged.reason;
      }
      if (merged.updatedInput) specific.updatedInput = merged.updatedInput;
      break;

    case 'permissionRequest':
      if (denied) {
        specific.decision = 'deny';
        specific.denialReason = merged.reason;
      } else if (merged.decision === 'allow') {
        specific.decision = 'allow';
      }
      break;

    case 'retry':
      if (merged.retry !== undefined) specific.retry = merged.retry;
      break;

    case 'prompt':
      if (merged.updatedPrompt !== undefined) specific.updatedPrompt = merged.updatedPrompt;
      break;

    case 'continue':
      if (denied) specific.shouldContinue = true;
      break;

    case 'postTool':
      if (denied) specific.shouldStop = true;
      break;

    case 'block':
      if (denied) {
        specific.shouldBlock = true;
        specific.reason = merged.reason;
      }
      break;

    default:
      break;
  }

  if (merged.additionalContext) specific.additionalContext = merged.additionalContext;
  if (merged.systemMessage) specific.systemMessage = merged.systemMessage;
  if (merged.terminalSequence) specific.terminalSequence = merged.terminalSequence;

  return { hookSpecificOutput: specific };
}

/** Fold several handler results into one. First deny wins. */
export function merge(results) {
  const out = { decision: 'pass' };
  const contexts = [];
  const messages = [];

  for (const r of results) {
    if (!r || typeof r !== 'object') continue;
    if (r.decision === 'deny' && out.decision !== 'deny') {
      out.decision = 'deny';
      out.reason = r.reason;
    } else if (r.decision === 'allow' && out.decision === 'pass') {
      out.decision = 'allow';
      if (r.reason) out.reason = r.reason;
    }
    if (r.updatedInput) out.updatedInput = { ...(out.updatedInput ?? {}), ...r.updatedInput };
    if (r.updatedPrompt !== undefined) out.updatedPrompt = r.updatedPrompt;
    if (r.retry !== undefined) out.retry = r.retry;
    if (r.additionalContext) contexts.push(r.additionalContext);
    if (r.systemMessage) messages.push(r.systemMessage);
    if (r.terminalSequence) out.terminalSequence = r.terminalSequence;
  }

  if (contexts.length) out.additionalContext = contexts.join('\n');
  if (messages.length) out.systemMessage = messages.join('\n');
  return out;
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve(data);
    };
    // A hook with no piped stdin must not hang the session.
    const guard = setTimeout(done, 3000);
    guard.unref?.();
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => { clearTimeout(guard); done(); });
    process.stdin.on('error', () => { clearTimeout(guard); done(); });
  });
}

function logError(projectDir, message) {
  try {
    const file = join(projectDir, '.claude', 'hookrig-errors.log');
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, `${new Date().toISOString()} ${message}\n`);
  } catch {
    // A logging failure must never take the session down.
  }
}

/**
 * Run one event. Returns the process exit code.
 * Exported so tests can drive it without spawning a process.
 */
export async function dispatch(event, input, config) {
  const handlers = (config?.hooks?.[event] ?? []).filter((h) => typeof h === 'function' || typeof h?.run === 'function');
  const ctx = makeContext(input, event);
  const results = [];

  for (const handler of handlers) {
    if (!handlerApplies(handler, input)) continue;
    const fn = typeof handler === 'function' ? handler : handler.run;
    const result = await fn(input, ctx);
    if (result) results.push(result);
    if (result?.decision === 'deny') break;
  }

  const merged = merge(results);
  const output = buildOutput(event, merged);
  const hasPayload = Object.keys(output.hookSpecificOutput).length > 1;
  const blocked = merged.decision === 'deny' && BLOCKABLE.has(event);

  return { output: hasPayload ? output : null, exitCode: blocked ? 2 : 0, reason: merged.reason };
}

export async function main(argv = process.argv.slice(2)) {
  const event = argv[0];
  const projectDir = process.env.CLAUDE_PROJECT_DIR ?? process.cwd();

  if (!event) {
    logError(projectDir, 'hookrig runtime called without an event name');
    return 0;
  }

  let input = {};
  try {
    const raw = await readStdin();
    if (raw.trim()) input = JSON.parse(raw);
  } catch (err) {
    logError(projectDir, `could not parse hook input for ${event}: ${err.message}`);
    return 0;
  }

  let config;
  try {
    const configPath = join(projectDir, '.claude', 'hooks', 'hookrig.config.mjs');
    config = (await import(pathToFileURL(configPath).href)).default;
  } catch (err) {
    logError(projectDir, `could not load .claude/hooks/hookrig.config.mjs: ${err.message}`);
    return 0;
  }

  try {
    const { output, exitCode, reason } = await dispatch(event, input, config);
    if (output) process.stdout.write(JSON.stringify(output));
    if (exitCode === 2 && reason) process.stderr.write(reason);
    return exitCode;
  } catch (err) {
    // A crashing hook must never block the user's work.
    logError(projectDir, `${event} handler threw: ${err?.stack ?? err}`);
    return 0;
  }
}
