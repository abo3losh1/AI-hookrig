/**
 * Canonical Claude Code hook events.
 *
 * Source: https://code.claude.com/docs/en/hooks (verified 2026-09-02).
 *
 * `blockable`   exit code 2 (or a shouldBlock/deny decision) stops the action.
 * `matcher`     what the `matcher` string is compared against, or null when the
 *               event ignores matchers entirely.
 * `values`      the closed set of matcher values, when the event has one. Used
 *               by the doctor to catch matchers that can never fire.
 * `timeout`     default timeout in seconds when the handler does not set one.
 */

export const EVENTS = {
  SessionStart:        { blockable: false, matcher: 'reason',        values: ['startup', 'resume', 'clear', 'compact', 'fork'], timeout: 600, context: true },
  Setup:               { blockable: false, matcher: 'flag',          values: ['init', 'maintenance'], timeout: 600 },
  UserPromptSubmit:    { blockable: true,  matcher: null,            timeout: 30, context: true },
  UserPromptExpansion: { blockable: true,  matcher: 'command name',  timeout: 600, context: true },
  PreToolUse:          { blockable: true,  matcher: 'tool name',     timeout: 600, tool: true },
  PermissionRequest:   { blockable: false, matcher: 'tool name',     timeout: 600, tool: true },
  PermissionDenied:    { blockable: false, matcher: 'tool name',     timeout: 600, tool: true },
  PostToolUse:         { blockable: false, matcher: 'tool name',     timeout: 600, tool: true },
  PostToolUseFailure:  { blockable: false, matcher: 'tool name',     timeout: 600, tool: true },
  PostToolBatch:       { blockable: true,  matcher: null,            timeout: 600 },
  Stop:                { blockable: true,  matcher: null,            timeout: 600 },
  StopFailure:         { blockable: false, matcher: 'error type',    values: ['rate_limit', 'overloaded', 'authentication_failed', 'oauth_org_not_allowed', 'account_on_hold', 'billing_error', 'invalid_request', 'model_not_found', 'server_error', 'max_output_tokens', 'unknown'], timeout: 600 },
  SubagentStart:       { blockable: false, matcher: 'agent type',    timeout: 600 },
  SubagentStop:        { blockable: true,  matcher: 'agent type',    timeout: 600 },
  TaskCreated:         { blockable: true,  matcher: null,            timeout: 600 },
  TaskCompleted:       { blockable: true,  matcher: null,            timeout: 600 },
  TeammateIdle:        { blockable: true,  matcher: null,            timeout: 600 },
  PreCompact:          { blockable: false, matcher: 'trigger',       values: ['manual', 'auto'], timeout: 600 },
  PostCompact:         { blockable: false, matcher: 'trigger',       values: ['manual', 'auto'], timeout: 600 },
  PreModelSwitch:      { blockable: true,  matcher: 'model name',    timeout: 30 },
  PostModelSwitch:     { blockable: false, matcher: 'model name',    timeout: 30, context: true },
  InstructionsLoaded:  { blockable: false, matcher: 'load reason',   values: ['session_start', 'nested_traversal', 'path_glob_match', 'include', 'compact'], timeout: 600 },
  ConfigChange:        { blockable: true,  matcher: 'config source', values: ['user_settings', 'project_settings', 'local_settings', 'policy_settings', 'skills'], timeout: 600 },
  CwdChanged:          { blockable: false, matcher: null,            timeout: 600 },
  DirectoryAdded:      { blockable: false, matcher: 'how added',     values: ['slash_command', 'register_repo_root'], timeout: 600 },
  FileChanged:         { blockable: false, matcher: 'literal names', literalMatcher: true, timeout: 600 },
  WorktreeCreate:      { blockable: true,  matcher: null,            timeout: 600, anyNonZeroBlocks: true },
  WorktreeRemove:      { blockable: false, matcher: null,            timeout: 600 },
  Notification:        { blockable: false, matcher: 'notification type', values: ['permission_prompt', 'idle_prompt', 'auth_success', 'elicitation_dialog', 'elicitation_url_dialog', 'elicitation_complete', 'elicitation_response', 'agent_needs_input', 'agent_completed', 'quota_auto_resume_fired', 'quota_auto_resume_stale', 'quota_auto_resume_disabled'], timeout: 600 },
  MessageDisplay:      { blockable: false, matcher: null,            timeout: 10 },
  Elicitation:         { blockable: false, matcher: 'mcp server',    timeout: 600 },
  ElicitationResult:   { blockable: false, matcher: 'mcp server',    timeout: 600 },
  SessionEnd:          { blockable: false, matcher: 'reason',        values: ['clear', 'resume', 'logout', 'prompt_input_exit', 'other'], timeout: 600 },
};

export const EVENT_NAMES = Object.keys(EVENTS);

/** Events where a hook may return a permission decision on a tool call. */
export const TOOL_EVENTS = EVENT_NAMES.filter((n) => EVENTS[n].tool);

/** Events whose plain-text stdout is injected into the model's context. */
export const CONTEXT_EVENTS = EVENT_NAMES.filter((n) => EVENTS[n].context);

/**
 * Closest known event name for a typo, or null when nothing is close enough.
 * Plain Levenshtein, capped so "Stop" does not "correct" to "Setup".
 */
export function suggestEvent(name) {
  let best = null;
  let bestScore = Infinity;
  for (const candidate of EVENT_NAMES) {
    const d = distance(name.toLowerCase(), candidate.toLowerCase());
    if (d < bestScore) {
      bestScore = d;
      best = candidate;
    }
  }
  const limit = Math.max(2, Math.floor(name.length / 3));
  return bestScore <= limit ? best : null;
}

function distance(a, b) {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  const row = new Array(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min(row[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev.splice(0, prev.length, ...row);
  }
  return prev[b.length];
}
