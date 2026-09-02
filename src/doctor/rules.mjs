import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { EVENTS, suggestEvent } from '../events.mjs';

/**
 * Portability and correctness rules for Claude Code hooks.
 *
 * The important fact these rules encode: a `command` handler with no `args`
 * is handed to a shell, and that shell is `sh` on macOS/Linux but PowerShell
 * on Windows. Almost every hook published on the internet assumes `sh`, so on
 * Windows it either fails to parse or, worse, runs a PowerShell alias that
 * quietly does something else.
 *
 * Each rule returns an array of findings. A finding is:
 *   { id, severity, message, detail, fix, platforms }
 * `platforms` says where the problem bites, so a macOS user still sees what
 * their Windows teammates hit.
 */

const ERROR = 'error';
const WARN = 'warn';
const INFO = 'info';

const WIN = ['win32'];
const POSIX = ['darwin', 'linux'];
const ALL = ['win32', 'darwin', 'linux'];

/**
 * Commands that simply do not exist in a stock Windows PowerShell session.
 * Hitting one of these means the hook errors out and, because most hook
 * events ignore non-zero exits, it fails silently.
 */
const POSIX_ONLY_BINARIES = [
  'jq', 'sed', 'awk', 'grep', 'egrep', 'fgrep', 'xargs', 'tr', 'cut', 'paste',
  'basename', 'dirname', 'realpath', 'readlink', 'mktemp', 'chmod', 'chown',
  'touch', 'uname', 'stat', 'du', 'df', 'wc', 'head', 'tail', 'uniq', 'seq',
  'yes', 'nohup', 'pgrep', 'pkill', 'killall', 'lsof', 'md5sum', 'sha256sum',
];

/**
 * The nastier class: these names DO resolve in PowerShell, as aliases to
 * cmdlets with different flags and different output. Nothing errors. The hook
 * just does the wrong thing.
 *
 * `exe` is the real executable that ships with Windows, when one does. Most of
 * these have no native equivalent at all, so telling people to call `echo.exe`
 * would send them after a binary that does not exist.
 */
const PS_ALIASES = {
  curl: { cmdlet: 'Invoke-WebRequest (PowerShell 5.1) - ignores -s, -o, -H and returns an object, not text', exe: 'curl.exe' },
  wget: { cmdlet: 'Invoke-WebRequest (PowerShell 5.1) - same problem as curl' },
  cat: { cmdlet: 'Get-Content - splits output into an array of lines' },
  ls: { cmdlet: 'Get-ChildItem - different columns, no -la' },
  rm: { cmdlet: 'Remove-Item - no -rf, prompts on non-empty directories' },
  cp: { cmdlet: 'Copy-Item - no -r' },
  mv: { cmdlet: 'Move-Item' },
  echo: { cmdlet: 'Write-Output - objects, not raw text' },
  sort: { cmdlet: 'Sort-Object - sorts objects, not lines', exe: 'sort.exe' },
  tee: { cmdlet: 'Tee-Object' },
  ps: { cmdlet: 'Get-Process' },
  kill: { cmdlet: 'Stop-Process' },
  sleep: { cmdlet: 'Start-Sleep - takes seconds as -Seconds, not a bare arg in all forms' },
  diff: { cmdlet: 'Compare-Object' },
  pwd: { cmdlet: 'Get-Location' },
  where: { cmdlet: 'Where-Object', exe: 'where.exe' },
  set: { cmdlet: 'Set-Variable' },
  history: { cmdlet: 'Get-History' },
  man: { cmdlet: 'help' },
};

const HANDLER_TYPES = new Set(['command', 'http', 'mcp_tool', 'prompt', 'agent']);

/** True when the handler is passed to a shell rather than spawned directly. */
function isShellForm(handler) {
  return handler?.type === 'command' && !Array.isArray(handler.args);
}

/** Mask quoted spans so "looks unquoted" checks do not fire inside strings. */
function maskQuoted(text) {
  return text.replace(/"[^"]*"|'[^']*'/g, (m) => '\u0000'.repeat(m.length));
}

/** Strip the `${...}` placeholders Claude Code substitutes before exec. */
function stripPlaceholders(text) {
  return text.replace(/\$\{[A-Za-z_][A-Za-z0-9_.]*\}/g, '');
}

/** The first word of a shell command, ignoring leading env assignments. */
function commandHeads(command) {
  return command
    .split(/(?:&&|\|\||[;|])/)
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const words = part.split(/\s+/).filter(Boolean);
      let i = 0;
      while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++;
      return words[i] ?? '';
    })
    .filter(Boolean);
}

function finding(id, severity, platforms, message, detail, fix) {
  return { id, severity, platforms, message, detail, fix };
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export const RULES = [];

function rule(id, fn) {
  RULES.push({ id, run: fn });
}

/* --- settings file level ------------------------------------------------ */

rule('json-strict', (entry, ctx) => {
  const file = ctx.files.find((f) => f.file === entry.file);
  if (!file || file.strict !== false) return [];
  return [finding(
    'json-strict', ERROR, ALL,
    'This settings file is not valid JSON, so Claude Code loads none of its hooks.',
    file.strictError ? String(file.strictError.message) : 'Trailing comma or comment.',
    'Remove comments and trailing commas. settings.json is strict JSON, not JSONC.',
  )];
});

/* --- event and matcher correctness -------------------------------------- */

rule('unknown-event', (entry) => {
  if (EVENTS[entry.event]) return [];
  const guess = suggestEvent(entry.event);
  return [finding(
    'unknown-event', ERROR, ALL,
    `"${entry.event}" is not a Claude Code hook event, so this hook never fires.`,
    'Unknown event keys are ignored without any warning.',
    guess ? `Did you mean "${guess}"?` : 'Check the event name against the hooks reference.',
  )];
});

rule('dead-matcher', (entry) => {
  const spec = EVENTS[entry.event];
  if (!spec || !spec.values || typeof entry.matcher !== 'string') return [];
  const value = entry.matcher.trim();
  if (!value || value === '*') return [];
  const parts = value.split('|').map((p) => p.trim()).filter(Boolean);
  const unknown = parts.filter((p) => !spec.values.includes(p));
  if (unknown.length === 0 || unknown.length !== parts.length) return [];
  return [finding(
    'dead-matcher', ERROR, ALL,
    `Matcher "${value}" can never match a ${entry.event} event.`,
    `${entry.event} only ever emits: ${spec.values.join(', ')}.`,
    `Use one of those values, or "*" to match all.`,
  )];
});

rule('matcher-ignored', (entry) => {
  const spec = EVENTS[entry.event];
  if (!spec || spec.matcher !== null) return [];
  if (typeof entry.matcher !== 'string' || !entry.matcher || entry.matcher === '*') return [];
  return [finding(
    'matcher-ignored', WARN, ALL,
    `${entry.event} ignores matchers, but this group sets matcher "${entry.matcher}".`,
    'The hook still runs on every occurrence of the event.',
    'Drop the matcher so the config says what actually happens.',
  )];
});

rule('matcher-is-permission-rule', (entry) => {
  if (typeof entry.matcher !== 'string') return [];
  if (!/^[A-Za-z_]+\(.*\)$/.test(entry.matcher.trim())) return [];
  return [finding(
    'matcher-is-permission-rule', ERROR, ALL,
    `Matcher "${entry.matcher}" uses permission-rule syntax, which matchers do not support.`,
    'A matcher containing brackets is compiled as a regular expression, so it will not match a tool name.',
    `Set "matcher": "${entry.matcher.split('(')[0]}" and move the pattern into the handler's "if" field.`,
  )];
});

rule('matcher-bad-regex', (entry) => {
  if (typeof entry.matcher !== 'string' || !entry.matcher) return [];
  const spec = EVENTS[entry.event];
  if (spec?.literalMatcher) return [];
  if (/^[a-zA-Z0-9_\-\s,|]+$/.test(entry.matcher)) return [];
  try {
    new RegExp(entry.matcher);
    return [];
  } catch (err) {
    return [finding(
      'matcher-bad-regex', ERROR, ALL,
      `Matcher "${entry.matcher}" is not a valid regular expression.`,
      String(err.message),
      'Matchers with any character outside letters, digits, _, -, space, comma and | are compiled as regexes. A glob like "*.ts" is not a regex; use ".*\\.ts$".',
    )];
  }
});

rule('if-on-non-tool-event', (entry) => {
  const spec = EVENTS[entry.event];
  if (!spec || spec.tool) return [];
  if (entry.handler?.if === undefined) return [];
  return [finding(
    'if-on-non-tool-event', WARN, ALL,
    `The "if" field has no effect on ${entry.event}.`,
    'Permission-rule filtering only applies to tool events.',
    'Remove "if", or move the check inside the hook.',
  )];
});

/* --- handler shape ------------------------------------------------------ */

rule('handler-type', (entry) => {
  const type = entry.handler?.type;
  if (type === undefined) {
    return [finding('handler-type', ERROR, ALL, 'Handler has no "type".', '', 'Add "type": "command".')];
  }
  if (HANDLER_TYPES.has(type)) return [];
  return [finding(
    'handler-type', ERROR, ALL,
    `Unknown handler type "${type}".`,
    `Supported: ${[...HANDLER_TYPES].join(', ')}.`,
    'Fix the type or remove the handler.',
  )];
});

rule('missing-command', (entry) => {
  if (entry.handler?.type !== 'command') return [];
  if (typeof entry.handler.command === 'string' && entry.handler.command.trim()) return [];
  return [finding('missing-command', ERROR, ALL, 'Command handler has no "command".', '', 'Add the command to run.')];
});

rule('exec-form-shell-syntax', (entry) => {
  const h = entry.handler;
  if (h?.type !== 'command' || !Array.isArray(h.args)) return [];
  const all = [h.command, ...h.args].filter((x) => typeof x === 'string').join(' ');
  const operator = all.match(/(&&|\|\||[|><]|\$\()/);
  if (!operator) return [];
  return [finding(
    'exec-form-shell-syntax', ERROR, ALL,
    `Exec form passes "${operator[0]}" to the program as a literal argument.`,
    'When "args" is present the handler is spawned directly, with no shell to interpret operators.',
    'Move the pipeline into a script file and call that script, or drop "args" to use shell form.',
  )];
});

rule('plugin-placeholder-outside-plugin', (entry) => {
  const h = entry.handler;
  const text = [h?.command, ...(Array.isArray(h?.args) ? h.args : [])].filter((x) => typeof x === 'string').join(' ');
  if (!/\$\{CLAUDE_PLUGIN_(ROOT|DATA)\}/.test(text)) return [];
  if (entry.file.includes(`${'plugins'}`)) return [];
  return [finding(
    'plugin-placeholder-outside-plugin', ERROR, ALL,
    'CLAUDE_PLUGIN_ROOT / CLAUDE_PLUGIN_DATA are only substituted for hooks that ship inside a plugin.',
    'In a settings.json hook the placeholder stays literal and the path will not resolve.',
    'Use ${CLAUDE_PROJECT_DIR} instead.',
  )];
});

rule('script-missing', (entry, ctx) => {
  const h = entry.handler;
  if (h?.type !== 'command' || typeof h.command !== 'string') return [];
  const raw = Array.isArray(h.args)
    ? [h.command, ...h.args].find((a) => typeof a === 'string' && /\.(mjs|cjs|js|ts|py|sh|ps1)$/.test(a))
    : (commandHeads(h.command).find((c) => /\.(mjs|cjs|js|ts|py|sh|ps1)$/.test(c)) ?? null);
  if (!raw) return [];
  if (/\$\{CLAUDE_PLUGIN_/.test(raw)) return [];
  const resolved = raw
    .replace(/\$\{CLAUDE_PROJECT_DIR\}/g, ctx.projectDir)
    .replace(/^["']|["']$/g, '');
  const candidate = resolved.startsWith('.') ? join(ctx.projectDir, resolved) : resolved;
  if (!/^([A-Za-z]:|\/|\\)/.test(candidate) && !candidate.includes(ctx.projectDir)) return [];
  if (existsSync(candidate)) return [];
  return [finding(
    'script-missing', ERROR, ALL,
    `Hook script not found: ${candidate}`,
    'A missing script makes the hook fail, and most events ignore a failing hook without telling you.',
    'Fix the path, or use ${CLAUDE_PROJECT_DIR} so it resolves from the repo root.',
  )];
});

rule('http-plaintext', (entry) => {
  const h = entry.handler;
  if (h?.type !== 'http' || typeof h.url !== 'string') return [];
  if (!/^http:\/\//i.test(h.url)) return [];
  if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(h.url)) return [];
  return [finding(
    'http-plaintext', WARN, ALL,
    'HTTP hook posts your prompts and tool inputs over plaintext http://.',
    h.url,
    'Use https://, or keep the endpoint on localhost.',
  )];
});

rule('http-env-not-allowed', (entry) => {
  const h = entry.handler;
  if (h?.type !== 'http' || !h.headers) return [];
  const allowed = new Set(Array.isArray(h.allowedEnvVars) ? h.allowedEnvVars : []);
  const missing = new Set();
  for (const value of Object.values(h.headers)) {
    if (typeof value !== 'string') continue;
    for (const m of value.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)) {
      if (!allowed.has(m[1])) missing.add(m[1]);
    }
  }
  if (missing.size === 0) return [];
  return [finding(
    'http-env-not-allowed', ERROR, ALL,
    `Header variables not listed in allowedEnvVars: ${[...missing].join(', ')}.`,
    'Unlisted variables are sent literally, so the endpoint receives the string "$TOKEN".',
    `Add "allowedEnvVars": [${[...missing].map((v) => `"${v}"`).join(', ')}].`,
  )];
});

/* --- timeouts and blocking --------------------------------------------- */

rule('exit-2-on-nonblockable', (entry) => {
  const spec = EVENTS[entry.event];
  if (!spec || spec.blockable) return [];
  const cmd = entry.handler?.command;
  if (typeof cmd !== 'string' || !/\bexit\s+2\b/.test(cmd)) return [];
  return [finding(
    'exit-2-on-nonblockable', WARN, ALL,
    `${entry.event} cannot be blocked, so "exit 2" here does not stop anything.`,
    'On non-blockable events exit 2 only surfaces stderr to the model.',
    spec.tool ? 'To deny a tool call, hook PreToolUse instead.' : 'Move the check to a blockable event.',
  )];
});

rule('slow-hook-no-timeout', (entry) => {
  const h = entry.handler;
  if (h?.type !== 'command' || typeof h.command !== 'string') return [];
  if (h.timeout !== undefined || h.async === true) return [];
  const slow = h.command.match(/\b(npm|pnpm|yarn|bun|cargo|go|gradle|mvn|pytest|jest|vitest|tsc|docker|terraform|pip|poetry|uv)\b/);
  if (!slow) return [];
  const spec = EVENTS[entry.event];
  return [finding(
    'slow-hook-no-timeout', WARN, ALL,
    `"${slow[1]}" runs with no timeout, so a hang freezes the session for up to ${spec?.timeout ?? 600}s.`,
    'Hooks run synchronously unless marked async.',
    'Add "timeout": 60, or "async": true when you do not need the result.',
  )];
});

rule('recursion-risk', (entry) => {
  if (entry.event !== 'PostToolUse' && entry.event !== 'PreToolUse') return [];
  const matcher = typeof entry.matcher === 'string' ? entry.matcher : '';
  if (!/(^|\|)\s*Bash\s*(\||$)|^\*?$/.test(matcher)) return [];
  const cmd = entry.handler?.command;
  if (typeof cmd !== 'string') return [];
  if (!/\b(claude|npx\s+claude)\b/.test(cmd)) return [];
  return [finding(
    'recursion-risk', ERROR, ALL,
    'This hook invokes Claude Code from inside a Bash tool hook, which can recurse.',
    'The nested run issues its own Bash calls, each firing this hook again.',
    'Guard with an environment flag, or narrow the matcher so the hook cannot see its own commands.',
  )];
});

/* --- Windows shell portability ----------------------------------------- */

rule('posix-devnull', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  if (!/\/dev\/null/.test(entry.handler.command)) return [];
  return [finding(
    'posix-devnull', ERROR, WIN,
    '/dev/null does not exist on Windows.',
    'PowerShell writes a file literally named "null" instead of discarding output.',
    'Use exec form and discard output in your script, or write $null in PowerShell.',
  )];
});

rule('posix-tmp', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const m = entry.handler.command.match(/(^|[\s"'=])(\/tmp\/[^\s"';|]*)/);
  if (!m) return [];
  return [finding(
    'posix-tmp', ERROR, WIN,
    `"${m[2]}" is a POSIX-only path.`,
    'Windows has no /tmp; the write fails or lands somewhere unexpected.',
    'Resolve a temp directory in code (os.tmpdir() in Node, tempfile in Python).',
  )];
});

rule('ps-chain-operators', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const m = entry.handler.command.match(/&&|\|\|/);
  if (!m) return [];
  return [finding(
    'ps-chain-operators', ERROR, WIN,
    `"${m[0]}" is a parser error in Windows PowerShell 5.1, which ships with Windows.`,
    'Chain operators only arrived in PowerShell 7. The whole hook fails to parse, so nothing runs.',
    'Put the steps in a script file and call it with exec form.',
  )];
});

rule('unbraced-variable', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const cmd = stripPlaceholders(entry.handler.command);
  const m = cmd.match(/\$(?!\{)([A-Za-z_][A-Za-z0-9_]*)/);
  if (!m) return [];
  const isClaudeVar = /^CLAUDE_/.test(m[1]);
  return [finding(
    'unbraced-variable', ERROR, WIN,
    `"$${m[1]}" is expanded by PowerShell, not by the shell you wrote this for.`,
    isClaudeVar
      ? `PowerShell has no $${m[1]} variable, so it expands to an empty string and the path collapses.`
      : 'An undefined PowerShell variable silently becomes an empty string.',
    isClaudeVar
      ? `Write \${${m[1]}} with braces. Claude Code substitutes that placeholder itself, before any shell sees it.`
      : 'Read the value inside your script instead of interpolating it in the command string.',
  )];
});

rule('heredoc', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  if (!/<<-?\s*['"]?[A-Za-z_]/.test(entry.handler.command)) return [];
  return [finding(
    'heredoc', ERROR, WIN,
    'Heredoc syntax is a parser error in PowerShell.',
    'PowerShell uses @" ... "@ here-strings with different rules.',
    'Move the text into a file, or pass it on stdin from a script.',
  )];
});

rule('backtick-substitution', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  if (!/`[^`]+`/.test(entry.handler.command)) return [];
  return [finding(
    'backtick-substitution', ERROR, WIN,
    'Backtick command substitution means the opposite in PowerShell.',
    'The backtick is the PowerShell escape character, so the command is mangled rather than executed.',
    'Use a script file, or $(...) if you are targeting sh only.',
  )];
});

rule('dollar-paren', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const cmd = stripPlaceholders(entry.handler.command);
  if (!/\$\([^)]*\)/.test(cmd)) return [];
  return [finding(
    'dollar-paren', ERROR, WIN,
    '$(...) runs as a PowerShell subexpression on Windows, not a shell command substitution.',
    'PowerShell evaluates the contents as PowerShell, so shell utilities inside it break.',
    'Compute the value inside a script and pass it with exec form.',
  )];
});

rule('inline-env-assignment', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const cmd = entry.handler.command.trim();
  const m = cmd.match(/^(export\s+[A-Za-z_][A-Za-z0-9_]*=|[A-Za-z_][A-Za-z0-9_]*=\S*\s+\S)/);
  if (!m) return [];
  return [finding(
    'inline-env-assignment', ERROR, WIN,
    'Inline environment assignment is not PowerShell syntax.',
    'PowerShell sets variables with $env:NAME = "value"; there is no FOO=bar prefix form.',
    'Set the variable inside your script, or use exec form and pass it as a flag.',
  )];
});

rule('posix-only-binary', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const heads = commandHeads(stripPlaceholders(entry.handler.command));
  const hits = [...new Set(heads.filter((h) => POSIX_ONLY_BINARIES.includes(h.replace(/^.*[\\/]/, ''))))];
  if (hits.length === 0) return [];
  return hits.map((bin) => finding(
    'posix-only-binary', ERROR, WIN,
    `"${bin}" is not available in a stock Windows shell.`,
    'The hook exits non-zero, and most events ignore a failing hook without surfacing anything.',
    bin === 'jq'
      ? 'Parse the hook JSON in Node instead: it is already on the machine, because Claude Code needs it.'
      : `Replace ${bin} with equivalent logic in a Node or Python script and call it with exec form.`,
  ));
});

rule('powershell-alias-shadow', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const heads = commandHeads(stripPlaceholders(entry.handler.command));
  const hits = [...new Set(heads.map((h) => h.replace(/^.*[\\/]/, '')).filter((h) => PS_ALIASES[h]))];
  if (hits.length === 0) return [];
  return hits.map((bin) => {
    const { cmdlet, exe } = PS_ALIASES[bin];
    return finding(
      'powershell-alias-shadow',
      bin === 'curl' || bin === 'wget' ? ERROR : WARN,
      WIN,
      `"${bin}" is a PowerShell alias for ${cmdlet}.`,
      'Nothing errors. The hook runs and quietly does something different, which is why this class is so hard to notice.',
      exe
        ? `Call ${exe} by name, which bypasses the alias, or do the work in a script and use exec form.`
        : `Windows ships no ${bin} executable, so there is nothing to fall back to. Do the work in a Node script and call it with exec form.`,
    );
  });
});

rule('shell-script-direct', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const heads = commandHeads(entry.handler.command);
  const hit = heads.find((h) => /\.sh(["']?)$/.test(h));
  if (!hit) return [];
  return [finding(
    'shell-script-direct', ERROR, WIN,
    `"${hit}" is invoked directly, which Windows cannot do.`,
    'Windows has no shebang handling and no execute bit, so PowerShell does not know how to start a .sh file.',
    'Rewrite the script in Node and call it as "command": "node", "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/x.mjs"].',
  )];
});

rule('python3-binary', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const heads = commandHeads(entry.handler.command);
  if (!heads.some((h) => h.replace(/^.*[\\/]/, '') === 'python3')) return [];
  return [finding(
    'python3-binary', ERROR, WIN,
    '"python3" on Windows usually hits the Microsoft Store stub, not your interpreter.',
    'The stub opens the Store and exits, so the hook never runs.',
    'Use exec form with "command": "python" (or the "py" launcher), and pin the script in "args".',
  )];
});

rule('native-stderr-redirect', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  if (!/2>&1/.test(entry.handler.command)) return [];
  return [finding(
    'native-stderr-redirect', WARN, WIN,
    '2>&1 on a native executable is unreliable in Windows PowerShell 5.1.',
    'PowerShell wraps each stderr line in an ErrorRecord and flips the success flag even when the program exited 0.',
    'Let the process write stderr through, and read it from your script instead.',
  )];
});

rule('tilde-home', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  if (!/(^|[\s"'=])~[\\/]/.test(entry.handler.command)) return [];
  return [finding(
    'tilde-home', WARN, WIN,
    '~ is not expanded for native executables on Windows.',
    'PowerShell expands ~ for its own cmdlets, but passes it through literally to other programs.',
    'Resolve the home directory in your script with os.homedir().',
  )];
});

rule('windows-only-syntax', (entry) => {
  if (!isShellForm(entry.handler)) return [];
  const cmd = entry.handler.command;
  const hits = [];
  if (/%[A-Za-z_][A-Za-z0-9_]*%/.test(cmd)) hits.push('%VAR% expansion');
  if (/\$env:/.test(cmd)) hits.push('$env: variables');
  if (/(^|\s)(cmd(\.exe)?\s+\/c|powershell(\.exe)?\s)/i.test(cmd)) hits.push('an explicit Windows shell');
  if (/(^|[\s"'=])[A-Za-z]:\\/.test(cmd)) hits.push('a drive-letter path');
  if (/(^|\s)(NUL|nul)(\s|$)/.test(cmd)) hits.push('NUL');
  if (hits.length === 0) return [];
  return [finding(
    'windows-only-syntax', ERROR, POSIX,
    `This hook uses ${hits.join(', ')}, which does not work on macOS or Linux.`,
    'Anyone on the team who is not on Windows silently loses this hook.',
    'Move the logic into a Node script and call it with exec form so both sides run the same code.',
  )];
});

rule('unquoted-path-with-space', (entry) => {
  const h = entry.handler;
  if (!isShellForm(h)) return [];
  const masked = maskQuoted(h.command);
  const m = masked.match(/(^|\s)((?:[A-Za-z]:[\\/]|\/)[^\s"']*\s[^\s"']*)/);
  if (!m) return [];
  return [finding(
    'unquoted-path-with-space', ERROR, ALL,
    'Unquoted path containing a space.',
    'The shell splits it into two arguments. This bites hardest under paths like C:\\Users\\me\\My Projects.',
    'Quote the path, or switch to exec form where each argument is passed intact.',
  )];
});

/* --- the general recommendation ---------------------------------------- */

rule('prefer-exec-form', (entry, ctx) => {
  if (!isShellForm(entry.handler)) return [];
  // Only nudge when the command is doing something a shell is needed for.
  const cmd = entry.handler.command;
  const needsShell = /(&&|\|\||[|><]|\$\(|`)/.test(stripPlaceholders(cmd));
  if (!needsShell) return [];
  if (ctx.findingsForEntry?.some((f) => f.severity === ERROR)) return [];
  return [finding(
    'prefer-exec-form', INFO, ALL,
    'Shell form runs under sh on macOS and Linux but PowerShell on Windows.',
    'Any shell operator in the string is interpreted by two different languages.',
    'Add an "args" array to switch to exec form; the program is then spawned directly on every platform.',
  )];
});

/**
 * Run every rule over every collected hook entry.
 * `target` narrows results to one platform, or 'all' to report everything.
 */
export function analyze(collected, { target = 'all' } = {}) {
  const ctx = { files: collected.files, projectDir: collected.projectDir };
  const results = [];
  const seenFiles = new Set();

  for (const entry of collected.entries) {
    const forEntry = [];
    ctx.findingsForEntry = forEntry;
    for (const r of RULES) {
      if (r.id === 'json-strict') continue; // file-level, handled below
      let produced;
      try {
        produced = r.run(entry, ctx) ?? [];
      } catch (err) {
        produced = [finding(r.id, INFO, ALL, `Rule ${r.id} could not run.`, String(err.message), '')];
      }
      forEntry.push(...produced);
    }
    for (const f of forEntry) {
      if (target !== 'all' && !f.platforms.includes(target)) continue;
      results.push({ ...f, entry });
    }
  }

  // File-level findings, once per file.
  for (const file of collected.files) {
    if (file.strict === false && !seenFiles.has(file.file)) {
      seenFiles.add(file.file);
      results.push({
        ...finding(
          'json-strict', ERROR, ALL,
          'This settings file is not valid JSON, so Claude Code loads none of its hooks.',
          file.strictError ? String(file.strictError.message) : 'Trailing comma or comment.',
          'Remove comments and trailing commas. settings.json is strict JSON, not JSONC.',
        ),
        entry: { file: file.file, scope: file.scope, event: '-', pointer: '-', line: null },
      });
    }
  }

  const rank = { error: 0, warn: 1, info: 2 };
  results.sort((a, b) => rank[a.severity] - rank[b.severity] || a.entry.file.localeCompare(b.entry.file));
  return results;
}
