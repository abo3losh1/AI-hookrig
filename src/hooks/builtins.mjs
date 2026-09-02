/**
 * Built-in hooks.
 *
 * Every one of these is plain Node with no dependencies, so it behaves the
 * same on Windows, macOS and Linux. Compose them in
 * .claude/hooks/hookrig.config.mjs:
 *
 *   import { protectSecrets, blockDangerousBash } from './hookrig/builtins.mjs';
 *   export default { hooks: { PreToolUse: [protectSecrets(), blockDangerousBash()] } };
 */

import { appendFileSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { dirname, join, relative, isAbsolute } from 'node:path';

/* -------------------------------------------------------------------------
 * Small glob matcher. Supports *, **, ? and {a,b}. Enough for path rules,
 * and it avoids pulling a dependency into a file people have to trust.
 * ---------------------------------------------------------------------- */

export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
        if (glob[i + 1] === '/') i++;
      } else {
        re += '[^/]*';
      }
    } else if (ch === '?') re += '[^/]';
    else if (ch === '{') re += '(?:';
    else if (ch === '}') re += ')';
    else if (ch === ',') re += '|';
    else re += ch.replace(/[.+^$()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`, 'i');
}

function normalize(p) {
  return String(p).split('\\').join('/');
}

export function matchesAnyGlob(filePath, globs, projectDir) {
  if (!filePath) return false;
  const abs = normalize(filePath);
  const rel = projectDir && isAbsolute(filePath) ? normalize(relative(projectDir, filePath)) : abs;
  const base = abs.split('/').pop();
  return globs.some((g) => {
    const re = globToRegExp(normalize(g));
    return re.test(abs) || re.test(rel) || re.test(base) || re.test(`./${rel}`);
  });
}

/** File paths a tool call touches, across the tools that take one. */
export function touchedPaths(input) {
  const ti = input.tool_input ?? {};
  const out = [];
  for (const key of ['file_path', 'path', 'notebook_path', 'filePath']) {
    if (typeof ti[key] === 'string') out.push(ti[key]);
  }
  if (Array.isArray(ti.edits)) {
    for (const e of ti.edits) if (typeof e?.file_path === 'string') out.push(e.file_path);
  }
  return out;
}

/* -------------------------------------------------------------------------
 * protectSecrets
 * ---------------------------------------------------------------------- */

const DEFAULT_SECRET_GLOBS = [
  '**/.env', '**/.env.*', '!**/.env.example',
  '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx',
  '**/id_rsa', '**/id_ed25519', '**/id_ecdsa',
  '**/.npmrc', '**/.pypirc', '**/.netrc',
  '**/credentials.json', '**/service-account*.json',
  '**/.aws/credentials', '**/.ssh/**',
  '**/secrets.*', '**/*.keystore', '**/*.jks',
];

/**
 * Stop the agent reading or writing credential files.
 *
 * Claude Code already refuses some of these, but the deny list is yours and
 * it also covers Bash commands that would cat or copy the file.
 */
export function protectSecrets({ globs = DEFAULT_SECRET_GLOBS, allow = [] } = {}) {
  const deny = globs.filter((g) => !g.startsWith('!'));
  const exempt = [...allow, ...globs.filter((g) => g.startsWith('!')).map((g) => g.slice(1))];

  return (input, ctx) => {
    const paths = touchedPaths(input);

    if (input.tool_name === 'Bash') {
      const command = String(input.tool_input?.command ?? '');
      const hit = deny
        .map((g) => g.replace(/^\*\*\//, ''))
        .filter((g) => !g.includes('*'))
        .find((name) => command.includes(name));
      if (hit && !exempt.some((e) => command.includes(e.replace(/^\*\*\//, '')))) {
        return ctx.deny(`This command references ${hit}, which hookrig protects. Read it yourself if you need the value.`);
      }
      return ctx.pass();
    }

    for (const p of paths) {
      if (matchesAnyGlob(p, exempt, ctx.projectDir)) continue;
      if (matchesAnyGlob(p, deny, ctx.projectDir)) {
        return ctx.deny(`${p} holds credentials and is protected by hookrig. Ask the user for the value instead of opening the file.`);
      }
    }
    return ctx.pass();
  };
}

/* -------------------------------------------------------------------------
 * blockDangerousBash
 * ---------------------------------------------------------------------- */

const DANGEROUS = [
  { re: /\brm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rR][a-zA-Z]*f|\brm\s+-f[a-zA-Z]*[rR]/, why: 'recursive force delete' },
  { re: /\brm\s+-rf?\s+[/~]\s*$/, why: 'delete of the filesystem root or home' },
  { re: /\bgit\s+push\b[^\n]*\s--force(?!-with-lease)\b/, why: 'force push that can discard other people\u2019s commits' },
  { re: /\bgit\s+push\b[^\n]*\s-f\b/, why: 'force push that can discard other people\u2019s commits' },
  { re: /\bgit\s+reset\s+--hard\b/, why: 'hard reset that throws away uncommitted work' },
  { re: /\bgit\s+clean\s+-[a-zA-Z]*[dfx]/, why: 'clean that deletes untracked files' },
  { re: /\b(curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(sudo\s+)?(ba|z|)sh\b/, why: 'piping a downloaded script straight into a shell' },
  { re: /\bchmod\s+(-R\s+)?777\b/, why: 'world-writable permissions' },
  { re: /\bmkfs(\.[a-z0-9]+)?\b|\bdd\s+[^\n]*\bof=\/dev\//, why: 'writing directly to a block device' },
  { re: /\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)\b/i, why: 'destructive SQL' },
  { re: /\bnpm\s+publish\b|\bcargo\s+publish\b|\btwine\s+upload\b/, why: 'publishing a package to a public registry' },
  { re: /\b(shutdown|reboot|halt)\b/, why: 'shutting down the machine' },
  { re: /\bhistory\s+-c\b|\b>\s*~\/\.bash_history\b/, why: 'clearing shell history' },
];

/**
 * Deny the Bash commands that are hard or impossible to undo.
 *
 * `extra` adds patterns, `allow` exempts commands that match a pattern you
 * genuinely need (a deploy script that force-pushes a docs branch, say).
 */
export function blockDangerousBash({ extra = [], allow = [], ask = false } = {}) {
  const rules = [...DANGEROUS, ...extra.map((e) => (e instanceof RegExp ? { re: e, why: 'matched a project rule' } : e))];
  const allowRes = allow.map((a) => (a instanceof RegExp ? a : new RegExp(a)));

  return {
    match: { tool: 'Bash' },
    run(input, ctx) {
      const command = String(input.tool_input?.command ?? '');
      if (!command) return ctx.pass();
      if (allowRes.some((re) => re.test(command))) return ctx.pass();

      for (const rule of rules) {
        if (!rule.re.test(command)) continue;
        const message = `hookrig blocked this command: ${rule.why}.`;
        if (ask) return ctx.context(`${message} Confirm with the user before retrying.`);
        return ctx.deny(`${message}\n\n  ${command}\n\nIf this is intentional, ask the user to run it themselves.`);
      }
      return ctx.pass();
    },
  };
}

/* -------------------------------------------------------------------------
 * protectPaths
 * ---------------------------------------------------------------------- */

/** Make a set of paths read-only, or off limits entirely, for the agent. */
export function protectPaths({ globs = [], mode = 'write', reason } = {}) {
  const writeTools = new Set(['Edit', 'Write', 'NotebookEdit', 'MultiEdit']);
  return (input, ctx) => {
    if (mode === 'write' && !writeTools.has(input.tool_name)) return ctx.pass();
    for (const p of touchedPaths(input)) {
      if (matchesAnyGlob(p, globs, ctx.projectDir)) {
        return ctx.deny(reason ?? `${p} is protected by hookrig and must be edited by a human.`);
      }
    }
    return ctx.pass();
  };
}

/* -------------------------------------------------------------------------
 * formatOnWrite
 * ---------------------------------------------------------------------- */

/**
 * Run a formatter after the agent writes a file.
 *
 * `commands` maps a glob to an argv array. The file path is appended, and the
 * process is spawned directly, so there is no shell and no quoting problem
 * even under a path like C:\Users\me\My Projects.
 */
export function formatOnWrite({ commands = {}, timeout = 20000 } = {}) {
  const pairs = Object.entries(commands).map(([glob, argv]) => [globToRegExp(normalize(glob)), argv]);

  return {
    match: { tool: 'Edit|Write|MultiEdit|NotebookEdit' },
    async run(input, ctx) {
      const ran = [];
      for (const p of touchedPaths(input)) {
        const norm = normalize(p);
        const base = norm.split('/').pop();
        for (const [re, argv] of pairs) {
          if (!re.test(norm) && !re.test(base)) continue;
          const ok = await run(argv[0], [...argv.slice(1), p], { cwd: ctx.projectDir, timeout });
          ran.push(`${argv[0]} ${base}${ok ? '' : ' (failed)'}`);
        }
      }
      return ran.length ? ctx.message(`hookrig: ${ran.join(', ')}`) : ctx.pass();
    },
  };
}

function run(command, args, { cwd, timeout }) {
  return new Promise((resolve) => {
    // shell:false is deliberate. Spawning directly is what makes this portable.
    const child = spawn(command, args, { cwd, shell: false, stdio: 'ignore', windowsHide: true });
    const timer = setTimeout(() => child.kill(), timeout);
    child.on('error', () => { clearTimeout(timer); resolve(false); });
    child.on('close', (code) => { clearTimeout(timer); resolve(code === 0); });
  });
}

/* -------------------------------------------------------------------------
 * auditLog
 * ---------------------------------------------------------------------- */

/** Append one JSON line per event, so you can see what the agent did. */
export function auditLog({ file = '.claude/hookrig-audit.jsonl', fields } = {}) {
  return (input, ctx) => {
    const record = fields
      ? fields(input, ctx)
      : {
          at: new Date().toISOString(),
          event: ctx.event,
          session: input.session_id,
          tool: input.tool_name,
          paths: touchedPaths(input),
          command: input.tool_input?.command,
        };
    try {
      const target = isAbsolute(file) ? file : join(ctx.projectDir, file);
      mkdirSync(dirname(target), { recursive: true });
      appendFileSync(target, `${JSON.stringify(record)}\n`);
    } catch {
      // Never let logging break a session.
    }
    return ctx.pass();
  };
}

/* -------------------------------------------------------------------------
 * notify
 * ---------------------------------------------------------------------- */

/**
 * Tell the user the agent wants them.
 *
 * The terminal bell is the only notification channel that works everywhere
 * with no dependency, so that is the default. `command` is the escape hatch
 * for a real desktop notifier, and it is spawned directly rather than through
 * a shell.
 */
export function notify({ bell = true, message = 'Claude needs you.', command } = {}) {
  return async (input, ctx) => {
    if (command) {
      const argv = Array.isArray(command) ? command : [command];
      await run(argv[0], argv.slice(1), { cwd: ctx.projectDir, timeout: 5000 });
    }
    const result = ctx.message(message);
    if (bell) result.terminalSequence = '\u0007';
    return result;
  };
}

/* -------------------------------------------------------------------------
 * addContext
 * ---------------------------------------------------------------------- */

/** Inject text into the model's context. `text` may be a function. */
export function addContext(text) {
  return async (input, ctx) => {
    const value = typeof text === 'function' ? await text(input, ctx) : text;
    return value ? ctx.context(String(value)) : ctx.pass();
  };
}
