import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { EVENTS } from './events.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const VENDORED = [
  ['runner/runtime.mjs', 'runtime.mjs'],
  ['runner/run.mjs', 'run.mjs'],
  ['hooks/builtins.mjs', 'builtins.mjs'],
];

const CONFIG_TEMPLATE = `/**
 * hookrig configuration.
 *
 * Handlers are plain functions. They receive the hook input Claude Code sends
 * on stdin, plus a context with helpers, and return a decision. hookrig turns
 * that decision into the JSON shape and exit code the event expects, so you do
 * not have to remember which events use permissionDecision and which use
 * shouldBlock.
 *
 * Run \`npx hookrig init\` again after changing the event names below; it
 * rewrites the matching entries in .claude/settings.json.
 */

import {
  protectSecrets,
  blockDangerousBash,
  auditLog,
  notify,
} from './hookrig/builtins.mjs';

export default {
  hooks: {
    PreToolUse: [
      protectSecrets(),
      blockDangerousBash(),
    ],

    PostToolUse: [
      auditLog(),
    ],

    Stop: [
      notify({ message: 'Claude finished.' }),
    ],
  },
};
`;

const GITIGNORE_LINES = [
  '.claude/hookrig-audit.jsonl',
  '.claude/hookrig-errors.log',
];

export async function init({ dir = process.cwd(), force = false } = {}) {
  const claudeDir = join(dir, '.claude');
  const hooksDir = join(claudeDir, 'hooks');
  const vendorDir = join(hooksDir, 'hookrig');
  const configPath = join(hooksDir, 'hookrig.config.mjs');
  const settingsPath = join(claudeDir, 'settings.json');

  mkdirSync(vendorDir, { recursive: true });

  for (const [from, to] of VENDORED) {
    copyFileSync(join(HERE, from), join(vendorDir, to));
  }
  log(`runtime      .claude/hooks/hookrig/  (${VENDORED.length} files, no dependencies)`);

  if (!existsSync(configPath) || force) {
    writeFileSync(configPath, CONFIG_TEMPLATE);
    log(`config       .claude/hooks/hookrig.config.mjs${force ? ' (overwritten)' : ''}`);
  } else {
    log('config       .claude/hooks/hookrig.config.mjs (kept)');
  }

  const events = await readConfigEvents(configPath);
  if (events.length === 0) {
    log('');
    log('No events declared in the config, so settings.json was left alone.');
    return 0;
  }

  const unknown = events.filter((e) => !EVENTS[e]);
  for (const e of unknown) {
    log(`warning      "${e}" is not a Claude Code hook event and will never fire`);
  }

  const written = syncSettings(settingsPath, events);
  log(`settings     .claude/settings.json  (${written.join(', ')})`);
  log('');
  log('Hooks are registered in exec form, so no shell runs them on any platform.');
  log('Add the log files to .gitignore:');
  for (const line of GITIGNORE_LINES) log(`  ${line}`);
  return 0;
}

async function readConfigEvents(configPath) {
  try {
    const mod = await import(`${pathToFileURL(configPath).href}?t=${Date.now()}`);
    const hooks = mod.default?.hooks ?? {};
    return Object.keys(hooks).filter((event) => Array.isArray(hooks[event]) && hooks[event].length > 0);
  } catch (err) {
    log(`warning      could not read the config: ${err.message}`);
    return [];
  }
}

/**
 * Point each declared event at the runtime, in exec form, without disturbing
 * any other hook the project already has.
 */
export function syncSettings(settingsPath, events) {
  let settings = {};
  if (existsSync(settingsPath)) {
    const raw = readFileSync(settingsPath, 'utf8');
    try {
      settings = raw.trim() ? JSON.parse(raw) : {};
    } catch (err) {
      throw new Error(`${settingsPath} is not valid JSON (${err.message}). Fix it before running init.`);
    }
  }

  settings.hooks ??= {};
  const written = [];

  for (const event of events) {
    const groups = Array.isArray(settings.hooks[event]) ? settings.hooks[event] : [];
    const others = groups
      .map((group) => ({
        ...group,
        hooks: (Array.isArray(group.hooks) ? group.hooks : []).filter((h) => !isHookrigHandler(h)),
      }))
      .filter((group) => group.hooks.length > 0);

    settings.hooks[event] = [...others, { hooks: [handlerFor(event)] }];
    written.push(event);
  }

  mkdirSync(dirname(settingsPath), { recursive: true });
  writeFileSync(settingsPath, `${JSON.stringify(settings, null, 2)}\n`);
  return written;
}

export function handlerFor(event) {
  return {
    type: 'command',
    command: 'node',
    args: ['${CLAUDE_PROJECT_DIR}/.claude/hooks/hookrig/run.mjs', event],
    timeout: 30,
  };
}

function isHookrigHandler(handler) {
  const args = Array.isArray(handler?.args) ? handler.args : [];
  return args.some((a) => typeof a === 'string' && a.includes('hookrig/run.mjs'));
}

function log(line) {
  process.stdout.write(`${line}\n`);
}
