import { readFileSync, existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join, resolve } from 'node:path';

/**
 * Every settings file Claude Code merges hooks from, most-general first.
 * Hooks from all of these are additive, so a broken hook in any one of them
 * is a broken hook in your session.
 */
export function settingsFiles(projectDir = process.cwd()) {
  const home = homedir();
  const files = [];

  const managed = managedPath();
  if (managed) files.push({ scope: 'managed', file: managed });

  files.push({ scope: 'user', file: join(home, '.claude', 'settings.json') });
  files.push({ scope: 'project', file: join(projectDir, '.claude', 'settings.json') });
  files.push({ scope: 'local', file: join(projectDir, '.claude', 'settings.local.json') });

  return files.filter((f) => existsSync(f.file));
}

function managedPath() {
  if (platform() === 'win32') {
    const programData = process.env.PROGRAMDATA;
    return programData ? join(programData, 'ClaudeCode', 'managed-settings.json') : null;
  }
  if (platform() === 'darwin') return '/Library/Application Support/ClaudeCode/managed-settings.json';
  return '/etc/claude-code/managed-settings.json';
}

/**
 * Parse a settings file. Reports whether strict JSON.parse succeeded, because
 * Claude Code uses a strict parser: a stray trailing comma silently drops
 * every hook in the file.
 */
export function parseSettings(file) {
  const raw = readFileSync(file, 'utf8');
  try {
    return { data: JSON.parse(raw), strict: true, raw };
  } catch (strictError) {
    try {
      return { data: JSON.parse(tolerant(raw)), strict: false, raw, strictError };
    } catch {
      return { data: null, strict: false, raw, strictError };
    }
  }
}

/** Strip line and block comments plus trailing commas, ignoring string bodies. */
function tolerant(text) {
  let out = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c.charCodeAt(0) === 92) escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

/**
 * Flatten `settings.hooks` into one record per handler, keeping enough
 * location detail to point a human at the exact line.
 */
export function collectHooks(projectDir = process.cwd()) {
  const entries = [];
  const files = [];

  for (const { scope, file } of settingsFiles(projectDir)) {
    let parsed;
    try {
      parsed = parseSettings(file);
    } catch (err) {
      files.push({ scope, file, error: err.message });
      continue;
    }
    files.push({ scope, file, strict: parsed.strict, strictError: parsed.strictError, data: parsed.data, raw: parsed.raw });
    if (!parsed.data || typeof parsed.data.hooks !== 'object' || parsed.data.hooks === null) continue;

    for (const [event, groups] of Object.entries(parsed.data.hooks)) {
      if (!Array.isArray(groups)) continue;
      groups.forEach((group, groupIndex) => {
        const handlers = Array.isArray(group?.hooks) ? group.hooks : [];
        handlers.forEach((handler, handlerIndex) => {
          entries.push({
            scope,
            file,
            event,
            matcher: group?.matcher,
            handler,
            pointer: `hooks.${event}[${groupIndex}].hooks[${handlerIndex}]`,
            line: findLine(parsed.raw, handler),
          });
        });
      });
    }
  }

  return { entries, files, projectDir: resolve(projectDir) };
}

/** Best-effort line number for a handler, by searching for its command text. */
function findLine(raw, handler) {
  const needle = handler?.command ?? handler?.url ?? handler?.tool ?? handler?.prompt;
  if (typeof needle !== 'string' || !needle) return null;
  const escaped = JSON.stringify(needle).slice(1, -1);
  const index = raw.indexOf(escaped);
  if (index === -1) return null;
  return raw.slice(0, index).split('\n').length;
}
