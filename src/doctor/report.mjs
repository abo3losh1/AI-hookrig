import { relative } from 'node:path';

const COLOR = process.env.NO_COLOR === undefined && process.stdout.isTTY;

const c = {
  dim: (s) => (COLOR ? `\u001b[2m${s}\u001b[0m` : s),
  bold: (s) => (COLOR ? `\u001b[1m${s}\u001b[0m` : s),
  red: (s) => (COLOR ? `\u001b[31m${s}\u001b[0m` : s),
  yellow: (s) => (COLOR ? `\u001b[33m${s}\u001b[0m` : s),
  blue: (s) => (COLOR ? `\u001b[34m${s}\u001b[0m` : s),
  green: (s) => (COLOR ? `\u001b[32m${s}\u001b[0m` : s),
};

const LABEL = {
  error: (s) => c.red(s),
  warn: (s) => c.yellow(s),
  info: (s) => c.blue(s),
};

const PLATFORM_LABEL = {
  win32: 'Windows',
  darwin: 'macOS',
  linux: 'Linux',
};

function platforms(list) {
  if (list.length === 3) return 'all platforms';
  return list.map((p) => PLATFORM_LABEL[p] ?? p).join(' and ');
}

export function renderText(findings, collected, { target = 'all' } = {}) {
  const lines = [];
  const cwd = collected.projectDir;

  const scanned = collected.files.length;
  const hooks = collected.entries.length;
  lines.push('');
  lines.push(c.bold('hookrig doctor'));
  lines.push(
    c.dim(`  ${hooks} hook${hooks === 1 ? '' : 's'} across ${scanned} settings file${scanned === 1 ? '' : 's'}`) +
      (target === 'all' ? '' : c.dim(`  |  target ${PLATFORM_LABEL[target] ?? target}`)),
  );
  for (const f of collected.files) {
    lines.push(c.dim(`  ${f.scope.padEnd(8)} ${short(f.file, cwd)}`));
  }
  lines.push('');

  if (hooks === 0) {
    // Saying "no problems found" here would claim a check that never ran.
    lines.push('  No hooks configured, so there is nothing to check.');
    lines.push(c.dim('  Run "hookrig init" to add cross-platform hooks to this project.'));
    lines.push('');
    return lines.join('\n');
  }

  if (findings.length === 0) {
    lines.push(c.green('  No problems found. Your hooks are portable.'));
    lines.push('');
    return lines.join('\n');
  }

  let currentFile = null;
  for (const f of findings) {
    const file = f.entry.file;
    if (file !== currentFile) {
      currentFile = file;
      lines.push(c.bold(short(file, cwd)));
    }
    const where = f.entry.line ? `:${f.entry.line}` : '';
    const tag = LABEL[f.severity](f.severity.toUpperCase().padEnd(5));
    lines.push(`  ${tag} ${c.bold(f.message)}`);
    lines.push(`        ${c.dim(`${f.entry.event}  ${f.entry.pointer}${where}  |  breaks on ${platforms(f.platforms)}  |  ${f.id}`)}`);
    if (f.detail) lines.push(`        ${f.detail}`);
    if (f.fix) lines.push(`        ${c.green('fix')} ${f.fix}`);
    lines.push('');
  }

  const counts = tally(findings);
  const summary = [
    counts.error ? c.red(`${counts.error} error${counts.error === 1 ? '' : 's'}`) : null,
    counts.warn ? c.yellow(`${counts.warn} warning${counts.warn === 1 ? '' : 's'}`) : null,
    counts.info ? c.blue(`${counts.info} note${counts.info === 1 ? '' : 's'}`) : null,
  ].filter(Boolean).join(c.dim('  |  '));
  lines.push(summary);
  lines.push('');

  return lines.join('\n');
}

export function renderJson(findings, collected) {
  return JSON.stringify(
    {
      projectDir: collected.projectDir,
      settingsFiles: collected.files.map((f) => ({ scope: f.scope, file: f.file, validJson: f.strict !== false })),
      hookCount: collected.entries.length,
      summary: tally(findings),
      findings: findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        platforms: f.platforms,
        message: f.message,
        detail: f.detail,
        fix: f.fix,
        scope: f.entry.scope,
        file: f.entry.file,
        line: f.entry.line,
        event: f.entry.event,
        pointer: f.entry.pointer,
      })),
    },
    null,
    2,
  );
}

export function tally(findings) {
  const counts = { error: 0, warn: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

function short(file, cwd) {
  const rel = relative(cwd, file);
  return !rel.startsWith('..') && rel.length < file.length ? rel.split('\\').join('/') : file.split('\\').join('/');
}
