#!/usr/bin/env node
import { collectHooks } from '../src/doctor/settings.mjs';
import { analyze } from '../src/doctor/rules.mjs';
import { renderText, renderJson, tally } from '../src/doctor/report.mjs';
import { EVENTS, EVENT_NAMES } from '../src/events.mjs';
import { init } from '../src/init.mjs';

const USAGE = `
hookrig - Claude Code hooks that actually fire on Windows

  hookrig doctor            Find hooks that break on Windows, macOS or Linux
  hookrig list              Show every hook Claude Code will load, and from where
  hookrig events            Print the hook event reference
  hookrig init              Install the cross-platform runner into this project

Options
  --dir <path>              Project directory to scan (default: cwd)
  --target <platform>       win32 | darwin | linux | all   (default: all)
  --json                    Machine-readable output
  --quiet                   Errors only
  --version                 Print version

Exit codes
  0  no errors
  1  at least one error-level finding
`;

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') args.json = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--version' || a === '-v') args.version = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--dir') args.dir = argv[++i];
    else if (a === '--target') args.target = argv[++i];
    else if (a === '--force') args.force = true;
    else if (a.startsWith('--')) args[a.slice(2)] = true;
    else args._.push(a);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.version) {
    const { readFileSync } = await import('node:fs');
    const url = new URL('../package.json', import.meta.url);
    process.stdout.write(`${JSON.parse(readFileSync(url, 'utf8')).version}\n`);
    return 0;
  }

  const command = args._[0] ?? 'doctor';
  if (args.help || command === 'help') {
    process.stdout.write(USAGE);
    return 0;
  }

  const dir = args.dir ?? process.cwd();
  const target = args.target ?? 'all';
  if (!['all', 'win32', 'darwin', 'linux'].includes(target)) {
    process.stderr.write(`Unknown target "${target}". Use win32, darwin, linux or all.\n`);
    return 2;
  }

  switch (command) {
    case 'doctor': {
      const collected = collectHooks(dir);
      let findings = analyze(collected, { target });
      if (args.quiet) findings = findings.filter((f) => f.severity === 'error');
      process.stdout.write(args.json ? `${renderJson(findings, collected)}\n` : renderText(findings, collected, { target }));
      return tally(findings).error > 0 ? 1 : 0;
    }

    case 'list': {
      const collected = collectHooks(dir);
      if (args.json) {
        process.stdout.write(`${JSON.stringify(collected.entries, null, 2)}\n`);
        return 0;
      }
      if (collected.entries.length === 0) {
        process.stdout.write('No hooks configured.\n');
        return 0;
      }
      for (const e of collected.entries) {
        const form = e.handler?.type === 'command' ? (Array.isArray(e.handler.args) ? 'exec' : 'shell') : e.handler?.type;
        const what = e.handler?.command ?? e.handler?.url ?? e.handler?.tool ?? e.handler?.prompt ?? '';
        process.stdout.write(
          `${e.scope.padEnd(8)} ${e.event.padEnd(20)} ${String(e.matcher ?? '*').padEnd(14)} ${String(form).padEnd(6)} ${String(what).slice(0, 80)}\n`,
        );
      }
      return 0;
    }

    case 'events': {
      if (args.json) {
        process.stdout.write(`${JSON.stringify(EVENTS, null, 2)}\n`);
        return 0;
      }
      process.stdout.write(`${'EVENT'.padEnd(21)}${'BLOCKS'.padEnd(8)}MATCHER\n`);
      for (const name of EVENT_NAMES) {
        const s = EVENTS[name];
        process.stdout.write(`${name.padEnd(21)}${(s.blockable ? 'yes' : 'no').padEnd(8)}${s.matcher ?? '-'}\n`);
      }
      return 0;
    }

    case 'init':
      return init({ dir, force: args.force === true });

    default:
      process.stderr.write(`Unknown command "${command}".\n${USAGE}`);
      return 2;
  }
}

main().then(
  (code) => process.exit(code ?? 0),
  (err) => {
    process.stderr.write(`hookrig: ${err?.stack ?? err}\n`);
    process.exit(2);
  },
);
