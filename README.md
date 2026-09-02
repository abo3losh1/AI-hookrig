# hookrig

**Claude Code hooks that actually fire on Windows.**

Find the hooks that silently do nothing, then run the rest the same way on
every platform. No dependencies, no install in the projects that use it.

```bash
npx hookrig doctor
```

---

## The problem

A `command` hook with no `args` is handed to a shell. That shell is `sh` on
macOS and Linux, and **PowerShell on Windows**. Almost every hook published on
the internet assumes `sh`.

```json
{ "type": "command", "command": "jq -r .tool_name | grep -q Bash && exit 2" }
```

On macOS this blocks a tool call. On Windows:

- `jq` is not installed, so the pipeline errors immediately
- `&&` is a **parser error** in Windows PowerShell 5.1, the version that ships
  with Windows, so the line never even parses
- most hook events ignore a non-zero exit, so nothing is printed

The hook is dead and Claude Code never tells you. The nastier variant is worse:

```json
{ "type": "command", "command": "curl -s https://example.com/ping" }
```

Nothing fails here. `curl` is a PowerShell alias for `Invoke-WebRequest`, which
ignores `-s`, treats the URL differently, and returns an object instead of
text. The hook runs, reports success, and does the wrong thing.

## The fix

Two commands.

### 1. Find what is broken

```bash
npx hookrig doctor
```

```
hookrig doctor
  6 hooks across 2 settings files  ·  target Windows

.claude/settings.json
  ERROR "jq" is not available in a stock Windows shell.
        PreToolUse  hooks.PreToolUse[0].hooks[0]:7  ·  breaks on Windows  ·  posix-only-binary
        The hook exits non-zero, and most events ignore a failing hook without surfacing anything.
        fix Parse the hook JSON in Node instead: it is already on the machine, because Claude Code needs it.

  ERROR "$CLAUDE_PROJECT_DIR" is expanded by PowerShell, not by the shell you wrote this for.
        PreToolUse  hooks.PreToolUse[1].hooks[0]:13  ·  breaks on Windows  ·  unbraced-variable
        PowerShell has no $CLAUDE_PROJECT_DIR variable, so it expands to an empty string and the path collapses.
        fix Write ${CLAUDE_PROJECT_DIR} with braces. Claude Code substitutes that placeholder itself, before any shell sees it.

  ERROR "PostToolUce" is not a Claude Code hook event, so this hook never fires.
        PostToolUce  hooks.PostToolUce[0].hooks[0]:26  ·  breaks on all platforms  ·  unknown-event
        fix Did you mean "PostToolUse"?

  ERROR Matcher "launch" can never match a SessionStart event.
        SessionStart  hooks.SessionStart[0].hooks[0]:32  ·  breaks on all platforms  ·  dead-matcher
        SessionStart only ever emits: startup, resume, clear, compact, fork.

13 errors  ·  2 warnings
```

It reads every scope Claude Code merges hooks from (managed, user, project,
local) and reports problems for **all** platforms, so a macOS user still sees
what breaks for their Windows teammates. Try it on the bundled example:

```bash
npx hookrig doctor --dir examples/broken-hooks
```

### 2. Stop writing shell in JSON

```bash
npx hookrig init
```

This writes a small runtime into `.claude/hooks/hookrig/`, a config file, and
registers your events in **exec form**:

```json
{
  "type": "command",
  "command": "node",
  "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/hookrig/run.mjs", "PreToolUse"],
  "timeout": 30
}
```

Exec form spawns the process directly. No shell, on any platform, ever. Your
logic moves into JavaScript, where it behaves identically everywhere:

```js
// .claude/hooks/hookrig.config.mjs
import { protectSecrets, blockDangerousBash, auditLog, notify } from './hookrig/builtins.mjs';

export default {
  hooks: {
    PreToolUse: [
      protectSecrets(),
      blockDangerousBash(),

      (input, ctx) => input.tool_name === 'Bash' && input.tool_input.command.includes('prod')
        ? ctx.deny('Production commands go through CI.')
        : ctx.pass(),
    ],

    PostToolUse: [auditLog()],
    Stop: [notify({ message: 'Claude finished.' })],
  },
};
```

Run `npx hookrig init` again after adding an event; it re-syncs
`.claude/settings.json` and leaves hooks it did not create alone.

The runtime is **vendored**, not a dependency. Commit
`.claude/hooks/hookrig/` and every teammate gets identical behaviour with no
`npm install`, which matters when the repo is Python, Rust or Go.

---

## Why exec form is the whole answer

| | shell form | exec form |
|---|---|---|
| `"command": "npm test && echo ok"` | `sh -c` on macOS, PowerShell on Windows | not applicable |
| shell operators | interpreted by two different languages | passed as literal arguments |
| `$VAR` | expanded by whichever shell won | never expanded |
| paths with spaces | split into two arguments unless quoted | passed intact |
| `.sh` scripts | need a shebang and an execute bit | call `node`/`python` explicitly |

hookrig's doctor flags shell form only when the command actually needs a shell.
A plain `"command": "node scripts/x.mjs"` is fine as it is.

---

## Handler API

A handler is a function `(input, ctx)`. `input` is the JSON Claude Code sends
on stdin for that event. Return one of:

| Call | Effect |
|---|---|
| `ctx.pass()` | do nothing |
| `ctx.allow(reason?)` | approve without a permission prompt |
| `ctx.deny(reason)` | stop the action |
| `ctx.context(text)` | add text the model will see |
| `ctx.message(text)` | show a line to the user |
| `ctx.updateInput(obj)` | rewrite the tool input (`PreToolUse`) |
| `ctx.updatePrompt(str)` | rewrite the user's prompt (`UserPromptSubmit`) |
| `ctx.bell()` | ring the terminal bell |

`ctx` also carries `event`, `projectDir`, `cwd`, `sessionId`, `toolName`,
`toolInput` and `platform`.

**hookrig translates the decision into whatever shape the event expects.** The
same `ctx.deny('nope')` becomes `permissionDecision: "deny"` with exit 2 on
`PreToolUse`, `shouldStop: true` with exit 0 on `PostToolUse`, `shouldContinue`
on `Stop`, and `shouldBlock` + `reason` on `ConfigChange`. You do not have to
remember which is which.

Handlers run in order and the first `deny` wins. Narrow one to a tool:

```js
{ match: { tool: 'Edit|Write' }, run: (input, ctx) => ... }
```

A handler that throws is logged to `.claude/hookrig-errors.log` and the session
continues. A hook must never be the reason your work stops.

## Built-in hooks

```js
import {
  protectSecrets, blockDangerousBash, protectPaths,
  formatOnWrite, auditLog, notify, addContext,
} from './hookrig/builtins.mjs';
```

| Hook | What it does |
|---|---|
| `protectSecrets({ globs, allow })` | Deny reads and writes of `.env`, `*.pem`, `id_rsa`, `.aws/credentials` and friends, including Bash commands that reference them. `.env.example` stays readable. |
| `blockDangerousBash({ extra, allow, ask })` | Deny `rm -rf`, `git push --force` (but not `--force-with-lease`), `git reset --hard`, `curl \| sh`, `chmod 777`, `dd of=/dev/*`, `DROP TABLE`, `npm publish`, and more. `ask: true` warns instead of blocking. |
| `protectPaths({ globs, mode })` | Make paths read-only (`mode: 'write'`, the default) or invisible (`mode: 'all'`). |
| `formatOnWrite({ commands })` | Run a formatter after the agent edits a file. Maps a glob to an argv array, spawned directly so paths with spaces work. |
| `auditLog({ file, fields, redact, redactExtra, maxBytes })` | One JSON line per event, so you can see what the agent actually did. Credentials are redacted and the file rotates at 5 MB, both by default. |
| `notify({ message, bell, command })` | Terminal bell plus a message. `command` is an argv array for a real desktop notifier. |
| `addContext(textOrFn)` | Inject text into the model's context. |

```js
formatOnWrite({
  commands: {
    '**/*.{ts,tsx,js,jsx,json,md}': ['npx', 'prettier', '--write'],
    '**/*.py': ['ruff', 'format'],
    '**/*.go': ['gofmt', '-w'],
  },
})
```

### A note on the audit log

`auditLog()` records full Bash command text, so a token pasted into a command
would otherwise sit in a plaintext file forever. Anthropic, OpenAI, GitHub,
AWS, Slack, Stripe and Google key formats are redacted, along with JWTs,
private key blocks, `NAME_WITH_TOKEN=value` assignments, `--password` style
flags, `Authorization:` headers and credentials embedded in URLs. Add your own
with `redactExtra: [/acme-internal-\d+/g]`, or turn the whole thing off with
`redact: false` if you know what is in your commands.

Redaction is best effort against known formats, not a guarantee. Treat the log
as sensitive and keep it out of version control:

```
.claude/hookrig-audit.jsonl
.claude/hookrig-audit.jsonl.1
.claude/hookrig-errors.log
```

---

## Rules the doctor checks

**Windows portability**

| Rule | Catches |
|---|---|
| `posix-devnull` | `/dev/null`, which PowerShell turns into a file named `null` |
| `posix-tmp` | `/tmp/...` paths |
| `ps-chain-operators` | `&&` and `\|\|`, parser errors in Windows PowerShell 5.1 |
| `unbraced-variable` | `$CLAUDE_PROJECT_DIR` instead of `${CLAUDE_PROJECT_DIR}` |
| `posix-only-binary` | `jq`, `sed`, `awk`, `grep`, `chmod` and 40 more that are simply absent |
| `powershell-alias-shadow` | `curl`, `wget`, `cat`, `ls`, `rm`, `echo` and friends, which resolve to cmdlets that behave differently |
| `shell-script-direct` | invoking a `.sh` file, which Windows cannot start |
| `python3-binary` | `python3`, which usually hits the Microsoft Store stub |
| `heredoc`, `backtick-substitution`, `dollar-paren` | shell syntax PowerShell reads as something else |
| `inline-env-assignment` | `FOO=bar cmd`, which is not PowerShell |
| `native-stderr-redirect` | `2>&1`, unreliable against native executables in PowerShell 5.1 |
| `tilde-home` | `~/`, not expanded for native executables |

**POSIX portability**

| Rule | Catches |
|---|---|
| `windows-only-syntax` | `%VAR%`, `$env:`, `cmd /c`, `powershell`, `C:\` paths, `NUL` |

**Correctness, everywhere**

| Rule | Catches |
|---|---|
| `unknown-event` | a misspelled event, which is ignored in silence |
| `dead-matcher` | a matcher value the event can never emit |
| `matcher-is-permission-rule` | `"matcher": "Bash(git *)"`, which is `if` syntax, not matcher syntax |
| `matcher-bad-regex` | a glob like `*.ts` where an unanchored regex is required |
| `exec-form-shell-syntax` | shell operators inside `args`, where they are literal text |
| `script-missing` | a hook script that is not on disk |
| `json-strict` | a settings file with a comment or trailing comma, which drops every hook in it |
| `http-env-not-allowed` | a header using `$TOKEN` without `allowedEnvVars` |
| `http-plaintext` | prompts and tool inputs posted over non-local `http://` |
| `exit-2-on-nonblockable` | `exit 2` on an event that cannot block |
| `slow-hook-no-timeout` | `npm`, `pytest`, `docker` and friends with no timeout, so a hang freezes the session |
| `recursion-risk` | a Bash hook that invokes Claude Code, which can fire itself |
| `plugin-placeholder-outside-plugin` | `${CLAUDE_PLUGIN_ROOT}` in a settings hook, where it is never substituted |
| `unquoted-path-with-space` | an unquoted path containing a space |

---

## CLI

```
hookrig doctor            Find hooks that break on Windows, macOS or Linux
hookrig list              Show every hook Claude Code will load, and from where
hookrig events            Print the hook event reference
hookrig init              Install the cross-platform runner into this project

  --dir <path>            Project directory to scan (default: cwd)
  --target <platform>     win32 | darwin | linux | all   (default: all)
  --json                  Machine-readable output
  --quiet                 Errors only
```

`doctor` exits `1` when there is at least one error, so it works in CI:

```yaml
- run: npx hookrig doctor --quiet
```

## Requirements

Node 18.17 or newer, which you already have, because Claude Code needs it.
Zero runtime dependencies.

## Contributing

Every rule lives in [`src/doctor/rules.mjs`](src/doctor/rules.mjs) as a small
function plus a test in [`test/rules.test.mjs`](test/rules.test.mjs). If you
have hit a hook that fails on your platform and hookrig does not catch it,
that is the highest-value contribution there is: open an issue with the hook
that broke.

```bash
npm test
```

## License

MIT
