# secret-run Claude Code plugin

A [Claude Code](https://code.claude.com) plugin that teaches an AI coding agent how to use
[secret-run](../README.md) safely, and backs that up with a mechanical guard. 中文：
[README.zh-CN.md](README.zh-CN.md)

## What it adds

- **A skill** (`skills/use-secret-run/`): loaded into context when a task needs a credential
  value, or when it sees a `secret:<path>#<FIELD>` pointer. Tells the agent to resolve values only
  through `secret run -e NAME=<path>#<FIELD> -- <command>`, that `<concealed:NAME>` in captured
  output is expected and must not be worked around, and to never run `get` / `show` / `edit` or
  decrypt anything directly.
- **A PreToolUse hook** (`hooks/guard-secret-run.ps1`): a mechanical backstop for the skill. It
  denies the tool calls that would put a value into the conversation even if the skill's
  instructions are ignored or forgotten: `secret get/show/edit`, a `secret run` child command that
  prints back the value it was just given, `age -d` / `age --decrypt`, calling `SecretLib.ps1`'s
  decrypt functions directly, and reads of the identity or recovery key files. See the comment
  block at the top of the script for the exact rule list and its known gap.

Neither component can see inside a script you already wrote to disk and then run with
`secret run -- <that script>` — the hook can't parse arbitrary scripts without an unworkable false
positive rate, so the skill's rules still matter even where the hook stays quiet.

## Install

From a Claude Code terminal session, once this repository (or your fork/mirror of it) is reachable
over git:

```
/plugin marketplace add <owner>/secret-run
/plugin install secret-run@secret-run
```

Or, while developing against a local checkout, skip the marketplace and load the plugin directory
directly:

```
claude --plugin-dir /path/to/secret-run/claude-plugin
```

## Requirements

The hook runs `pwsh` (PowerShell 7) directly — the same runtime `secret run` itself requires on
every platform (see [`cli/README.md`](../cli/README.md)). If `pwsh` isn't resolvable on `PATH`,
the hook fails to start; Claude Code treats that as a non-blocking error and the tool call proceeds
(fail-open, see below) — the skill's instructions are then the only thing enforcing the rules.

## Why fail-open

The hook denies on exit code 0 with a `deny` decision; any other failure (script not found, a
thrown exception past the top-level `try/catch`, a timeout) is non-blocking by Claude Code's
default hook behavior, and this plugin does not set `onFailure: "block"`. A hook that can crash or
hang should never be the only thing standing between a working session and a stuck one — the same
trade-off `secret run`'s own output masking makes (best-effort, not a security boundary by itself;
see the root [README's security model](../README.md#security-model--read-before-use)). If you want
a hard stop instead, add `"onFailure": "block"` to the hook entry in `hooks/hooks.json` yourself —
it is deliberately left out here.

## Test

```
pwsh -NoProfile -File claude-plugin/test/test-guard-secret-run.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File claude-plugin/test/test-guard-secret-run.ps1
```

Feeds the hook the same stdin JSON shape Claude Code sends, on a set of deny/allow fixtures; never
touches a real data repo, identity, or value. Exit 0 = all pass.
