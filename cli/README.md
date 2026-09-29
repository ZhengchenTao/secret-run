# secret CLI

Command-line tool for a secret-run data repo. The format contract is [../FORMAT.md](../FORMAT.md). 中文：[README.zh-CN.md](README.zh-CN.md)

- Entry point: `secret.ps1`; two shims, `secret.cmd` (cmd / PowerShell) and `secret` (Git Bash / POSIX), prefer `pwsh` and fall back to `powershell.exe`.
- Library: `SecretLib.ps1` (restricted TOML, kv, glob, recipient hash, lock, age calls, ACLs); other scripts can dot-source it.
- Sources are ASCII-only and run on Windows PowerShell 5.1 and pwsh 7 (Windows, Linux, macOS). Needs `age` / `age-keygen` (v1.3+) and `git` on PATH.
- Plaintext only lives in memory and in the pipe to `age`; the only temp file is the editor step of `add` / `edit` (`%LOCALAPPDATA%\secret\tmp` or `~/.cache/secret/tmp`, owner-only ACL, zeroed and deleted afterwards).

## Using it with AI coding agents

The point of the design: **values reach the process that needs them, not the model's context.**

- Documents and prompts only carry pointers: `secret:<path>#<FIELD>`.
- The agent runs commands as `secret run -e NAME=<path>#<FIELD> -- <command>`: the value exists only in the child's environment.
- **Output masking**: when `secret run`'s own stdout / stderr is redirected (an agent capturing output, a log file, a pipe), the child's stream is relayed through `secret` and every injected value (UTF-8 bytes, at least 6) is replaced with `<concealed:NAME>`. A stream that is a console stays inherited, so humans in a terminal and services under a console host are unaffected. Matching is byte-wise, so binary output passes through unchanged; a value split across two writes is still caught. **Not caught**: values the child transforms (base64, URL-encoding), a pause longer than 200 ms in the middle of a value, values shorter than 6 bytes. `--mask` forces masking on both streams, `--no-mask` turns it off. It prevents accidents, not a determined bypass.
- Tell your agent not to use `get` / `show` / `edit` and not to read `~/.config/secrets/`. In Claude Code, add `permissions.deny` rules such as `Read(~/.config/secrets/**)` and `Read(~/.ssh/*.pem)`.

## Global options and environment

| Item | Meaning |
|---|---|
| `--repo <dir>` / `SECRET_REPO` | Data repo. Default: `{workspace}/secrets` when `SECRET_WORKSPACE` is set, else `~/secrets` |
| `--identity <file>` / `SECRET_IDENTITY` | This machine's identity, default `~/.config/secrets/identity.txt` (on Windows `~` is `USERPROFILE`) |
| `--pull` | `git pull --ff-only` before running |
| `SECRET_WORKSPACE` | Root for `{workspace}/` materialize targets. Unset = such targets are refused |
| `SECRET_SCAN_LOGS` | Extra log files `check` scans for leaked values (separated by the platform path separator) |
| `SECRET_INVENTORY_TEMPLATE` | Template for `inventory`, e.g. the bundled `inventory-template.zh-CN.md` |
| `SECRET_HOME` / `SECRET_STATE_DIR` / `SECRET_DESKTOP` / `SECRET_DEVICE_NAME` | **Test-only**: override the home dir, `%LOCALAPPDATA%\secret`, the desktop and the device name |

## Notes

- **The editor must block**: `secret` reads the file back after the editor process exits. VS Code needs `EDITOR="code --wait"`; without `EDITOR`, Windows uses `%SystemRoot%\System32\notepad.exe`. Turn off editor backups / swap / autosave recovery (e.g. `vim -n` with `nobackup nowritebackup`), otherwise plaintext lands outside the temp dir. Invalid kv content asks whether to reopen the editor (content kept); when stdin is at EOF, nothing is written.
- **Reading values from other PowerShell scripts**: dot-source `SecretLib.ps1` and call `Sec-GetField <repo> <identity> <path> <FIELD>` (string) or `Sec-GetEntryBytes <repo> <identity> <path>` (bytes), or `Sec-ReadField <path> <FIELD>` with the default repo / identity. When capturing `secret get` from a child process in PowerShell, set `[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)` first.
- **Exit codes** are reliable when called directly or through the shims. When a scheduled task wraps a service in `conhost --headless … secret run …`, conhost swallows the exit code; judge liveness by the process, not the task result.
- **Atomic writes**: `add` / `edit` / `rekey` write everything to temp files first and only then replace in the order ciphertext → lock → catalog; any failure rolls back from the old bytes in memory. When the ciphertext hash in the lock does not match the file (someone bypassed the CLI), these commands refuse to overwrite.
- **Materialize safety**: every level from the root to the parent directory, and the target itself, is rejected if it is a junction or symlink; Windows reserved-name segments are always rejected (with extensions too, e.g. `nul.txt`). Script / executable targets (`.ps1` `.psm1` `.cmd` `.bat` `.exe` `.dll` `.js` `.vbs`), `~/.ssh/config*` and `authorized_keys` are flagged `SENSITIVE` before approval.
- **Incident keys** (FORMAT §6): `rotate` (where to rotate), `readers` (who reads it), `priority` (`high` / `normal` / `low`, **ordering only, no crypto meaning**), `linked` (entries to rotate together). `secret add` takes `--rotate '<text>'`, `--reader '<reader>'` (repeatable), `--priority high`, `--linked <path>` (repeatable). Never put values or account URLs there.
- **Catalog key order is fixed** (FORMAT §6); unknown keys are kept verbatim after `updated`. The CLI and the web write the same bytes, so alternating writes do not produce whole-file diffs.
- **`secret rm` does not touch materialized files and does not rewrite git history**: delete the file by hand and rotate the value.
- **Invalid catalog entries**: `check` reports `ERROR catalog-entry`. Read commands (get / show / run / list / resolve …) skip them and keep working with the rest; write commands (add / edit / rekey …) require the catalog to be fixed first. The error lists each invalid entry and the rule it breaks; fix it in `catalog.toml` (or delete the `[[entry]]` block together with its ciphertext and lock line) and re-run `secret check`.

Commands that write the repo (`init` / `recipients add|approve|remove` / `rekey` / `add` / `edit` / `rm` / `recovery new|seal|confirm` / `inventory` when writing a file):

- **Commit by default** with a generated message (`secret: add personal/x/y (kv)`, `secret: rm …`, `secret: rekey N entries`). `--commit "<msg>"` replaces the message, `--no-commit` only stages.
- **A commit only contains the files this command touched** (`git commit -- <files>`); unrelated work-tree changes are never swept in. Unrelated uncommitted changes to catalog / policy / recipients / store / INCIDENT.md produce a WARN listing the file names, without blocking.
- **Being behind upstream** produces a WARN (suggesting `--pull` or `git pull --rebase`), without blocking.
- `--push` is always explicit. A rejected push (remote has new commits) is **not** rebased automatically; the error tells you to `git -C <repo> pull --rebase`, `git push`, then `secret check`.
- **One write lock per machine**: an exclusive file lock outside the repo (`%LOCALAPPDATA%\secret\locks\` / `~/.cache/secret/locks/`), waiting 30 s by default (`--lock-timeout <s>`, 0 = don't wait); on timeout the error names the holding pid and command. Read commands take no lock. A killed process releases the lock automatically.

## Commands

| Command | What it does |
|---|---|
| `secret init [--name <n>]` | Create an identity if there is none (never overwritten), print the public key, register this machine in `recipients.toml`: `active` when the repo has no active recipient or an empty store, otherwise `pending` |
| `secret recipients list` | List recipients |
| `secret recipients add <name> <key> [--type device\|service\|recovery] [--pending]` | Register a recipient (active by default) |
| `secret recipients approve <name>` / `remove <name>` | pending → active / → revoked (record kept); run `rekey` afterwards |
| `secret rekey [--all]` | Re-encrypt ciphertexts whose recipient-set hash differs from the policy (`--all`: everything), verifying the SHA-256 of the plaintext before replacing, and update the lock. Any failure (including a lock hash mismatch) aborts everything |
| `secret add <path> --type kv\|file\|doc --title <t> [--description <d>] [--from-file <f> \| --stdin] [--target <t>] [--acl private\|inherit] [--machines a,b] [--tag x]... [--alias x]... [--replace]` | Add an entry; without an input source it opens `$EDITOR`. kv is validated strictly; `fields` follows the key order of the content |
| `secret edit <path>` | Decrypt to a temp file, open the editor, re-encrypt only if the content changed; updates `updated`, kv `fields` and the lock |
| `secret rm <path> [--yes] [--force] [--keep-target]` | Delete an entry: ciphertext, catalog entry and lock line together (rolled back on failure). Without `--yes` it prints a summary (including `readers` and `linked`) and exits 2. **Refuses by default when other entries `linked` to it** (exit 1, referrers listed); `--force` deletes and removes the reference from those entries in the same transaction. Materialized files are **not** deleted. The ciphertext stays in git history — rotate the value |
| `secret inventory [--out <file>] [--stdout]` | Generate the incident checklist (markdown, **no values**) from the catalog, grouped by domain/group and sorted by `priority` then path. Default output `<repo>/INCIDENT.md`. `check` regenerates it in memory and WARNs when the file is missing or stale. Before writing, every kv value this machine can decrypt is searched in the output: a value that appears once in the catalog text (someone pasted a credential into a title / description) stops the write with the entry and field name; a value that appears 2+ times (identifier-like values such as user / database / environment names) is only reported as a note. Values shorter than 4 characters are skipped |
| `secret show <path>` | For humans: kv as `KEY=VALUE`, doc as text, file as text when it is UTF-8, otherwise only size and SHA-256 |
| `secret get <path>#<FIELD>` | Write the value to stdout as is, no trailing newline (for scripts) |
| `secret get <path> --out <file> [--allow-sync-dir]` | Write the whole entry to a file (owner-only ACL; refuses to overwrite). The path is validated like a materialize target: inside the data repo, junctions / symlinks, reserved names are refused; cloud-synced folders (OneDrive / Dropbox / Google Drive / iCloudDrive / Nextcloud / Syncthing) are refused unless `--allow-sync-dir` |
| `secret run [-e NAME=<path>#<FIELD>]... [-a [PREFIX=]<path>]... [--mask\|--no-mask] -- <cmd> [args]` | Inject values into the child's environment only and return its exit code; output masking as described above. `.ps1` runs in the current host, `.cmd` / `.bat` through `cmd.exe /c` |
| `secret materialize [--approve] [--force] [--dry-run] [<path>...]` | Write file entries to their `target` (only under `~/.ssh/` and `{workspace}/`). A new `(path, target)` pair needs `--approve`; approvals live in `%LOCALAPPDATA%\secret\approved-targets.txt`. Markers: `+` written / `=` same / `!` differs, skipped (`--force` overwrites) / `?` not approved / `X` error |
| `secret list [<prefix>]` / `secret info <path>` | Catalog only, nothing decrypted |
| `secret resolve <old pointer>` | Turn an old pointer (`notes:ops/chat-bot.md#Credentials`) into `secret:<path>` via the entries' `aliases` |
| `secret check [--sample <n>] [--web <url>] [--scan-log <path>]... [--no-log-scan] [--quick]` | All FORMAT §12 checks, one line per result `<LEVEL> <check> <name>`; exit 0 / 2 (WARN) / 1 (ERROR). Also: `hooks` (the data repo's `core.hooksPath` must point at `cli/githooks`, else ERROR — run `secret hooks install`); `log-leak` scans logs (`%LOCALAPPDATA%\secret\*.log`, `SECRET_SCAN_LOGS`, `--scan-log`) for the entries' values and reports `ERROR log-leak <log file> <path#field>` — **names only, never values**. Thresholds: kv values under 4 characters are skipped; for file entries only credential-looking single lines (12+ characters, no whitespace) are searched; entries ending in `-pub` are skipped. A clean scan means "nothing found", not "nothing leaked". `git` compares HEAD with the cached `@{u}` without fetching (offline-safe) and WARNs when ahead or behind |
| `secret recovery new [--out <file>] [--replace]` | Create a recovery identity (written to the desktop by default, private key never printed) and register it as the active `recovery` recipient |
| `secret recovery drill --identity <recovery key> [<path>]` | Decrypt one entry with the recovery key only and compare with this machine's result: `match true\|false` |
| `secret recovery seal --identity <recovery key> [--replace]` | Run `age -p` interactively and write `recovery/recovery-identity.age` (passphrase typed by a human) |
| `secret recovery confirm` | Once the recovery key file is gone from the desktop, write `backup = "offline <date>"` |
| `secret hooks install` | Point the data repo's `core.hooksPath` at `cli/githooks/` (pre-commit validates `.age` headers, paths and the whitelist) |

## Self-test

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File cli/test/selftest.ps1
pwsh -NoProfile -File cli/test/selftest.ps1
```

Uses only a temp repo, test identities and random test values, and cleans up afterwards; exit 0 when everything passes.
