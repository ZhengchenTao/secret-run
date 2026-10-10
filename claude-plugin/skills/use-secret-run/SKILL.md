---
name: use-secret-run
description: Use whenever a task needs a credential value (API key, token, password, SSH key, .env content) to run a command, configure a service, or make a request — or when a document, prompt, or pointer contains `secret:<path>#<FIELD>`. Explains how to resolve secret-run pointers and inject values without ever bringing the value itself into the conversation, a file, or a log. Trigger phrases: "need the API key for...", "set the token/password/secret for...", "add this to .env", "what's in secret:...", "configure credentials for...".
---

# Using secret-run safely

secret-run stores credential values as `.age` ciphertext in a private data repo. Metadata (paths,
titles, descriptions) is plaintext and safe to read and quote; **values are not** — the whole point
of this tool is that an AI agent's context, transcript, and command line never see them.

## The one correct way to use a value

```
secret run -e NAME=<path>#<FIELD> -- <command> [args...]
```

- `<path>` is the three-segment logical path (`<domain>/<group>/<name>`), `<FIELD>` is the kv field name.
- The value is written only into the **child process's environment**. It never appears in the
  command line you type, in `secret run`'s own stdout, or in a parent-level environment variable.
- Inject several values with repeated `-e NAME=...`, or a whole entry with `-a [PREFIX=]<path>`.
- A document or prompt should only ever carry the pointer form `secret:<path>#<FIELD>` — write that,
  never the value, when you reference a credential in notes, commit messages, or code comments.

Example: a script that needs `APP_SECRET`:

```
secret run -e APP_SECRET=work/chat/bot-app#APP_SECRET -- python notify.py
```

## `<concealed:NAME>` is expected — do not try to see through it

When `secret run`'s output is captured (which it is, whenever an agent runs it — every Bash tool
call captures stdout/stderr), any injected value that the child prints gets replaced with
`<concealed:NAME>` before it reaches you. Seeing this string means masking is working correctly.

- **Do not** add `--no-mask` to see the real value. That flag exists for interactive terminal use by
  a human, not for an agent.
- **Do not** try to route around masking (base64-encoding the value, writing it to a file, splitting
  it across multiple prints) to recover what is under `<concealed:NAME>`. If a task genuinely needs
  the plaintext visible (debugging, sharing with a teammate), ask the human to run `secret show
  <path>` themselves in their own terminal, or point them at the project's web UI if one is deployed.
- Masking is best-effort by design (see the project's security model) — it stops accidents, not a
  determined attempt to exfiltrate. Don't be the determined attempt.

## Never do these

- **Never run `secret get`, `secret show`, or `secret edit`.** `get` writes the value to stdout (or
  to a file with `--out`), `show` prints it for humans, `edit` opens a plaintext editor on it. All
  three put the value where you can read it — that is exactly what this tool is designed to avoid.
- **Never decrypt the data repo directly.** No `age -d` / `age --decrypt` on a `store/**/*.age` file,
  and no dot-sourcing `SecretLib.ps1` (or any other secret-run internals) to call `Sec-ReadField`,
  `Sec-GetField`, `Sec-GetEntryBytes`, `Sec-KvParse`, or `Sec-AgeDecrypt` yourself. These are the
  same decrypt path `secret get` uses internally — calling them directly is `secret get` with extra
  steps.
- **Never read the identity file.** That's `~/.config/secrets/identity.txt` by default (or whatever
  `SECRET_IDENTITY` / `--identity` points at) — it is the private key that decrypts everything
  encrypted to this machine. Also never read a `recovery/*.age` file or a
  `secret-recovery-identity-*.txt` left on the Desktop by `secret recovery new`.
- **Never pipe a value to something that re-exposes it.** `secret run -e NAME=... -- printenv`,
  `-- echo $NAME`, `-- curl -H "... $NAME"`, writing it to a file and `cat`-ing the file — all of
  these take the value right back out of the child process you just tried to protect it in.

## Finding and managing entries (safe, read-only or write-only-metadata)

These never decrypt a value, so use them freely:

- `secret list [<prefix>]` — browse what exists.
- `secret info <path>` — one entry's metadata (title, description, fields, rotate/readers notes).
- `secret resolve <old pointer>` — turn a legacy pointer into `secret:<path>`.
- `secret check` — repo health (consistency, drift, recovery key status); never prints values.
- `secret add <path> --type kv|file|doc --title <t> --stdin` (or `--from-file <f>`) — add a new
  entry. Prefer `--stdin`/`--from-file` over typing the value as a visible argument. If you're
  unsure of the exact fields or entry-type rules, read `FORMAT.md` and `cli/README.md` in the
  secret-run checkout first.

## Why this matters

If a value ends up in your context, it also ends up in the session transcript on disk, in whatever
log captured your output, and possibly in a commit message or a file you wrote. None of that is
reversible the way "forget this" is for a person. Routing every value through `secret run -e` is the
only way the value stays out of all of those places at once.

A PreToolUse hook that ships with this plugin backs up the "never" list above by denying the
riskiest commands outright (`get`/`show`/`edit`, raw `age -d`, the `SecretLib.ps1` decrypt
functions, reads of the identity/recovery files). Treat it as a backstop, not a license to get
close to the line — the hook can't see inside a script you already wrote to disk and then run with
`secret run -- <that script>`, so the rules above still apply even where the hook would stay quiet.
