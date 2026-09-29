# secret-run

**Keep secret values out of your AI coding agent's context.** A small secrets manager built on plain [age](https://age-encryption.org) files in a private git repo, with a CLI that injects values into a child process only — and masks them if the child prints them — plus an optional self-hosted web UI for humans.

中文：[README.zh-CN.md](README.zh-CN.md)

## Why

AI coding agents read files, run commands and keep transcripts. A key in a `.env`, a note or a command's output ends up in the context, the transcript on disk, and often a "you leaked a secret" warning loop. secret-run keeps documents and prompts on **pointers** (`secret:work/chat/bot-app#APP_SECRET`) and delivers values straight to the process that needs them:

```
secret run -e APP_SECRET=work/chat/bot-app#APP_SECRET -- python notify.py
```

- The value exists only in the child's environment — not in the agent's command line, not in user-level environment variables.
- If the child prints it anyway and the output is being captured (by the agent, a log, a pipe), it comes out as `<concealed:APP_SECRET>`.

## How it works

```
                 your private git repo (data)
   recipients.toml · policy.toml · catalog.toml · store/**/*.age
        ▲  git pull / push                      ▲  read-only bare repo
        │                                       │
 ┌──────┴─────────────────────┐   ┌─────────────┴──────────────────────────┐
 │ each machine: secret CLI    │   │ optional: web UI (container)           │
 │ own age identity, never     │   │ behind your access layer, any OIDC     │
 │ leaves the machine          │   │ login, its own age identity            │
 │ agents / scripts / services │   │ humans: browse, reveal, copy, edit     │
 └────────────────────────────┘   └────────────────────────────────────────┘
```

- **Data repo**: one `.age` file per entry, encrypted to every allowed recipient (devices, a service, an offline recovery key). Metadata is plaintext TOML with **no values**. No server is needed to read values — git is the transport.
- **Entry types**: `kv` (dotenv fields for scripts), `file` (private keys, `.env` files — can be materialized to `~/.ssh/…` after approval), `doc` (markdown for humans).
- **Drift checks**: `secret check` verifies catalog ↔ store ↔ lock consistency, recipient sets vs policy, test decryption, the pre-commit hook, and scans your logs for leaked values (reporting names only).
- **Incident checklist**: `secret inventory` turns catalog metadata (`rotate`, `readers`, `priority`, `linked`) into a "what to rotate where, in which order" page — without decrypting anything.

| Part | What | Docs |
|---|---|---|
| `cli/` | `secret` CLI — PowerShell, runs on Windows PowerShell 5.1 and pwsh 7 (Windows / Linux / macOS) | [cli/README.md](cli/README.md) |
| `web/` | Web UI — ASP.NET, Docker, any OIDC provider (Google documented) | [web/README.md](web/README.md) |
| `FORMAT.md` | The data format contract both sides implement | [FORMAT.md](FORMAT.md) |
| `examples/data-repo/` | Starting files for your private data repo | — |

## Quick start (CLI)

Requirements: `git`, [`age` / `age-keygen`](https://github.com/FiloSottile/age) v1.3+, PowerShell (5.1 or 7).

```bash
# 1. your private data repo, from the template
cp -r secret-run/examples/data-repo ~/secrets && cd ~/secrets && git init && git add -A && git commit -m init
# 2. this machine's identity (prints the public key and registers the machine)
secret-run/cli/secret init
# 3. add a value without it touching your shell history
printf 'API_KEY=%s\n' "$(read -rs v; echo "$v")" | secret-run/cli/secret add personal/demo/api --type kv --title "Demo API" --stdin
# 4. use it -- single quotes: the child expands $API_KEY, not your shell
secret-run/cli/secret run -e API_KEY=personal/demo/api#API_KEY -- bash -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com'
```

Put `cli/` on your PATH to type `secret` directly. More machines: `secret init` on the new one (registered as `pending`), then `secret recipients approve <name>` and `secret rekey` on a machine that already has access. Create an offline recovery key with `secret recovery new`.

**Telling your agent**: add a line like this to your agent instructions (CLAUDE.md / AGENTS.md):

> Credentials are pointers `secret:<path>#<FIELD>`. Use them only via `secret run -e NAME=<path>#<FIELD> -- <command>`. Never use `secret get` / `show` / `edit`, never read `~/.config/secrets/`, never pass `--no-mask`. `<concealed:NAME>` in output is expected.

In Claude Code, also deny the Read tool on key material: `"permissions": { "deny": ["Read(~/.config/secrets/**)", "Read(~/.ssh/*.pem)"] }`.

## Security model — read before use

- **One identity decrypts everything encrypted to it.** Losing a device means rotating every value it could read. `rekey` only changes future ciphertext; old ciphertext in git history still opens with the old key. Use `policy.toml` to narrow what each recipient gets.
- **The web UI decrypts server-side.** Whoever controls its host reads everything encrypted to its identity. It **must** sit behind an access layer (VPN, Tailscale, a zero-trust proxy…) — it refuses to start in production until you declare one — and should get a narrow policy.
- **Masking is best-effort.** It stops accidents (a debug print, an env dump in an error), not an agent determined to exfiltrate: base64, `--no-mask`, or writing the value to a file all bypass it. The real boundary is "the agent never gets the value in its command line or files".
- **Anyone who can push to the data repo can forge entries** (age does not authenticate senders). Materialize roots are hard-coded and every new target needs your approval, but replacing the content of an approved target is not detected. See [FORMAT.md §15](FORMAT.md#15-threat-model-format-level-accepted-trade-offs).
- Metadata (entry names, descriptions, recipients) is plaintext. Keep the data repo private and name entries without hints about values.

## Similar tools

| Tool | Overlap | Difference |
|---|---|---|
| [1Password CLI `op run`](https://developer.1password.com/docs/cli/secret-references/) | `op://` references, env injection, output masking — the inspiration for masking | Commercial SaaS, not self-hostable |
| [SOPS](https://github.com/getsops/sops) + age | Encrypted files in git | GitOps-oriented; no `run` with masking, no per-entry model |
| [passage](https://github.com/FiloSottile/passage), [gage](https://github.com/distillerylabs/gage) | age + git, one file per secret | No injection / masking, no drift checks, no web UI |
| [secretless-ai](https://github.com/opena2a-org/secretless-ai) | Keeping secrets away from AI tools, hooks, `run` | Different storage backends; not age + git |
| [Infisical](https://github.com/Infisical/infisical) | Web UI + `infisical run`, self-hostable | A server with a database; much larger |

## Status

Personal tool, used daily on a few machines; published as is. Issues and PRs are welcome, but there is no support commitment.

## License

[MIT](LICENSE)
