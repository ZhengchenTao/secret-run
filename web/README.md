# secrets-web

*Chinese version: [README.zh-CN.md](README.zh-CN.md)*

A small self-hosted web UI for a git repository of [age](https://age-encryption.org)-encrypted secrets — the same repository
the `secret` CLI manages. It reads a bare git repo, decrypts **server-side** with its own age identity, signs users in with
any OpenID Connect provider (Google is the documented example), and can optionally create / edit / delete entries by
committing and pushing with a deploy key.

- **Format**: the data layout (`catalog.toml`, `recipients.toml`, `policy.toml`, `store/<domain>/<group>/<name>.<kv|file|doc>.age`,
  `store/.recipients.lock`) is defined in [`../FORMAT.md`](../FORMAT.md). This service implements its restricted TOML,
  recipients, glob / recipient-set hash, catalog, kv and ciphertext-validity rules, and reads exactly like the CLI.
- **Stack**: ASP.NET Core (.NET 10) Razor Pages, no front-end build chain, no external scripts, `git` and `age` as child processes.

> **Read the security model before deploying.** This service can decrypt every secret that is encrypted to its identity.
> It refuses to start in Production unless you declare the network access layer in front of it.

## Architecture

```
browser (phone / laptop)
   │  HTTPS
   ▼
your access layer / reverse proxy          (VPN, mesh VPN, identity-aware proxy, authenticating reverse proxy …)
   │  http://127.0.0.1:8099
   ▼
secrets-web container                      (non-root, read-only root filesystem, no capabilities)
   ├─ OIDC relying party ──────────────►   your OpenID Connect provider (code flow + PKCE, RS256 id_tokens only)
   ├─ git --git-dir /repo                  bare repo, mounted read-only
   │     rev-parse HEAD / cat-file blob <commit>:catalog.toml | store/…
   ├─ age -d -i /identity/identity.txt     ciphertext on stdin, plaintext on stdout, memory only
   ├─ /data/audit.log                      JSONL audit
   └─ (optional) /data/work → git push     writes: working clone + deploy key → your git server
```

| Directory | Contents |
|---|---|
| `src/SecretsWeb/Format/` | Hand-written restricted-TOML parser, catalog / recipients validation, kv parser, path and ciphertext-header rules, glob and recipient-set hash, canonical TOML writer |
| `src/SecretsWeb/Repo/` | Child-process wrapper (stdin for ciphertext, capped stdout, allowlisted environment), bare-repo reader with a per-HEAD catalog cache, writer (working clone → commit → push) |
| `src/SecretsWeb/Security/` | OIDC / cookie setup, independent id_token verifier, in-memory `ITicketStore`, security headers, PublicOrigin rewrite, rate limiters, startup guards (access layer, trusted proxies) |
| `src/SecretsWeb/Services/` | Decryption + audit (`EntryService`), writes (`EntryWriteService`), health, Markdown rendering, favorites |
| `src/SecretsWeb/Pages/` | Razor Pages: list / tree / search, entry page, create / edit / delete |
| `src/SecretsWeb/wwwroot/` | `app.css`, `app.js`, `form.js` (no inline scripts) |
| `tests/SecretsWeb.Tests/` | xUnit: format unit tests + integration tests against a throwaway test repo |
| `deploy/docker-compose.yml` | Example deployment |

## Security model

**Server-side decryption.** The browser never holds a key. The container holds an age identity and decrypts on request,
so *anyone who controls the service, or can sign in to it, can read every entry encrypted to that identity*. Consequences:

- **Give it a dedicated recipient.** Generate a fresh identity for the web UI (`age-keygen -o identity.txt`), register its
  public key as a `service`-type recipient (`secret recipients add web <age1…> --type service`) and re-encrypt (`secret rekey`).
  Never reuse a device or recovery identity.
- **Encrypt to it only what the web UI needs.** `policy.toml` decides who can decrypt what; the last matching rule wins.
  For example, keep the web recipient out of everything except one domain:

  ```toml
  [[rule]]
  path = "store/**"
  recipients = ["@device", "@recovery"]

  [[rule]]
  path = "store/personal/**"
  recipients = ["@device", "@recovery", "web"]
  ```

  Entries the identity can't decrypt show up in the list but can't be opened. Writes are limited the same way: after
  encrypting, the service decrypts its own output as a self-check, so it cannot create or edit entries it can't read.
- **It must sit behind a network access layer.** OIDC login alone is not enough for a service that holds a decryption key.
  Bind it to `127.0.0.1` and publish it only through something that authenticates the network path first (a VPN or mesh VPN,
  an identity-aware proxy such as Cloudflare Access, an authenticating reverse proxy). `Deployment:AccessLayer` must
  describe that layer; in Production the service refuses to start without it. The value `none` starts anyway with a
  prominent warning in the log.
- **Revocation is rotation.** Removing an entry or a recipient does not un-leak anything: git history keeps the old
  ciphertext. If the web identity may have been exposed, remove the recipient, rekey, and rotate the values it could read.

**Login.** OIDC relying party only (authorization code + PKCE, confidential client). The OIDC handler does not enforce a
signature for every id_token shape returned by the token endpoint (`alg=none`, RS256 header with an empty signature), so
`OnTokenValidated` verifies the raw id_token again independently: non-empty signature, header `alg` must be RS256, only RSA
keys from the JWKS, `RequireSignedTokens`, `iss`, `aud = ClientId`, lifetime. On a signature/key failure the JWKS is
refreshed once (at most every 60 seconds) so an IdP key rotation doesn't lock you out, and a removed key is no longer
accepted. No JwtBearer is registered and no bearer / access token is ever accepted. `SaveTokens = false`; after sign-in the
session principal keeps only `sub`, `name`, a random session id and — only if the IdP marked it verified — the email.
Access is decided by the allowlists (`Auth:AllowedSubjects`, `Auth:AllowedEmails`, optional `Auth:RequireAmr`) at sign-in,
again by the authorization fallback policy, and again on every request (`OnValidatePrincipal`), so removing someone from the
allowlist takes effect without a restart. `returnUrl` only accepts site-relative paths (`/…`, `IsLocalUrl`, no control
characters, no backslashes). A refused sign-in shows the caller their own `sub` / email and which setting would admit them.

**Sessions.** The `__Host-secrets-web` cookie only carries a random session id (server-side in-memory ticket store),
HttpOnly + Secure + SameSite=Lax, non-persistent; 15 minutes idle (sliding), 8 hours absolute since sign-in. Restarting the
process signs everyone out. Sign-out uses RP-initiated logout when the IdP publishes an `end_session_endpoint`; otherwise
(Google publishes none) only the local session is cleared.

**Reading values.** The list, search and the GET pages of kv and file entries never decrypt; kv decrypts one field per
click. Value endpoints are POST only and require an antiforgery token (`__Host-` cookie, SameSite=Strict) plus the custom
header `X-Secrets-Web`; downloads are a form POST with the token. Shown values are re-masked after 30 seconds. `doc`
entries decrypt on GET only for same-origin navigation (`Sec-Fetch-Site: same-origin | none`), otherwise behind a button.

**Plaintext handling.** Ciphertext goes to `age -d` on stdin, plaintext is read from stdout into a bounded buffer, never
written to disk; beyond the limit the process is killed; byte arrays are wiped after use (best effort). Catalog and
ciphertext reads are pinned to the same commit.

**Validation.** catalog / recipients are parsed as the restricted TOML subset (anything outside it is an error);
ciphertext paths are checked against a regex plus reserved-name exclusion; the `age-encryption.org/v1\n` header is
required; kv is parsed strictly and its field set must equal the catalog's. Any violation is an error, never a guess. Only a
TOML syntax error, a missing / unknown `[[meta]] format`, or an unreadable repo takes the whole site down (503); every other
problem only marks that one entry unavailable, with the reason shown and nothing decrypted.

**Audit.** Every decryption (including failures) writes one JSONL line: `ts / event / sub / path / field / action /
result / reason / suppressed_before / ip` — there is **no value field in the structure**. If the audit line can't be
written, no plaintext is returned (fail closed; on a write error the log is rotated and the write retried once, since
rotation is exactly what helps on a full disk). Logins (successful, failed, refused) and writes are audited too, without
values. Failure lines on the anonymous callback are rate limited per client IP (10/minute, 60/minute globally; suppressed
lines are counted in `suppressed_before`). The rate-limit key is the client IP only — client-supplied headers never
influence it. Behind a reverse proxy, configure `Network:KnownProxies` so the real client IP is used; otherwise every
request appears to come from the proxy and the per-IP limit becomes effectively global. The `ip` field is informational.

**Rate limits and alerts.** Per session: 20 decryptions/minute, 200/hour (429 beyond), 10 writes/minute. The limiter keys
on a random session id stored in the ticket, not on the cookie string (sliding renewal re-issues the cookie). Alerts fire on
login failures, non-allowlisted accounts, `amr` mismatches, more than 30 distinct entries decrypted within 10 minutes, and
more than 5 distinct entries changed within 10 minutes; at most one alert per 10 minutes; alert texts never contain entry
names or subjects.

**Response headers.** `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'
data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on every response, HSTS on HTTPS.

**Markdown.** Raw HTML disabled, no generic attributes; links only http / https / mailto / site-relative (others become
`#`), always `rel="noopener noreferrer"`; external images are replaced by their alt text (they would leak the time of
viewing and your IP), with the CSP as a second layer.

**Child processes.** `git` / `age` run without a shell, with an environment rebuilt from an allowlist (`PATH`, `HOME`, `TZ`,
locale, temp directories, a few Windows process-creation variables, plus fixed `GIT_CONFIG_NOSYSTEM=1`,
`GIT_TERMINAL_PROMPT=0`, `LC_ALL=C`). The OIDC client secret and the alert webhook token never reach them. At most 4 run
concurrently; `/health` is cached for 10 seconds.

**Container.** Non-root (UID 1654), read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, bound to 127.0.0.1;
the bare repo and the identity are mounted read-only. Build the image on the host that runs it rather than on shared CI.

## Writes (create / edit / delete)

Optional: with `Repo:PushUrl` empty the instance is read-only (write endpoints return 400, no write UI). **The read path
never changes — it still reads the read-only bare repo.** Writes take a separate path:

```
form → /api/entry/*  →  working clone (/data/work)
                         ├─ fetch the bare repo + reset --hard (the clone is derived state and can be discarded any time)
                         ├─ pre-check: catalog ↔ store ↔ lock must correspond one to one, and the target ciphertext must
                         │             match the CHash in the lock (a mismatch means someone bypassed the CLI: refuse, keep the evidence)
                         ├─ change: age-encrypt to the recipients policy.toml expands to → decrypt again and compare SHA-256
                         │          → write .age → update catalog.toml (canonical form, unknown keys kept) → update the lock
                         ├─ post-check again; on failure git reset --hard and no push
                         ├─ commit (author = secrets-web, message `web: add personal/x/y (kv)`)
                         └─ git push (deploy key over ssh) → the bare repo is updated, the next read sees it
```

- **Conflicts**: one in-process write lock; a rejected push (the CLI pushed first) → fetch again and **replay only this one
  operation** on the new HEAD (not a rebase), up to 3 times, then 409.
- **Optimistic concurrency (mandatory)**: the edit page carries the fingerprint of the entry block as it was opened;
  `/api/entry/update` **without a fingerprint is 400**, a mismatch is 409 ("reload and edit again").
- **References before delete**: the confirmation page and the delete response list `readers`, `linked` and who links to
  the entry; with inbound links the delete is **refused** (409 + the referencing entries) — change those first, or
  force-delete with the CLI.
- **Aliases** are normalized before writing (strip `[[ ]]`, backslash → slash, drop `.md`, NFC) — the same string the CLI stores.
- **Catalog key order** follows FORMAT exactly, unknown keys are preserved after `updated`, and leading comments are kept,
  so CLI and web writes don't produce churn. There is a byte-for-byte regression test.
- **Plaintext never touches the disk**: values only live in memory and the pipe to `age`; a regression test scans the working clone.
- **Deleting** removes the ciphertext, the catalog entry and the lock line. The old ciphertext stays in git history; to really
  revoke, rotate the value where it was issued.

## Configuration

Every key can be overridden with an environment variable (`:` becomes `__`, array items use `__0`, `__1`, …).
**`Auth__ClientSecret` and `Alerts__WebhookToken` belong in `.env` only** — never in appsettings, compose files or a repo.

| Key | Default | Description |
|---|---|---|
| `PublicOrigin` | empty | Public origin, e.g. `https://secrets.example.com`. Every request's Scheme/Host is rewritten to it (redirect_uri and Secure cookies depend on it). **Required in Production, and must be `https://`** (session and antiforgery cookies are `__Host-` / Secure-only; an `http://` origin is refused at startup) |
| `Deployment:AccessLayer` | empty | Free text naming what protects the service, e.g. `tailscale`, `cloudflare-access`, `vpn`, `reverse-proxy`. **Required in Production** (refuses to start when empty); `none` starts with a prominent warning. Not enforced in Development |
| `Network:KnownProxies` | `[]` | IP addresses of trusted reverse proxies. When this or `KnownNetworks` is non-empty, `X-Forwarded-For` / `X-Forwarded-Proto` are honored from those peers only (one hop; the framework's default loopback trust is cleared). Empty = forwarded headers are ignored |
| `Network:KnownNetworks` | `[]` | CIDR ranges of trusted reverse proxies, e.g. `10.0.0.0/8` |
| `Auth:Authority` | empty | OIDC issuer, e.g. `https://accounts.google.com`. **Required** |
| `Auth:ClientId` | `secrets-web` | Client id registered at the IdP |
| `Auth:ClientSecret` | empty | **Environment only**. Required |
| `Auth:CallbackPath` | `/signin-oidc` | Must match the redirect URI registered at the IdP (`<PublicOrigin>/signin-oidc`) |
| `Auth:Scopes` | `openid email profile` | `email` is needed for `AllowedEmails` |
| `Auth:Resource` | empty | When set, adds an RFC 8707 `resource=` parameter to the authorization request |
| `Auth:AllowedSubjects` | `[]` | id_token `sub` values allowed to sign in (exact, case-sensitive) |
| `Auth:AllowedEmails` | `[]` | Emails allowed to sign in (trimmed, case-insensitive), **only honored when the id_token has `email_verified: true`** (JSON boolean or the string `"true"`). At least one of the two allowlists must be non-empty, otherwise startup fails |
| `Auth:RequireAmr` | empty | When set, the id_token `amr` must contain this value |
| `Auth:IdleTimeoutMinutes` | 15 | Sliding idle expiry |
| `Auth:MaxLifetimeHours` | 8 | Absolute expiry since sign-in |
| `Repo:GitDir` | `/repo` | Bare repo path |
| `Repo:Identity` | `/identity/identity.txt` | age identity file |
| `Repo:GitPath` / `Repo:AgePath` | `git` / `age` | Executables |
| `Repo:CommandTimeoutSeconds` | 30 | Child-process timeout |
| `Repo:FileTextMaxBytes` / `FileMaxBytes` / `DocMaxBytes` | 256 KB / 1 MB / 1 MB | Size limits (text view of file entries / file entries and uploads / doc entries) |
| `Repo:PushUrl` | empty | Push URL for writes, e.g. `ssh://git@git.example.com/you/secrets.git`. **Empty = read-only instance** |
| `Repo:Branch` | `main` | Branch to push |
| `Repo:WorkDir` | `/data/work` | Working clone for writes (must be writable) |
| `Repo:SshKey` / `Repo:KnownHosts` | empty | Deploy key and known_hosts (read-only mounts), assembled into `GIT_SSH_COMMAND` with `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`, `BatchMode=yes` |
| `Repo:CommitAuthorName` / `CommitAuthorEmail` | `secrets-web` / `secrets-web@localhost` | Author and committer of web commits |
| `Repo:FavoritesPath` | `/data/favorites.json` | Server-side favorites (web UI only; not part of the data repo) |
| `Audit:Path` | `/data/audit.log` | JSONL audit log |
| `Audit:MaxBytes` / `Audit:KeepFiles` | 8 MB / 5 | Rotate into `audit.log.1 … .N` (new files 0600 on POSIX); `MaxBytes <= 0` disables rotation |
| `DecryptLimits:PerMinute` / `PerHour` | 20 / 200 | Decryptions per session; 429 beyond |
| `DecryptLimits:WritePerMinute` | 10 | Writes per session per minute |
| `DecryptLimits:DistinctWindowMinutes` / `DistinctThreshold` | 10 / 30 | More distinct entries decrypted within the window → one alert (without entry names) |
| `Alerts:WebhookUrl` | empty | Alerts are POSTed here as JSON `{"title": "...", "text": "...", "severity": "warning"}`. Empty = log only |
| `Alerts:WebhookToken` | empty | Optional, sent as `Authorization: Bearer <token>`. **Environment only** |
| `Alerts:MinIntervalMinutes` | 10 | At most one alert per window; the suppressed count is carried in the next one |
| `Alerts:WriteDistinctEntries` / `Alerts:WriteWindowMinutes` | 5 / 10 | More distinct entries changed within the window → one alert (without entry names) |

The alert webhook is deliberately generic: point it at a small relay for your chat or pager (the payload never contains
entry names, so it is safe to forward to a chat channel).

## Google as the OpenID Connect provider

1. In the Google Cloud console, open **APIs & Services → OAuth consent screen** and configure it. For personal use,
   "External" in testing mode with yourself as a test user is enough; for a Google Workspace organization use "Internal".
   The scopes `openid`, `email` and `profile` are non-sensitive.
2. **APIs & Services → Credentials → Create credentials → OAuth client ID**, application type **Web application**.
   Under **Authorized redirect URIs** add `<PublicOrigin>/signin-oidc`, e.g. `https://secrets.example.com/signin-oidc`.
   JavaScript origins are not needed.
3. Configure the service:
   - `Auth__Authority=https://accounts.google.com`
   - `Auth__ClientId=<client id>.apps.googleusercontent.com`
   - `Auth__ClientSecret=<client secret>` — **in `.env` only**
4. Allowlist yourself, either way:
   - by email: `Auth__AllowedEmails__0=you@example.com` (Google marks the email of a Google account as verified;
     unverified emails never match), or
   - by subject: sign in once — the "Access denied" page shows your `sub` (a stable numeric Google account id) — and set
     `Auth__AllowedSubjects__0=<sub>`. Subjects never change or get reassigned, so they are the stricter choice.
5. Sign-out: Google has no `end_session_endpoint`, so signing out clears the session of this service only; you stay signed
   in to Google in that browser. On a shared device, sign out of Google as well.

Any other OIDC provider works the same way as long as it supports the authorization code flow with PKCE, a confidential
client (`client_secret_post`), `response_mode=query`, and RS256-signed id_tokens.

## Deployment

1. **Identity**: `age-keygen -o identity.txt`, `chown 1654:1654 identity.txt`, `chmod 600 identity.txt`. Register the public
   key (`age-keygen -y identity.txt`) as a `service` recipient and rekey (see *Security model*).
2. **Repo**: make a bare copy of the secrets repo readable by UID 1654 at `deploy/repo.git` (or mount the git server's own
   bare repo read-only). Keep it current, e.g. mount the git server's copy, or have the writer push to it.
3. **Writes (optional)**: a deploy key with write access to the repo (`deploy_key`, mode 600, owner 1654) and a
   `known_hosts` file containing the git server's host key; set `Repo__PushUrl`. Leave `Repo__PushUrl` empty for a
   read-only instance.
4. **Data**: `mkdir data && chown 1654:1654 data` (audit log, favorites, working clone).
5. **`.env`** (mode 600): `Auth__ClientSecret=…`, optionally `Alerts__WebhookUrl=…` and `Alerts__WebhookToken=…`.
6. **Build**: `docker build -t secrets-web:local .` in `web/`, on the host that runs it.
7. **Start**: adjust `deploy/docker-compose.yml` (PublicOrigin, Authority, ClientId, allowlist, AccessLayer, PushUrl) and
   `docker compose up -d`.
8. **Publish** port `127.0.0.1:8099` only through your access layer. If the proxy connects from another address (a
   container network, a separate host), set `Network__KnownProxies__0` / `Network__KnownNetworks__0` to exactly that proxy.
9. **Verify**: `curl -s http://127.0.0.1:8099/health` returns `status: ok` and `head` equals the repo HEAD (`secret check
   --web <url>` does this too); sign in, view and copy a value once and check `data/audit.log`; confirm the service is not
   reachable without the access layer.

## Endpoints

| Path | Description |
|---|---|
| `GET /` | Tree by domain / group; `?q=` searches path, title, description, tags. Reads the catalog only, never decrypts |
| `GET /entry/<domain>/<group>/<name>` | Entry page. `doc` is decrypted and rendered only when `Sec-Fetch-Site` is `same-origin` / `none` (audited as `view`), otherwise a "Click to view" button (POST + antiforgery); `kv` lists field names with masked values; `file` shows buttons; entries with invalid metadata show the reason and are not decrypted |
| `POST /api/field` | Decrypt **one** kv field (`mode=show|copy`); needs the antiforgery token + `X-Secrets-Web` header |
| `POST /api/file` | `file` entry: text if UTF-8 and ≤ 256 KB, otherwise only the size; token + custom header |
| `POST /api/download` | `file` download (≤ 1 MB); form POST + antiforgery token |
| `POST /api/favorite` | Toggle a favorite (server-side file, no decryption, not audited); token + custom header |
| `GET /new` | Create form (hidden on a read-only instance) |
| `GET /entry/<path>/edit` | Edit form (GET doesn't decrypt; "Load current content" is a POST that decrypts and is audited) |
| `GET /entry/<path>/delete` | Delete confirmation; issues a one-time token (bound to session + path, 5 minutes) |
| `POST /api/entry/create` / `update` / `delete` | Writes (multipart form). Same protections as decryption: POST + antiforgery + `X-Secrets-Web` + allowlist + rate limit; delete also needs the one-time token |
| `GET /login` / `POST /logout` | Start OIDC sign-in / sign out (server-side session removed, RP-initiated logout when supported) |
| `GET /health` | Anonymous, cached 10 seconds: `{status, head, format, entries, invalidEntries, consistency: {consistent, catalogEntries, storeFiles, lockLines}}`. `status=error` / HTTP 503 only on a TOML syntax error, missing / unknown format, or an unreadable repo. Never contains entry names |

## Development and tests

Requires `git`, `age`, `age-keygen` on `PATH` and the .NET 10 SDK.

```
dotnet test
```

Integration tests generate a test identity in a temp directory, encrypt random test values with the age CLI, build a test
bare repo, and run the app through `WebApplicationFactory` with a test authentication scheme or a fake IdP. No real data is
involved. In the `Development` environment the access-layer guard is not enforced.

### Local try-out against a real IdP

Run with `ASPNETCORE_ENVIRONMENT=Development` and `PublicOrigin=http://localhost:8099` (plus `ASPNETCORE_URLS=http://localhost:8099`).
Only in Development are cookies issued without the `__Host-` prefix and without Secure, so plain `http://localhost` works;
the app logs a warning at startup. Register `http://localhost:8099/signin-oidc` as a redirect URI at your IdP (Google accepts
`http://localhost` for Web clients) and remove it again afterwards. Point `Repo:GitDir` / `Repo:PushUrl` at a local bare repo
with test values only, and set `Repo:WorkDir`, `Repo:FavoritesPath`, `Audit:Path` to a scratch directory. Never expose a
Development instance.
