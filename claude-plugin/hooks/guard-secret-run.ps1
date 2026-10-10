# PreToolUse hook for the secret-run Claude Code plugin.
#
# Mechanical backstop for the `use-secret-run` skill: the only correct way to read a value is
# `secret run -e NAME=<path>#<FIELD> -- <command>` (value goes into the child's environment only).
# This hook denies the tool calls that would instead put a value into the conversation:
#
#   1. `secret get` / `secret show` / `secret edit` (prints the value or opens an editor on it);
#   2. `secret run ... -- <child>` whose child command re-prints an injected value
#      (`echo $NAME`, `printenv`, `curl -H "... $NAME"`, ...) -- the correct form itself can be
#      defeated this way;
#   3. decrypting outside the CLI: `age -d` / `age --decrypt` on a repo ciphertext, or dot-sourcing
#      SecretLib.ps1 (or equivalent) to call Sec-ReadField / Sec-GetField / Sec-GetEntryBytes /
#      Sec-KvParse / Sec-AgeDecrypt directly -- same decrypt path `secret get` uses, called by hand;
#   4. reading key material: the identity file (default `~/.config/secrets/identity.txt`, or
#      `SECRET_IDENTITY` / `--identity` when set), a `recovery/*.age` file, or a
#      `secret-recovery-identity-*.txt` left on the Desktop by `secret recovery new`;
#   5. reading an environment variable that already looks like it holds a credential
#      (`*_KEY` / `*_TOKEN` / `*_SECRET` / `*_PASSWORD` / `*_PASSWD`).
#
# Not denied (normal, value-free operations): `secret run/list/info/resolve/check/recipients/
# materialize/init/hooks/add/recovery/inventory` on their own; search patterns, `--exclude-dir=`
# style option values, `sed`/`perl` replacement strings, `git commit -m` message text.
#
# Known gap (by design, not fixed here): `secret run -e T=... -- pwsh -File <script already on
# disk>` is not caught -- the hook never sees what that script does with the value. Parsing every
# script an agent might invoke is not worth the false-positive rate; this guards the instinctive
# mistakes (typing `secret get`, `echo $TOKEN`), not a determined bypass. See the skill's own
# "never do these" list, which still applies where this hook stays quiet.
#
# Fail-open: a crash, timeout, or bad JSON here must never block a legitimate tool call -- a broken
# hook is a missing backstop, not a hard stop. (Same choice secret-run itself makes for masking:
# best-effort, not a security boundary on its own. See README.md "Security model".)
#
# Self-test: cli/test/selftest.ps1 is this project's own style; the equivalent for this hook is
# ../test/test-guard-secret-run.ps1 (feeds it stdin JSON fixtures, asserts deny / allow).
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
# stdin must be decoded as UTF-8 explicitly: on a host whose console code page isn't UTF-8, the
# default decode is lossy and a non-ASCII path in tool_input would silently fail every regex below.
$raw = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false)).ReadToEnd()
try { $j = $raw | ConvertFrom-Json } catch { exit 0 }

function Deny([string]$why) {
    $msg = "secret-run guard: $why. The only way to read a value is " +
           '`secret run -e NAME=<path>#<FIELD> -- <command>` (value goes into the child process ' +
           'environment only, never into this conversation). Browse entries with `secret list` / ' +
           '`secret info <path>` / `secret resolve <old pointer>` -- none of those decrypt anything. ' +
           'If a human needs to see the actual value, they run `secret show <path>` themselves.'
    @{ hookSpecificOutput = @{ hookEventName = 'PreToolUse'; permissionDecision = 'deny'; permissionDecisionReason = $msg } } |
        ConvertTo-Json -Depth 5 -Compress
    exit 0
}

# This machine's identity path: SECRET_IDENTITY if set, else the documented default
# (~/.config/secrets/identity.txt -- FORMAT.md §9 / SecretLib.ps1 Sec-DefaultIdentity).
$identityOverride = $env:SECRET_IDENTITY
$isWindows = ($env:OS -eq 'Windows_NT')

# Path-shaped rules: forward and backward slashes, case-insensitive (Windows paths aren't
# case-sensitive and an agent may normalize separators either way).
$pathRules = New-Object 'System.Collections.Generic.List[object]'
if ($identityOverride) {
    $escaped = [regex]::Escape($identityOverride) -replace '\\\\', '[\\\\/]'
    [void]$pathRules.Add(@{ re = "(?i)$escaped"; why = 'reading this machine''s SECRET_IDENTITY file' })
}
[void]$pathRules.Add(@{ re = '(?i)\.config[\\/]+secrets[\\/]+identity\.txt'; why = "reading this machine's age identity file" })
[void]$pathRules.Add(@{ re = '(?i)recovery[\\/]+recovery-identity\.age'; why = 'reading the sealed recovery identity' })
[void]$pathRules.Add(@{ re = '(?i)secret-recovery-identity-[^"''\s]*\.txt'; why = 'reading a recovery identity file left on the Desktop' })

$tool = [string]$j.tool_name
if ($tool -in @('Read', 'Grep', 'Glob', 'NotebookRead')) {
    $ti = $j.tool_input
    foreach ($t in @($ti.file_path, $ti.path, $ti.notebook_path) | Where-Object { $_ }) {
        $s = [string]$t
        foreach ($r in $pathRules) { if ($s -match $r.re) { Deny $r.why } }
    }
    exit 0
}

if ($tool -cnotin @('Bash', 'exec_command', 'shell')) { exit 0 }   # the latter two are Codex's tool names
$cmd = $j.tool_input.command
if ($cmd -is [array]) { $cmd = $cmd -join ' ' }
if (-not $cmd) { exit 0 }

# ---- strip fragments that merely *name* something without reading/printing it; every check below
# runs against $check, never the raw $cmd ----
$check = $cmd
# 1) message / text arguments: git commit -m, echo/printf/Write-Host of a quoted literal
$check = [regex]::Replace($check, '(?i)(-m|--message)(=|\s+)("[^"]*"|''[^'']*'')', ' ')
$check = [regex]::Replace($check, '(?i)(^|[\s;&|(])(echo|printf|Write-Host|Write-Output)(\.exe)?\s+(-\S+\s+)*("[^"]*"|''[^'']*'')', ' ')
# 2) search-command pattern strings
$check = [regex]::Replace($check, '(?i)(^|[\s;&|(])(grep|rg|ag|findstr|Select-String)(\.exe)?\s+((-\S+|--\S+)\s+)*(?<p>"[^"]*"|''[^'']*''|\S+)',
    { param($m) $m.Value.Replace($m.Groups['p'].Value, ' ') })
# 3) option values that exclude/include a path rather than read it
$check = [regex]::Replace($check, '(?i)--(exclude-dir|exclude|include|glob|iglob)=("[^"]*"|''[^'']*''|\S+)', ' ')
# 4) sed / perl replacement strings
$check = [regex]::Replace($check, '(?i)(^|[\s;&|(])(sed|perl)(\.exe)?\s[^|;&]*?(?<s>"s[/#|][^"]*"|''s[/#|][^'']*'')',
    { param($m) $m.Value.Replace($m.Groups['s'].Value, ' ') })
# 5) secret CLI subcommands that never decrypt a value -- their arguments are paths/metadata, not
#    reasons to flag a path-rule match
$check = [regex]::Replace($check, '(?i)(^|[\s;&|(''"/\\])secret(\.ps1|\.cmd)?["'']?\s+(--?\S+\s+)*(resolve|info|list|check|recipients|materialize|init|hooks|add|recovery|inventory|rekey|rm)\b[^|;&]*',
    ' ')

# ---- 1. secret get / show / edit ----
if ($check -match '(?i)(^|[\s;&|(''"/\\])secret(\.ps1|\.cmd)?["'']?\s+(--?\S+\s+(\S+\s+)?)*(get|show|edit)(\s|$|["''])') {
    Deny 'running `secret get` / `show` / `edit` directly would print the value'
}

# ---- 2. secret run whose child command re-prints an injected value ----
$m = [regex]::Match($cmd, '(?i)(^|[\s;&|(''"/\\])secret(\.ps1|\.cmd)?["'']?\s+(?<rest>.*)$')
if ($m.Success -and $m.Groups['rest'].Value -match '(?i)^(--?\S+\s+\S*\s*)*run\b') {
    $rest = $m.Groups['rest'].Value
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in [regex]::Matches($rest, '(?i)(^|\s)-e\s+([A-Za-z_][A-Za-z0-9_]*)=')) { $names.Add($e.Groups[2].Value) }
    # `-a [PREFIX=]<path>` injects a whole entry's field names, which this hook can't know without
    # decrypting the catalog itself -- only the by-name check below is possible for `-a`; the
    # print/exfiltrate-shaped check a few lines down still applies to it.
    $sep = [regex]::Match($rest, '(?<=\s)--(\s|$)')
    $child = if ($sep.Success) { $rest.Substring($sep.Index) } else { '' }
    if ($child) {
        foreach ($n in $names) {
            $esc = [regex]::Escape($n)
            if ($child -match ('(?i)(\$\{?|\$env:|%|process\.env\.|process\.environ?\[|getenv\()\s*["'']?' + $esc)) {
                Deny "the child command of secret run reads back the value it was just given ($n)"
            }
        }
        if ($child -match '(?i)(^|[\s;&|(])(echo|print|printf|printenv|env|set|cat|type|curl|wget|Write-Host|Write-Output|Out-File|Set-Content|Add-Content|iwr|Invoke-WebRequest|Invoke-RestMethod)(\.exe)?(\s|$)') {
            Deny 'the child command of secret run is a print / exfiltrate-shaped command (echo, printenv, curl, ...)'
        }
    }
}

# ---- 3. decrypting outside the CLI ----
if ($check -match '(?i)\bSec-(ReadField|GetField|GetEntryBytes|AgeDecrypt|KvParse)\b' -or
    $check -match '(?i)(^|[\s;&|(''"])age(\.exe)?\s+([^|;&]*\s)?(-d|--decrypt)(\s|$)') {
    Deny 'decrypting directly (SecretLib.ps1 functions / age -d) is `secret get` with extra steps'
}

# ---- 4. reading key material by path ----
foreach ($r in $pathRules) { if ($check -match $r.re) { Deny $r.why } }

# ---- 5. reading an environment variable that already looks like a credential ----
if ($check -match '(?i)(\$\{?|\$env:|%|process\.env\.|process\.environ?\[["'']|getenv\(["'']|printenv\s+|GetEnvironmentVariable\(\s*["''])[A-Za-z_]*((API_)?KEY|TOKEN|SECRET|PASSWORD|PASSWD)\b' -or
    ($check -match '(?i)(^|[\s;&|]\s*|\|\s*)(printenv|env|set)(\s*$|\s*[|;&])' -and $check -notmatch '(?i)[=(){}]\s*(printenv|env|set)\s*[;)]') -or
    $check -match '(?i)(Get-ChildItem|gci|ls|dir)\s+env:') {
    Deny 'reading an environment variable that already looks like a credential'
}
exit 0
