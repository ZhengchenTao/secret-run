# cli/secret.ps1 -- `secret` CLI for a secret-run data repo (contract: FORMAT.md v1).
# ASCII-only (Windows PowerShell 5.1 misreads BOM-less UTF-8 scripts). Runs on 5.1 and pwsh 7. See README.md.
#
# Never prints a value: only `get` (raw to stdout, for scripts) and `show` (for humans) emit plaintext on purpose.
# Errors never include plaintext. `run` puts values only into the child's environment, and when its output is
# captured (pipe / file / AI tool) replaces any injected value the child prints with <concealed:NAME>.
#
# Exit codes are reliable when called directly or via the shims. When a scheduled task wraps a service in
# `conhost --headless ... secret run ...`, conhost swallows the exit code (the task result is always "success"):
# keep-alive there must be judged by process liveness, not by exit code.

$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, 'SecretLib.ps1'))

$script:G = @{ Repo = $null; Identity = $null; Pull = $false; Pulled = $false; LockTimeout = 30; Lock = $null; Cmd = '' }

function Parse-LockTimeout([string]$v) {
    $n = 0
    if (-not [int]::TryParse($v, [ref]$n) -or $n -lt 0) { Sec-Fail '--lock-timeout needs a non-negative number of seconds' }
    return $n
}

function Out-Line([string]$s) { [Console]::Out.Write($s + "`n") }
function Err-Line([string]$s) { [Console]::Error.Write($s + "`n") }

function Get-RepoDir {
    if ($script:G.Repo) { return $script:G.Repo }
    if ($env:SECRET_REPO) { return $env:SECRET_REPO }
    return (Sec-DefaultRepo)
}
function Get-IdentityPath {
    if ($script:G.Identity) { return $script:G.Identity }
    if ($env:SECRET_IDENTITY) { return $env:SECRET_IDENTITY }
    return (Sec-DefaultIdentity)
}
function Get-DesktopDir {
    if ($env:SECRET_DESKTOP) { return $env:SECRET_DESKTOP }   # test-only override
    return [Environment]::GetFolderPath('Desktop')
}

# spec: hashtable option -> 'switch' | 'value' | 'multi'. Global --repo/--identity/--pull accepted anywhere.
function Parse-Opts([string[]]$Argv, [hashtable]$Spec, [switch]$LocalIdentity) {
    $opts = @{}
    $pos = New-Object 'System.Collections.Generic.List[string]'
    $i = 0
    while ($i -lt $Argv.Length) {
        $a = $Argv[$i]
        $specKey = $null
        foreach ($k in $Spec.Keys) { if ($k -ceq $a) { $specKey = $k } }
        if ($specKey) {
            $kind = $Spec[$specKey]
            if ($kind -ceq 'switch') { $opts[$specKey] = $true; $i++; continue }
            if ($i + 1 -ge $Argv.Length) { Sec-Fail "option $a needs a value" }
            if ($kind -ceq 'multi') {
                if (-not $opts.ContainsKey($specKey)) { $opts[$specKey] = New-Object 'System.Collections.Generic.List[string]' }
                $opts[$specKey].Add($Argv[$i + 1])
            } else { $opts[$specKey] = $Argv[$i + 1] }
            $i += 2; continue
        }
        if ($a -ceq '--repo' -or ($a -ceq '--identity' -and -not $LocalIdentity)) {
            if ($i + 1 -ge $Argv.Length) { Sec-Fail "option $a needs a value" }
            if ($a -ceq '--repo') { $script:G.Repo = $Argv[$i + 1] } else { $script:G.Identity = $Argv[$i + 1] }
            $i += 2; continue
        }
        if ($a -ceq '--pull') { $script:G.Pull = $true; $i++; continue }
        if ($a -ceq '--lock-timeout') {
            if ($i + 1 -ge $Argv.Length) { Sec-Fail 'option --lock-timeout needs a value' }
            $script:G.LockTimeout = Parse-LockTimeout $Argv[$i + 1]
            $i += 2; continue
        }
        if ($a.Length -gt 1 -and $a.StartsWith('-')) { Sec-Fail "unknown option: $a" }
        $pos.Add($a); $i++
    }
    return (New-Object psobject -Property @{ Opts = $opts; Pos = $pos })
}
function Opt($p, [string]$name) { if ($p.Opts.ContainsKey($name)) { return $p.Opts[$name] }; return $null }

function Open-Ctx([switch]$Write) {
    $repo = Get-RepoDir
    if ($script:G.Pull -and -not $script:G.Pulled) {
        $script:G.Pulled = $true
        $r = Sec-Git $repo @('pull', '--ff-only') $null
        if ($r.Out) { [Console]::Error.Write($r.Out) }
        if ($r.Err) { [Console]::Error.Write($r.Err) }
        if ($r.Code -ne 0) { Sec-Fail 'git pull --ff-only failed' }
    }
    if ($Write) {
        Take-RepoLock $repo
        Warn-IfBehind $repo
        return (Sec-OpenRepo $repo -Strict)
    }
    $ctx = Sec-OpenRepo $repo -Strict -AllowEntryErrors
    foreach ($n in $ctx.Notes) { Err-Line ('note: ' + $n) }
    return $ctx
}

# Refuse to overwrite a ciphertext whose bytes no longer match the lock (changed outside the CLI).
function Assert-LockIntact($Ctx, $Lock, [string]$StorePath) {
    $f = Sec-RepoFile $Ctx $StorePath
    if ([IO.File]::Exists($f) -and $Lock.ContainsKey($StorePath)) {
        if ($Lock[$StorePath].CHash -cne (Sec-Sha256Hex ([IO.File]::ReadAllBytes($f)))) {
            Sec-Fail "$StorePath`: ciphertext changed outside the CLI (lock hash mismatch); inspect it first"
        }
    }
}

function Ask-Reopen([string]$Why) {
    [Console]::Error.Write('invalid content: ' + $Why + "`n" + 'reopen the editor to fix it? [Y/n] ')
    $a = [Console]::In.ReadLine()
    if ($null -eq $a) { [Console]::Error.Write("`n"); return $false }
    return ($a.Trim() -notmatch '^(n|no)$')
}

# Editor loop on an existing temp file: returns prepared plaintext, or $null when content equals $Original.
function Edit-Until-Valid([string]$Tmp, [string]$Type, [byte[]]$Original) {
    while ($true) {
        Invoke-Editor $Tmp
        $raw = [IO.File]::ReadAllBytes($Tmp)
        if ($null -ne $Original -and (Sec-Sha256Hex $raw) -ceq (Sec-Sha256Hex $Original)) { return $null }
        try { return (Prepare-Plain $Type $raw) }
        catch { if (-not (Ask-Reopen $_.Exception.Message)) { Sec-Fail 'aborted; nothing written' } }
    }
}

# Committing on top of a stale clone means the next push hits a catalog.toml text conflict; warn, do not block.
function Warn-IfBehind([string]$Repo) {
    if (-not (Sec-IsGitRepo $Repo)) { return }
    $u = Sec-Git $Repo @('rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}') $null
    if ($u.Code -ne 0) { return }
    $b = Sec-Git $Repo @('rev-list', '--count', 'HEAD..@{u}') $null
    if ($b.Code -ne 0) { return }
    $n = 0
    if (-not [int]::TryParse($b.Out.Trim(), [ref]$n) -or $n -le 0) { return }
    Err-Line ("WARN: this clone is $n commit(s) behind " + $u.Out.Trim() + "; writing on top of it invites a conflict. Consider '--pull' or 'git -C $Repo pull --rebase' first")
}

# Write commands hold a machine-local lock for the whole run; released in the outer finally (and by the OS on exit).
function Take-RepoLock([string]$Repo) {
    if ($null -ne $script:G.Lock) { return }
    $script:G.Lock = Sec-AcquireLock $Repo $script:G.LockTimeout $script:G.Cmd
}

function Require-Identity {
    $id = Get-IdentityPath
    if (-not [IO.File]::Exists($id)) { Sec-Fail "identity not found: $id (run 'secret init' or set SECRET_IDENTITY)" }
    return $id
}

# git add the touched files; --commit / --push only when asked.
# Stage the files this command touched and, by default, commit exactly those (never the rest of the work tree).
# --no-commit stages only; --commit "<msg>" overrides the generated message; --push is always explicit.
function Finish-Write($Ctx, [string[]]$Rels, $P, [string]$AutoMsg) {
    if (-not (Sec-IsGitRepo $Ctx.Dir)) { Err-Line 'note: repo is not a git work tree; nothing staged'; return }
    $mine = Sec-NewSet
    foreach ($r in $Rels) { if ($r) { [void]$mine.Add($r) } }
    # unrelated dirty files: warn, do not block (a batch import legitimately touches many entries in a row)
    $st = Sec-Git $Ctx.Dir @('status', '--porcelain', '--', 'catalog.toml', 'policy.toml', 'recipients.toml', 'store', 'INCIDENT.md') $null
    if ($st.Code -eq 0) {
        $others = New-Object 'System.Collections.Generic.List[string]'
        foreach ($line in $st.Out.Split([char]10)) {
            $l = $line.TrimEnd([char]13)
            if ($l.Length -lt 4) { continue }
            $f = $l.Substring(3).Trim('"')
            $arrow = $f.IndexOf(' -> ')
            if ($arrow -ge 0) { $f = $f.Substring($arrow + 4) }
            if (-not $mine.Contains($f) -and -not $others.Contains($f)) { $others.Add($f) }
        }
        if ($others.Count -gt 0) {
            Err-Line ('WARN: the repo has other uncommitted changes, not included in this commit: ' + ((@($others) | Select-Object -First 10) -join ', '))
        }
    }
    $a = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in @('add', '-A', '--')) { $a.Add($x) }
    foreach ($r in $Rels) { if ($r) { $a.Add($r) } }
    $g = Sec-Git $Ctx.Dir $a.ToArray() $null
    if ($g.Code -ne 0) { Err-Line $g.Err; Sec-Fail 'git add failed' }
    $msg = Opt $P '--commit'
    if (-not $msg) { $msg = $AutoMsg }
    if ((Opt $P '--no-commit') -or -not $msg) {
        if (Opt $P '--no-commit') { Err-Line 'staged, not committed (--no-commit). Later write commands commit only their own files, so this stays staged until you commit it yourself' }
        if (Opt $P '--push') { Sec-Fail 'nothing committed, so nothing to push (drop --no-commit)' }
        return
    }
    # commit exactly the staged paths of this command
    $staged = Sec-Git $Ctx.Dir @('diff', '--cached', '--name-only', '-z') $null
    $toCommit = New-Object 'System.Collections.Generic.List[string]'
    if ($staged.Code -eq 0) {
        foreach ($f in ($staged.Out.Split([char]0) | Where-Object { $_.Length -gt 0 })) { if ($mine.Contains($f)) { $toCommit.Add($f) } }
    }
    if ($toCommit.Count -eq 0) { Err-Line 'nothing to commit'; return }
    $c = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in @('commit', '-m', $msg, '--')) { $c.Add($x) }
    foreach ($f in $toCommit) { $c.Add($f) }
    $g = Sec-Git $Ctx.Dir $c.ToArray() $null
    if ($g.Code -ne 0) { if ($g.Out) { [Console]::Error.Write($g.Out) }; if ($g.Err) { [Console]::Error.Write($g.Err) }; Sec-Fail 'git commit failed' }
    Err-Line ('committed: ' + $msg)
    if (Opt $P '--push') {
        $g = Sec-Git $Ctx.Dir @('push') $null
        if ($g.Err) { [Console]::Error.Write($g.Err) }
        if ($g.Code -ne 0) {
            $all = $g.Err + $g.Out
            if ($all -match 'non-fast-forward' -or $all -match 'rejected' -or $all -match 'fetch first') {
                Sec-Fail ("git push was rejected (the remote moved on). Do NOT rebase automatically: run 'git -C " + $Ctx.Dir + " pull --rebase', then 'git push', then 'secret check'")
            }
            Sec-Fail 'git push failed'
        }
    }
}

function Add-WriteSpec([hashtable]$Spec) { $Spec['--commit'] = 'value'; $Spec['--no-commit'] = 'switch'; $Spec['--push'] = 'switch'; return $Spec }

function Get-HostExe { return [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }

# Resolve a command for run / editor -> @{ File; Args (already-quoted string prefix) }
function Resolve-Launch([string]$Command, [string[]]$CmdArgs) {
    $all = @(Get-Command $Command -CommandType Application, ExternalScript -ErrorAction SilentlyContinue)
    if ($all.Count -eq 0) { Sec-Fail "command not found: $Command" }
    $c = $all[0]
    if (Sec-IsWindows) {
        # only real Windows executables (PATHEXT) or .ps1; extension-less shell scripts cannot be started directly
        $exts = @(([string]$env:PATHEXT).ToLowerInvariant() -split ';' | Where-Object { $_ })
        if ($exts.Count -eq 0) { $exts = @('.com', '.exe', '.bat', '.cmd') }
        $ok = @($all | Where-Object { $_.CommandType -eq 'ExternalScript' -or ($exts -contains [IO.Path]::GetExtension($_.Path).ToLowerInvariant()) })
        if ($ok.Count -eq 0) {
            Sec-Fail ("not a Windows executable: $Command (extension not in PATHEXT; run shell scripts through bash explicitly, e.g. -- bash script.sh)")
        }
        $c = $ok[0]
    }
    $argStr = Sec-JoinArgs $CmdArgs
    if ($c.CommandType -eq 'ExternalScript') {
        $pre = '-NoProfile -ExecutionPolicy Bypass -File ' + (Sec-QuoteArg $c.Path)
        if ($argStr) { $pre += ' ' + $argStr }
        return (New-Object psobject -Property @{ File = (Get-HostExe); Args = $pre })
    }
    $path = $c.Path
    $ext = [IO.Path]::GetExtension($path).ToLowerInvariant()
    if ((Sec-IsWindows) -and ($ext -eq '.cmd' -or $ext -eq '.bat')) {
        $inner = '"' + $path + '"'
        if ($argStr) { $inner += ' ' + $argStr }
        $cmdExe = [IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'cmd.exe')
        return (New-Object psobject -Property @{ File = $cmdExe; Args = ('/d /s /c "' + $inner + '"') })
    }
    return (New-Object psobject -Property @{ File = $path; Args = $argStr })
}

function Start-Inherited($Launch, $EnvMap) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Launch.File
    $psi.Arguments = $Launch.Args
    $psi.UseShellExecute = $false
    if ($EnvMap) { foreach ($k in $EnvMap.Keys) { $psi.EnvironmentVariables[$k] = $EnvMap[$k] } }
    $p = [Diagnostics.Process]::Start($psi)
    $p.WaitForExit()
    $code = $p.ExitCode
    $p.Dispose()
    return $code
}

# ---- `run` output masking (same idea as 1Password `op run`)
# When our stdout / stderr is redirected (an AI tool capturing output, a log file, a pipe), the child's matching
# stream is piped through us and every injected value (its UTF-8 bytes, >= MaskMinLen) becomes <concealed:NAME>.
# A console stream stays inherited, so a human at a terminal and `conhost --headless` services keep a real console
# and see no change. Matching runs on raw bytes (Latin-1 view, 1:1), so binary / non-UTF-8 output passes through.
# A trailing partial match is held back until the next read, or flushed after MaskIdleMs of silence so prompts
# without a newline still show. After the child exits we drain for at most MaskDrainMs (a grandchild may keep
# the pipe open). Not covered: values the child transforms (base64, URL-encoding), values split by a pause longer
# than MaskIdleMs, values shorter than MaskMinLen (short values like `true` / a port would garble ordinary output).
$script:MaskMinLen = 6
$script:MaskIdleMs = 200
$script:MaskDrainMs = 2000
$script:Latin1 = [Text.Encoding]::GetEncoding(28591)

function New-MaskSet($EnvMap) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $items = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in $EnvMap.Keys) {
        $v = $EnvMap[$k]
        if ($null -eq $v) { continue }
        $b = $utf8.GetBytes([string]$v)
        if ($b.Length -lt $script:MaskMinLen) { continue }
        $s = $script:Latin1.GetString($b)
        if (-not $seen.Add($s)) { continue }
        $items.Add((New-Object psobject -Property @{ Key = $s; Repl = ('<concealed:' + $k + '>') }))
    }
    # longest first, so a value that contains another value is replaced whole
    return @($items | Sort-Object -Property @{ Expression = { $_.Key.Length } } -Descending)
}

# length of the longest suffix of $s that is a proper prefix of some masked value (held back for the next read)
function Get-MaskHold([string]$s, $Set, [int]$MaxLen, $Firsts) {
    $lim = [Math]::Min($s.Length, $MaxLen - 1)
    for ($k = $lim; $k -ge 1; $k--) {
        if (-not $Firsts.Contains($s[$s.Length - $k])) { continue }
        $suf = $s.Substring($s.Length - $k)
        foreach ($m in $Set) { if ($m.Key.Length -gt $k -and $m.Key.StartsWith($suf, [StringComparison]::Ordinal)) { return $k } }
    }
    return 0
}

function Write-MaskPump($Q, [string]$s) {
    if ($s.Length -eq 0) { return }
    $b = $script:Latin1.GetBytes($s)
    try { $Q.Out.Write($b, 0, $b.Length); $Q.Out.Flush() } catch { }
}

function Start-Masked($Launch, $EnvMap, [bool]$MaskOut, [bool]$MaskErr) {
    $set = @()
    if ($EnvMap) { $set = @(New-MaskSet $EnvMap) }
    if ($set.Count -eq 0 -or -not ($MaskOut -or $MaskErr)) { return (Start-Inherited $Launch $EnvMap) }
    $maxLen = 0
    $firsts = New-Object 'System.Collections.Generic.HashSet[char]'
    foreach ($m in $set) { if ($m.Key.Length -gt $maxLen) { $maxLen = $m.Key.Length }; [void]$firsts.Add($m.Key[0]) }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Launch.File
    $psi.Arguments = $Launch.Args
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $MaskOut
    $psi.RedirectStandardError = $MaskErr
    foreach ($k in $EnvMap.Keys) { $psi.EnvironmentVariables[$k] = $EnvMap[$k] }
    $p = [Diagnostics.Process]::Start($psi)
    $pumps = New-Object 'System.Collections.Generic.List[object]'
    if ($MaskOut) { $pumps.Add(@{ In = $p.StandardOutput.BaseStream; Out = [Console]::OpenStandardOutput(); Buf = (New-Object byte[] 8192); Task = $null; Pend = ''; Done = $false }) }
    if ($MaskErr) { $pumps.Add(@{ In = $p.StandardError.BaseStream; Out = [Console]::OpenStandardError(); Buf = (New-Object byte[] 8192); Task = $null; Pend = ''; Done = $false }) }
    $exitAt = $null
    while ($true) {
        $live = @($pumps | Where-Object { -not $_.Done })
        if ($live.Count -eq 0) { break }
        foreach ($q in $live) { if ($null -eq $q.Task) { $q.Task = $q.In.ReadAsync($q.Buf, 0, $q.Buf.Length) } }
        $tasks = [System.Threading.Tasks.Task[]]@($live | ForEach-Object { $_.Task })
        $idx = [System.Threading.Tasks.Task]::WaitAny($tasks, $script:MaskIdleMs)
        if ($idx -lt 0) {
            # quiet: release held-back tails (a prompt without newline must not hang), then check the drain deadline
            foreach ($q in $live) { Write-MaskPump $q $q.Pend; $q.Pend = '' }
            if ($p.HasExited) {
                if ($null -eq $exitAt) { $exitAt = [DateTime]::UtcNow }
                elseif (([DateTime]::UtcNow - $exitAt).TotalMilliseconds -ge $script:MaskDrainMs) { break }
            }
            continue
        }
        $q = $live[$idx]
        $t = $q.Task; $q.Task = $null
        $n = 0
        try { $n = $t.Result } catch { $n = 0 }
        if ($n -le 0) { Write-MaskPump $q $q.Pend; $q.Pend = ''; $q.Done = $true; continue }
        $s = $q.Pend + $script:Latin1.GetString($q.Buf, 0, $n)
        foreach ($m in $set) { $s = $s.Replace($m.Key, $m.Repl) }
        $hold = Get-MaskHold $s $set $maxLen $firsts
        Write-MaskPump $q $s.Substring(0, $s.Length - $hold)
        $q.Pend = $s.Substring($s.Length - $hold)
    }
    foreach ($q in $pumps) { Write-MaskPump $q $q.Pend; $q.Pend = '' }
    $p.WaitForExit()
    $code = $p.ExitCode
    $p.Dispose()
    return $code
}

function Invoke-Editor([string]$File) {
    $ed = $env:EDITOR
    if (-not $ed) {
        if (Sec-IsWindows) { $ed = [IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'notepad.exe') } else { $ed = 'vi' }
    }
    $exe = $ed; $extra = @()
    if (-not [IO.File]::Exists($ed)) {
        if ($ed.StartsWith('"')) {
            $end = $ed.IndexOf('"', 1)
            if ($end -lt 0) { Sec-Fail 'EDITOR has an unbalanced quote' }
            $exe = $ed.Substring(1, $end - 1); $rest = $ed.Substring($end + 1).Trim()
        } else {
            $sp = $ed.IndexOf(' ')
            if ($sp -gt 0) { $exe = $ed.Substring(0, $sp); $rest = $ed.Substring($sp + 1).Trim() } else { $rest = '' }
        }
        if ($rest) { $extra = @($rest -split '\s+') }
    }
    $launch = Resolve-Launch $exe (@($extra) + @($File))
    $code = Start-Inherited $launch $null
    if ($code -ne 0) { Sec-Fail "editor exited with code $code" }
}

function New-EditTemp([string]$Ext, [byte[]]$Content) {
    $dir = Sec-TmpDir
    Sec-EnsurePrivateDir $dir
    $f = [IO.Path]::Combine($dir, 'secret-' + (Sec-RandHex 6) + $Ext)
    [IO.File]::WriteAllBytes($f, (New-Object byte[] 0))
    Sec-SetPrivateAcl $f
    if ($Content -and $Content.Length -gt 0) { [IO.File]::WriteAllBytes($f, $Content) }
    return $f
}

function Ext-ForType([string]$Type) { if ($Type -ceq 'kv') { return '.env' } elseif ($Type -ceq 'doc') { return '.md' } else { return '.bin' } }

function Read-Stdin-Bytes {
    $ms = New-Object System.IO.MemoryStream
    $s = [Console]::OpenStandardInput()
    $s.CopyTo($ms)
    return , $ms.ToArray()
}

# Validates plaintext for a type; returns @{ Bytes (canonical); Fields }
function Prepare-Plain([string]$Type, [byte[]]$Bytes) {
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { Sec-Fail 'empty content; nothing written' }
    if ($Type -ceq 'kv') {
        $canon = Sec-KvCanonical $Bytes
        $fields = @((Sec-KvParse $canon) | ForEach-Object { $_.Key })
        if ($fields.Count -eq 0) { Sec-Fail 'kv content has no KEY=VALUE lines (fields must not be empty)' }
        return (New-Object psobject -Property @{ Bytes = $canon; Fields = [string[]]$fields })
    }
    if ($Type -ceq 'doc') { [void](Sec-DecodeUtf8 $Bytes) }
    return (New-Object psobject -Property @{ Bytes = $Bytes; Fields = $null })
}

# Encrypt for the store path's current policy; verify with the local identity when it is a recipient.
function Encrypt-For($Ctx, [string]$StorePath, [byte[]]$Plain, [switch]$RequireVerify) {
    $ex = Sec-KeysFor $Ctx $StorePath
    $cipher = Sec-AgeEncrypt $Plain $ex.Keys
    $id = Get-IdentityPath
    $local = $null
    if ([IO.File]::Exists($id)) { $local = Sec-IdentityPublicKey $id }
    if ($local -and (@($ex.Keys) -ccontains $local)) {
        $back = Sec-AgeDecrypt $cipher $id
        if ($null -eq $back -or (Sec-Sha256Hex $back) -cne (Sec-Sha256Hex $Plain)) { Sec-Fail "verification failed for $StorePath (re-decrypted content differs); nothing written" }
    } elseif ($RequireVerify) {
        Sec-Fail "this device is not in the new recipient set for $StorePath; cannot verify, refusing"
    }
    return (New-Object psobject -Property @{ Cipher = $cipher; Hash = $ex.Hash })
}

function Decrypt-Entry($Ctx, $Entry, [string]$Identity) {
    $f = Sec-RepoFile $Ctx $Entry.StorePath
    if (-not [IO.File]::Exists($f)) { Sec-Fail ("ciphertext missing: " + $Entry.StorePath) }
    $plain = Sec-AgeDecrypt ([IO.File]::ReadAllBytes($f)) $Identity
    if ($null -eq $plain) { Sec-Fail ("cannot decrypt " + $Entry.Path + " with " + $Identity) }
    return , $plain
}

function Need-Entry($Ctx, [string]$Path) {
    $e = Sec-FindEntry $Ctx $Path
    if (-not $e) { Sec-Fail "no such entry: $Path" }
    return $e
}

# ================================================================= commands

function Cmd-Init([string[]]$Argv) {
    $p = Parse-Opts $Argv (Add-WriteSpec @{ '--name' = 'value' })
    $id = Get-IdentityPath
    if (-not [IO.File]::Exists($id)) {
        $dir = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($id))
        Sec-EnsurePrivateDir $dir
        $pub = Sec-NewIdentityFile $id
        Err-Line "created identity: $id"
    } else {
        $pub = Sec-IdentityPublicKey $id
        Err-Line "identity exists (not overwritten): $id"
    }
    Out-Line $pub
    $repo = Get-RepoDir
    if (-not [IO.File]::Exists([IO.Path]::Combine($repo, 'recipients.toml'))) { Err-Line "repo not found at $repo; not registered"; return 0 }
    $ctx = Open-Ctx -Write
    $name = Opt $p '--name'
    if (-not $name) { $name = Sec-DeviceName }
    if (-not (Sec-IsSegment $name)) { Sec-Fail "invalid recipient name: $name" }
    $byKey = @($ctx.Recipients.Items | Where-Object { $_.Key -ceq $pub })
    if ($byKey.Count -gt 0) {
        if ($byKey[0].Name -ceq $name) { Err-Line ("already registered as '" + $name + "' (" + $byKey[0].Status + ")"); return 0 }
        Sec-Fail ("this key is already registered as '" + $byKey[0].Name + "'")
    }
    if (@($ctx.Recipients.Items | Where-Object { $_.Name -ceq $name }).Count -gt 0) { Sec-Fail "recipient '$name' already exists with a different key" }
    $active = @($ctx.Recipients.Items | Where-Object { $_.Status -ceq 'active' }).Count
    $stored = (Sec-ListStoreFiles $ctx.Dir).Count
    $status = 'pending'
    if ($active -eq 0 -or $stored -eq 0) { $status = 'active' }
    $t = Sec-NewTable 'recipient'
    $t.Pairs['name'] = $name; $t.Pairs['type'] = 'device'; $t.Pairs['key'] = $pub; $t.Pairs['status'] = $status; $t.Pairs['added'] = (Sec-Today)
    $ctx.Recipients.Doc.Tables.Add($t)
    Sec-TomlWriteFile (Sec-RepoFile $ctx 'recipients.toml') $ctx.Recipients.Doc
    Finish-Write $ctx @('recipients.toml') $p ("secret: register device " + $name + " (" + $status + ")")
    Err-Line "registered '$name' as $status"
    if ($status -ceq 'pending') { Err-Line "next: on an existing device run 'secret recipients approve $name' then 'secret rekey', push, then pull here" }
    return 0
}

function Cmd-Recipients([string[]]$Argv) {
    if ($Argv.Length -eq 0) { Sec-Fail 'usage: secret recipients list|add|approve|remove' }
    $sub = $Argv[0]
    $rest = [string[]]@($Argv | Select-Object -Skip 1)
    $p = Parse-Opts $rest (Add-WriteSpec @{ '--type' = 'value'; '--pending' = 'switch' })
    if ($sub -ceq 'list') { $ctx = Open-Ctx } else { $ctx = Open-Ctx -Write }
    $items = $ctx.Recipients.Items
    switch -CaseSensitive ($sub) {
        'list' {
            foreach ($r in $items) {
                $line = $r.Name + '  ' + $r.Type + '  ' + $r.Status + '  ' + $r.Key + '  ' + $r.Added
                if ($r.Type -ceq 'recovery') { $line += '  backup=' + [string]$r.Backup }
                Out-Line $line
            }
            return 0
        }
        'add' {
            if ($p.Pos.Count -ne 2) { Sec-Fail 'usage: secret recipients add <name> <key> [--type device|service|recovery] [--pending]' }
            $name = $p.Pos[0]; $key = $p.Pos[1]
            $type = Opt $p '--type'; if (-not $type) { $type = 'device' }
            if (-not (Sec-IsSegment $name)) { Sec-Fail 'invalid name' }
            if (-not (Sec-IsAgeKey $key)) { Sec-Fail 'invalid key (must be a lowercase age1... X25519 public key)' }
            if (-not (@('device', 'service', 'recovery') -ccontains $type)) { Sec-Fail 'invalid --type' }
            if (@($items | Where-Object { $_.Name -ceq $name }).Count) { Sec-Fail "recipient '$name' already exists" }
            if (@($items | Where-Object { $_.Key -ceq $key }).Count) { Sec-Fail 'this key is already registered' }
            $t = Sec-NewTable 'recipient'
            $status = 'active'; if (Opt $p '--pending') { $status = 'pending' }
            $t.Pairs['name'] = $name; $t.Pairs['type'] = $type; $t.Pairs['key'] = $key; $t.Pairs['status'] = $status; $t.Pairs['added'] = (Sec-Today)
            if ($type -ceq 'recovery') { $t.Pairs['backup'] = '' }
            $ctx.Recipients.Doc.Tables.Add($t)
            $msg = "added '$name' ($status)"
        }
        'approve' {
            if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret recipients approve <name>' }
            $r = @($items | Where-Object { $_.Name -ceq $p.Pos[0] })
            if ($r.Count -eq 0) { Sec-Fail 'no such recipient' }
            if ($r[0].Status -cne 'pending') { Sec-Fail ("recipient is " + $r[0].Status + ", not pending") }
            $r[0].Table.Pairs['status'] = 'active'
            $msg = "approved '" + $p.Pos[0] + "'"
        }
        'remove' {
            if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret recipients remove <name>' }
            $r = @($items | Where-Object { $_.Name -ceq $p.Pos[0] })
            if ($r.Count -eq 0) { Sec-Fail 'no such recipient' }
            $r[0].Table.Pairs['status'] = 'revoked'
            $msg = "revoked '" + $p.Pos[0] + "' (record kept). Values it could read must be rotated: rekey does not revoke git history"
        }
        default { Sec-Fail "unknown recipients subcommand: $sub" }
    }
    Sec-TomlWriteFile (Sec-RepoFile $ctx 'recipients.toml') $ctx.Recipients.Doc
    Finish-Write $ctx @('recipients.toml') $p ('secret: recipients ' + $sub + ' ' + $p.Pos[0])
    Err-Line $msg
    Err-Line "next: 'secret rekey' so ciphertexts match the new recipient set"
    return 0
}

function Cmd-Rekey([string[]]$Argv) {
    $p = Parse-Opts $Argv (Add-WriteSpec @{ '--all' = 'switch' })
    $ctx = Open-Ctx -Write
    $id = Require-Identity
    $lock = Sec-LockRead $ctx.Dir
    $changes = New-Object 'System.Collections.Generic.List[object]'
    $changed = New-Object 'System.Collections.Generic.List[string]'
    $errors = 0; $same = 0
    # phase 1: everything in memory (decrypt, encrypt, verify); nothing is written unless all entries succeed
    foreach ($e in $ctx.Catalog.Entries) {
        $sp = $e.StorePath
        $f = Sec-RepoFile $ctx $sp
        try {
            if (-not [IO.File]::Exists($f)) { Sec-Fail 'ciphertext missing' }
            Assert-LockIntact $ctx $lock $sp
            $ex = Sec-KeysFor $ctx $sp
            $need = (Opt $p '--all') -or (-not $lock.ContainsKey($sp)) -or ($lock[$sp].RHash -cne $ex.Hash)
            if (-not $need) { $same++; continue }
            $plain = Sec-AgeDecrypt ([IO.File]::ReadAllBytes($f)) $id
            if ($null -eq $plain) { Sec-Fail 'cannot decrypt with this identity' }
            $enc = Encrypt-For $ctx $sp $plain -RequireVerify
            [Array]::Clear($plain, 0, $plain.Length)
            $changes.Add(@{ Path = $f; Bytes = $enc.Cipher })
            $lock[$sp] = New-Object psobject -Property @{ RHash = $enc.Hash; CHash = (Sec-Sha256Hex $enc.Cipher) }
            $changed.Add($sp)
        } catch {
            $errors++
            Out-Line ("X $sp`: " + $_.Exception.Message)
        }
    }
    if ($errors -gt 0) { Err-Line "rekey aborted: $errors failed, nothing written"; return 1 }
    if ($changed.Count -gt 0) {
        $changes.Add(@{ Path = (Sec-LockPath $ctx.Dir); Bytes = (Sec-Utf8Bytes (Sec-LockFormat $lock)) })
        Sec-ApplyChanges $changes
        foreach ($sp in $changed) { Out-Line "~ $sp" }
        Finish-Write $ctx (@($changed) + @('store/.recipients.lock')) $p ('secret: rekey ' + $changed.Count + ' entries')
    }
    Err-Line ("rekeyed " + $changed.Count + ", unchanged " + $same)
    return 0
}

function Cmd-Add([string[]]$Argv) {
    $spec = Add-WriteSpec @{ '--type' = 'value'; '--title' = 'value'; '--description' = 'value'; '--from-file' = 'value'; '--stdin' = 'switch'
        '--target' = 'value'; '--acl' = 'value'; '--machines' = 'value'; '--tag' = 'multi'; '--alias' = 'multi'; '--replace' = 'switch'
        '--rotate' = 'value'; '--reader' = 'multi'; '--priority' = 'value'; '--linked' = 'multi' }
    $p = Parse-Opts $Argv $spec
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret add <path> --type kv|file|doc --title <t> [...]' }
    $path = $p.Pos[0]
    $type = Opt $p '--type'; $title = Opt $p '--title'
    if (-not (Sec-IsLogicalPath $path)) { Sec-Fail 'invalid path: need <domain>/<group>/<name>, segments ^[a-z0-9][a-z0-9-]*$, no reserved names' }
    if (-not (@('kv', 'file', 'doc') -ccontains $type)) { Sec-Fail '--type must be kv, file or doc' }
    if (-not $title) { Sec-Fail '--title is required and must not be empty' }
    $target = Opt $p '--target'; $acl = Opt $p '--acl'; $machinesRaw = Opt $p '--machines'
    if ($type -cne 'file' -and ($target -or $acl -or $machinesRaw)) { Sec-Fail '--target / --acl / --machines are only for type file' }
    if ($target) { $tr = Sec-CheckTargetSyntax $target; if (-not $tr.Ok) { Sec-Fail ('invalid --target: ' + $tr.Error) } }
    if ($acl -and -not (@('private', 'inherit') -ccontains $acl)) { Sec-Fail '--acl must be private or inherit' }
    if ($null -ne (Opt $p '--tag')) { foreach ($tg in (Opt $p '--tag')) { if (-not $tg) { Sec-Fail '--tag must not be empty' } } }
    if ($null -ne (Opt $p '--reader')) { foreach ($rd in (Opt $p '--reader')) { if (-not $rd) { Sec-Fail '--reader must not be empty' } } }
    if (Opt $p '--priority') { if (-not (@('high', 'normal', 'low') -ccontains (Opt $p '--priority'))) { Sec-Fail '--priority must be high, normal or low' } }
    if ($p.Opts.ContainsKey('--rotate') -and -not (Opt $p '--rotate')) { Sec-Fail '--rotate must not be empty' }
    $ctx = Open-Ctx -Write
    $existing = Sec-FindEntry $ctx $path
    if ($existing -and -not (Opt $p '--replace')) { Sec-Fail "entry exists: $path (use --replace)" }
    $machines = $null
    if ($machinesRaw) {
        $machines = [string[]]@($machinesRaw -csplit ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($m in $machines) {
            if (@($ctx.Recipients.Items | Where-Object { $_.Name -ceq $m -and $_.Type -ceq 'device' }).Count -eq 0) { Sec-Fail "--machines: '$m' is not a device recipient" }
        }
    }
    $aliases = New-Object 'System.Collections.Generic.List[string]'
    $taken = Sec-NewSet
    foreach ($e in $ctx.Catalog.Entries) { if ($e.Path -cne $path) { foreach ($n in $e.NormAliases) { [void]$taken.Add($n.Full) } } }
    if ($null -ne (Opt $p '--alias')) {
        foreach ($a in (Opt $p '--alias')) {
            $n = Sec-AliasNormalize $a
            if (-not (Sec-AliasIsValid $n)) { Sec-Fail 'alias needs a source prefix (<source>: with source ^[a-z][a-z0-9-]*) and a non-empty path' }
            if (-not $taken.Add($n.Full)) { Sec-Fail ("alias already used: " + $n.Full) }
            $aliases.Add($n.Full)
        }
    }
    $sp = Sec-StorePathOf $path $type
    $lock = Sec-LockRead $ctx.Dir
    Assert-LockIntact $ctx $lock $sp
    if ($existing) { Assert-LockIntact $ctx $lock $existing.StorePath }
    # input
    $from = Opt $p '--from-file'
    if ($from -and (Opt $p '--stdin')) { Sec-Fail 'use either --from-file or --stdin' }
    if ($from) {
        if (-not [IO.File]::Exists($from)) { Sec-Fail "file not found: $from" }
        $prep = Prepare-Plain $type ([IO.File]::ReadAllBytes($from))
    } elseif (Opt $p '--stdin') {
        $prep = Prepare-Plain $type (Read-Stdin-Bytes)
    } else {
        $tmp = New-EditTemp (Ext-ForType $type) $null
        try { $prep = Edit-Until-Valid $tmp $type $null } finally { Sec-RemoveFileWiped $tmp }
    }
    $enc = Encrypt-For $ctx $sp $prep.Bytes
    $changes = New-Object 'System.Collections.Generic.List[object]'
    $rels = New-Object 'System.Collections.Generic.List[string]'
    $changes.Add(@{ Path = (Sec-RepoFile $ctx $sp); Bytes = $enc.Cipher }); $rels.Add($sp)
    if ($existing -and $existing.StorePath -cne $sp) {
        $changes.Add(@{ Path = (Sec-RepoFile $ctx $existing.StorePath); Bytes = $null })
        [void]$lock.Remove($existing.StorePath)
        $rels.Add($existing.StorePath)
    }
    $lock[$sp] = New-Object psobject -Property @{ RHash = $enc.Hash; CHash = (Sec-Sha256Hex $enc.Cipher) }
    $changes.Add(@{ Path = (Sec-LockPath $ctx.Dir); Bytes = (Sec-Utf8Bytes (Sec-LockFormat $lock)) }); $rels.Add('store/.recipients.lock')
    # catalog (built in memory; the doc object is discarded on failure since the process exits)
    if ($existing) { $t = $existing.Table; $t.Pairs.Clear() } else { $t = Sec-NewTable 'entry'; $ctx.Catalog.Doc.Tables.Add($t) }
    $t.Pairs['path'] = $path
    $t.Pairs['type'] = $type
    $t.Pairs['title'] = Sec-Nfc $title
    if (Opt $p '--description') { $t.Pairs['description'] = Sec-Nfc (Opt $p '--description') }
    if ($type -ceq 'kv') { $t.Pairs['fields'] = [string[]]@($prep.Fields) }
    if ($target) { $t.Pairs['target'] = Sec-Nfc $target }
    if ($acl) { $t.Pairs['acl'] = $acl }
    if ($null -ne $machines) { $t.Pairs['machines'] = $machines }
    if ($null -ne (Opt $p '--tag')) { $t.Pairs['tags'] = [string[]]@((Opt $p '--tag') | ForEach-Object { Sec-Nfc $_ }) }
    if (Opt $p '--priority') { $t.Pairs['priority'] = Opt $p '--priority' }
    if ($null -ne (Opt $p '--linked')) {
        foreach ($lk in (Opt $p '--linked')) {
            if ($lk -ceq $path) { Sec-Fail '--linked cannot point at the entry itself' }
            if (-not (Sec-FindEntry $ctx $lk)) { Sec-Fail "--linked: no such entry: $lk" }
        }
        $t.Pairs['linked'] = [string[]]@(Opt $p '--linked')
    }
    if (Opt $p '--rotate') { $t.Pairs['rotate'] = Sec-Nfc (Opt $p '--rotate') }
    if ($null -ne (Opt $p '--reader')) { $t.Pairs['readers'] = [string[]]@((Opt $p '--reader') | ForEach-Object { Sec-Nfc $_ }) }
    if ($aliases.Count -gt 0) { $t.Pairs['aliases'] = [string[]]$aliases.ToArray() }
    $t.Pairs['updated'] = Sec-Today
    $changes.Add(@{ Path = (Sec-RepoFile $ctx 'catalog.toml'); Bytes = (Sec-Utf8Bytes (Sec-TomlFormat $ctx.Catalog.Doc)) }); $rels.Add('catalog.toml')
    Sec-ApplyChanges $changes
    $verb = 'add'
    if ($existing) { $verb = 'update' }
    Finish-Write $ctx $rels.ToArray() $p ('secret: ' + $verb + ' ' + $path + ' (' + $type + ')')
    Err-Line "added $path ($type)"
    return 0
}

function Cmd-Edit([string[]]$Argv) {
    $p = Parse-Opts $Argv (Add-WriteSpec @{})
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret edit <path>' }
    $ctx = Open-Ctx -Write
    $id = Require-Identity
    $e = Need-Entry $ctx $p.Pos[0]
    $lock = Sec-LockRead $ctx.Dir
    Assert-LockIntact $ctx $lock $e.StorePath
    $plain = Decrypt-Entry $ctx $e $id
    $tmp = New-EditTemp (Ext-ForType $e.Type) $plain
    try { $prep = Edit-Until-Valid $tmp $e.Type $plain } finally { Sec-RemoveFileWiped $tmp }
    if ($null -eq $prep) { Err-Line 'unchanged; nothing written'; return 0 }
    if ((Sec-Sha256Hex $prep.Bytes) -ceq (Sec-Sha256Hex $plain)) { Err-Line 'unchanged after normalization; nothing written'; return 0 }
    $enc = Encrypt-For $ctx $e.StorePath $prep.Bytes
    $lock[$e.StorePath] = New-Object psobject -Property @{ RHash = $enc.Hash; CHash = (Sec-Sha256Hex $enc.Cipher) }
    if ($e.Type -ceq 'kv') { $e.Table.Pairs['fields'] = [string[]]@($prep.Fields) }
    $e.Table.Pairs['updated'] = Sec-Today
    $changes = New-Object 'System.Collections.Generic.List[object]'
    $changes.Add(@{ Path = (Sec-RepoFile $ctx $e.StorePath); Bytes = $enc.Cipher })
    $changes.Add(@{ Path = (Sec-LockPath $ctx.Dir); Bytes = (Sec-Utf8Bytes (Sec-LockFormat $lock)) })
    $changes.Add(@{ Path = (Sec-RepoFile $ctx 'catalog.toml'); Bytes = (Sec-Utf8Bytes (Sec-TomlFormat $ctx.Catalog.Doc)) })
    Sec-ApplyChanges $changes
    Finish-Write $ctx @($e.StorePath, 'store/.recipients.lock', 'catalog.toml') $p ('secret: edit ' + $e.Path)
    Err-Line ("updated " + $e.Path)
    return 0
}

function Cmd-Rm([string[]]$Argv) {
    $p = Parse-Opts $Argv (Add-WriteSpec @{ '--yes' = 'switch'; '--keep-target' = 'switch'; '--force' = 'switch' })
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret rm <path> --yes [--force] [--keep-target] [--commit <msg>] [--push]' }
    $ctx = Open-Ctx -Write
    $e = Need-Entry $ctx (Sec-ParseRef $p.Pos[0]).Path
    $lock = Sec-LockRead $ctx.Dir
    $cipher = Sec-RepoFile $ctx $e.StorePath
    Out-Line ('path: ' + $e.Path)
    Out-Line ('type: ' + $e.Type)
    Out-Line ('title: ' + $e.Title)
    Out-Line ('store: ' + $e.StorePath + '  (' + $(if ([IO.File]::Exists($cipher)) { 'will be deleted' } else { 'file missing' }) + ')')
    Out-Line ('lock line: ' + $(if ($lock.ContainsKey($e.StorePath)) { 'will be removed' } else { 'none' }))
    $landed = $null
    if ($e.Target) {
        $tr = Sec-ResolveTarget $e.Target $ctx.Dir
        if ($tr.Ok -and [IO.File]::Exists($tr.Full)) { $landed = $tr.Full }
        Out-Line ('target: ' + $e.Target + '  (' + $(if ($landed) { 'materialized file exists, NOT deleted' } else { 'no materialized file here' }) + ')')
    }
    if ($null -ne $e.Readers) { Out-Line ('readers: ' + (@($e.Readers) -join '; ')) } else { Out-Line 'readers: (not registered)' }
    if ($null -ne $e.Linked) { Out-Line ('linked: ' + (@($e.Linked) -join ', ')) } else { Out-Line 'linked: (none)' }
    Err-Line 'before removing: make sure every reader above has been switched over, and handle the linked entries too'
    # who links to it? leaving a dangling `linked` breaks every later catalog read (and the web UI refuses to write)
    $referrers = @($ctx.Catalog.Entries | Where-Object { $null -ne $_.Linked -and (@($_.Linked) -ccontains $e.Path) })
    if ($referrers.Count -gt 0) {
        Out-Line ('linked from: ' + (@($referrers | ForEach-Object { $_.Path }) -join ', '))
        if (-not (Opt $p '--force')) {
            Err-Line ('refusing: ' + $referrers.Count + " other entry/entries list it in 'linked'; re-run with --force to remove those references too")
            return 1
        }
        Out-Line ("will also drop this path from 'linked' of: " + (@($referrers | ForEach-Object { $_.Path }) -join ', '))
    }
    if ([IO.File]::Exists($cipher) -and $lock.ContainsKey($e.StorePath) -and $lock[$e.StorePath].CHash -cne (Sec-Sha256Hex ([IO.File]::ReadAllBytes($cipher)))) {
        Err-Line 'WARNING: this ciphertext was changed outside the CLI (lock hash mismatch); removing it also removes the evidence'
    }
    if (-not (Opt $p '--yes')) { Err-Line 'nothing removed: re-run with --yes'; return 2 }
    $changes = New-Object 'System.Collections.Generic.List[object]'
    $rels = New-Object 'System.Collections.Generic.List[string]'
    if ([IO.File]::Exists($cipher)) { $changes.Add(@{ Path = $cipher; Bytes = $null }) }
    $rels.Add($e.StorePath)
    [void]$lock.Remove($e.StorePath)
    $changes.Add(@{ Path = (Sec-LockPath $ctx.Dir); Bytes = (Sec-Utf8Bytes (Sec-LockFormat $lock)) }); $rels.Add('store/.recipients.lock')
    [void]$ctx.Catalog.Doc.Tables.Remove($e.Table)
    foreach ($ref in $referrers) {
        $keep = [string[]]@(@($ref.Linked) | Where-Object { $_ -cne $e.Path })
        if ($keep.Count -eq 0) { $ref.Table.Pairs.Remove('linked') } else { $ref.Table.Pairs['linked'] = $keep }
    }
    $changes.Add(@{ Path = (Sec-RepoFile $ctx 'catalog.toml'); Bytes = (Sec-Utf8Bytes (Sec-TomlFormat $ctx.Catalog.Doc)) }); $rels.Add('catalog.toml')
    Sec-ApplyChanges $changes
    Err-Line ('removed ' + $e.Path)
    # Drop this entry's approved landing targets before touching git: a failing --commit / --push must not leave the
    # approval behind, or a later entry with the same path would land without asking again.
    try {
        $appr = Sec-ApprovalsRead
        $drop = @(@($appr) | Where-Object { $_.StartsWith($e.Path + "`t", [StringComparison]::Ordinal) })
        if ($drop.Count -gt 0) {
            foreach ($d in $drop) { [void]$appr.Remove($d) }
            Sec-ApprovalsWrite $appr
            Err-Line ('dropped ' + $drop.Count + ' approved target record(s) for this entry')
        }
    } finally {
        Finish-Write $ctx $rels.ToArray() $p ('secret: rm ' + $e.Path)
    }
    if ($landed) {
        if (Opt $p '--keep-target') { Err-Line ("keeping materialized file: $landed") }
        else { Err-Line ("note: the materialized file is still on disk: $landed -- delete it by hand once the value is dead") }
    }
    Err-Line 'reminder: the ciphertext stays in git history; rotate the value if it was a live credential'
    return 0
}

# Fixed wording for `inventory` lives in inventory-template.md (this file is ASCII-only on purpose).
# SECRET_INVENTORY_TEMPLATE points at another template, e.g. the bundled inventory-template.zh-CN.md.
function Read-InventoryTemplate {
    $f = $env:SECRET_INVENTORY_TEMPLATE
    if (-not $f) { $f = [IO.Path]::Combine($PSScriptRoot, 'inventory-template.md') }
    if (-not [IO.File]::Exists($f)) { Sec-Fail "missing template: $f" }
    $text = Sec-DecodeUtf8 ([IO.File]::ReadAllBytes($f))
    $tpl = @{}
    $pre = New-Object 'System.Collections.Generic.List[string]'
    $inPre = $false
    foreach ($raw in $text.Split([char]10)) {
        $line = $raw.TrimEnd([char]13)
        if ($inPre) {
            if ($line -ceq '@end') { $inPre = $false; continue }
            $pre.Add($line); continue
        }
        if ($line -ceq '@preamble') { $inPre = $true; continue }
        if ($line.StartsWith('@')) {
            $eq = $line.IndexOf('=')
            if ($eq -gt 1) { $tpl[$line.Substring(1, $eq - 1)] = $line.Substring($eq + 1) }
            continue
        }
    }
    $tpl['preamble'] = ($pre.ToArray() -join "`n")
    foreach ($k in @('not-registered', 'none', 'all-machines', 'group-heading', 'table-header', 'table-sep', 'preamble')) {
        if (-not $tpl.ContainsKey($k)) { Sec-Fail "template is missing @$k" }
    }
    return $tpl
}

function Priority-Rank([string]$P) {
    if ($P -ceq 'high') { return '0' }
    if ($P -ceq 'low') { return '2' }
    return '1'
}

# The incident list, built from catalog metadata only. Same text for `inventory` and for the freshness check.
function Build-Inventory($ctx) {
    $tpl = Read-InventoryTemplate
    $cell = { param($v) if ($null -eq $v -or $v.Length -eq 0) { return $tpl['not-registered'] } ; return ([string]$v).Replace('|', '\|') }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($tpl['preamble'] + "`n")
    $groups = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in $ctx.Catalog.Entries) {
        $g = (@($e.Path -csplit '/')[0]) + '/' + (@($e.Path -csplit '/')[1])
        if (-not $groups.Contains($g)) { $groups.Add($g) }
    }
    foreach ($g in (Sec-SortOrdinal @($groups))) {
        [void]$sb.Append("`n" + $tpl['group-heading'].Replace('{0}', $g) + "`n`n")
        [void]$sb.Append($tpl['table-header'] + "`n" + $tpl['table-sep'] + "`n")
        $rows = @($ctx.Catalog.Entries | Where-Object { $_.Path.StartsWith($g + '/', [StringComparison]::Ordinal) })
        # priority high -> normal -> low, then path (ordinal)
        $keys = Sec-NewDict
        foreach ($e in $rows) { $keys[(Priority-Rank $e.Priority) + "`t" + $e.Path] = $e }
        foreach ($k in (Sec-SortOrdinal @($keys.Keys))) {
            $e = $keys[$k]
            $readers = $null
            if ($null -ne $e.Readers) { $readers = (@($e.Readers) -join '; ') }
            $aliases = $null
            if ($null -ne $e.Aliases) { $aliases = (@($e.Aliases) -join '<br>') }
            $linked = $null
            if ($null -ne $e.Linked) { $linked = (@($e.Linked) -join '<br>') }
            $machines = $tpl['all-machines']
            if ($null -ne $e.Machines) { $machines = (@($e.Machines) -join '; ') }
            $prio = $e.Priority
            if (-not $prio) { $prio = 'normal' }
            $target = $e.Target
            if (-not $target) { $target = $tpl['none'] }
            if (-not $aliases) { $aliases = $tpl['none'] }
            if (-not $linked) { $linked = $tpl['none'] }
            $cells = @($prio, $e.Path, $e.Type, (& $cell $e.Title), (& $cell $e.Rotate), (& $cell $readers), $machines,
                ([string]$target).Replace('|', '\|'), ([string]$linked).Replace('|', '\|'), $e.Updated, ([string]$aliases).Replace('|', '\|'))
            [void]$sb.Append('| ' + ($cells -join ' | ') + " |`n")
        }
    }
    return $sb.ToString()
}

# How often catalog.toml mentions this value. Used to tell "someone pasted a credential into a title /
# description" (the value shows up once) from "identifier-like value" (user / db / env name, one's own handle:
# the same string legitimately shows up in many entries' text). Counting raw occurrences rather than distinct
# entries is deliberate: an entry named after its database or bot account repeats that name in its own path,
# title and aliases, and treating those as leaks made the check block on nine such entries. Residual gap:
# the same credential pasted TWICE inside one entry's metadata also counts 2 and is only reported in the note
# line (which names entry#FIELD), not refused -- pasting it once, the realistic slip, is still refused.
function Count-Occurrences([string]$Haystack, [string]$Needle) {
    if ([string]::IsNullOrEmpty($Needle)) { return 0 }
    $n = 0; $i = 0
    while ($true) {
        $j = $Haystack.IndexOf($Needle, $i, [StringComparison]::Ordinal)
        if ($j -lt 0) { break }
        $n++; $i = $j + 1
    }
    return $n
}

function Cmd-Inventory([string[]]$Argv) {
    $p = Parse-Opts $Argv (Add-WriteSpec @{ '--out' = 'value'; '--stdout' = 'switch' })
    $ctx = Open-Ctx
    if (-not (Opt $p '--stdout')) { Take-RepoLock $ctx.Dir }
    $text = Build-Inventory $ctx
    # self-check: the inventory must not contain any kv value (it is built from metadata only, but verify anyway).
    # The inventory is a projection of catalog.toml, so every hit means the value also sits in catalog metadata.
    # Identifier-like values (user / db / env names, one's own handle) legitimately appear in many entries' text;
    # once kv entries grow USERNAME / DATABASE / ENV_NAME style fields (typical after splitting docs into kv),
    # treating those as leaks made the check unusable. So: a value that catalog.toml mentions 2+ times is only
    # reported as a note (names only, never the value); a value that catalog.toml mentions exactly once is still a leak and
    # stops the write -- that is the "someone pasted a credential into a title / description" case.
    $id = Get-IdentityPath
    $catalogText = Sec-DecodeUtf8 ([IO.File]::ReadAllBytes((Sec-RepoFile $ctx 'catalog.toml')))
    $shared = New-Object 'System.Collections.Generic.List[string]'
    if ([IO.File]::Exists($id)) {
        $localKey = Sec-IdentityPublicKey $id
        foreach ($e in $ctx.Catalog.Entries) {
            if ($e.Type -cne 'kv') { continue }
            try { $ex = Sec-KeysFor $ctx $e.StorePath } catch { continue }
            if (-not (@($ex.Keys) -ccontains $localKey)) { continue }
            $f = Sec-RepoFile $ctx $e.StorePath
            if (-not [IO.File]::Exists($f)) { continue }
            $plain = Sec-AgeDecrypt ([IO.File]::ReadAllBytes($f)) $id
            if ($null -eq $plain) { continue }
            try { $pairs = Sec-KvParse $plain } catch { continue }
            foreach ($kv in $pairs) {
                if ($kv.Value.Length -lt 4) { continue }
                if ($text.IndexOf($kv.Value, [StringComparison]::Ordinal) -ge 0) {
                    if ((Count-Occurrences $catalogText $kv.Value) -ge 2) { [void]$shared.Add($e.Path + '#' + $kv.Key); continue }
                    Sec-Fail ('refusing to write the inventory: it would contain the value of ' + $e.Path + '#' + $kv.Key)
                }
            }
        }
    } else {
        Err-Line 'note: no identity, skipped the "contains no value" self-check'
    }
    if ($shared.Count -gt 0) {
        $head = @($shared)[0..([Math]::Min(4, $shared.Count - 1))] -join ', '
        if ($shared.Count -gt 5) { $head = $head + ', ...' }
        Err-Line ('note: ' + $shared.Count + ' kv value(s) also occur in catalog metadata in 2+ places (identifier-like), not treated as leaks: ' + $head)
    }
    if (Opt $p '--stdout') { [Console]::Out.Write($text); return 0 }
    $out = Opt $p '--out'
    if (-not $out) { $out = [IO.Path]::Combine($ctx.Dir, 'INCIDENT.md') }
    $chk = Sec-CheckOutPath $out $null
    if (-not $chk.Ok) { Sec-Fail ('cannot write there: ' + $chk.Error) }
    Sec-WriteFileAtomic $chk.Full (Sec-Utf8Bytes $text)
    Err-Line "wrote $out"
    # inside the repo (the usual INCIDENT.md) it is a repo change like any other
    $sep = [IO.Path]::DirectorySeparatorChar
    $base = [IO.Path]::GetFullPath($ctx.Dir).TrimEnd($sep) + $sep
    $cmp = [StringComparison]::Ordinal
    if (Sec-IsWindows) { $cmp = [StringComparison]::OrdinalIgnoreCase }
    if ($chk.Full.StartsWith($base, $cmp)) {
        $rel = $chk.Full.Substring($base.Length).Replace($sep, [char]47)
        Finish-Write $ctx @($rel) $p ('secret: inventory (' + $rel + ')')
    }
    return 0
}

function Cmd-Show([string[]]$Argv) {
    $p = Parse-Opts $Argv @{}
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret show <path>' }
    $ctx = Open-Ctx
    $id = Require-Identity
    $e = Need-Entry $ctx (Sec-ParseRef $p.Pos[0]).Path
    $plain = Decrypt-Entry $ctx $e $id
    if ($e.Type -ceq 'kv') {
        foreach ($kv in (Sec-KvParse $plain)) { Out-Line ($kv.Key + '=' + $kv.Value) }
    } elseif ($e.Type -ceq 'doc') {
        $t = Sec-DecodeUtf8 $plain
        [Console]::Out.Write($t); if (-not $t.EndsWith("`n")) { Out-Line '' }
    } else {
        if (Sec-IsUtf8Text $plain) {
            $t = Sec-DecodeUtf8 $plain
            [Console]::Out.Write($t); if (-not $t.EndsWith("`n")) { Out-Line '' }
        } else {
            Out-Line ('binary file, ' + $plain.Length + ' bytes, sha256 ' + (Sec-Sha256Hex $plain))
        }
    }
    return 0
}

function Cmd-Get([string[]]$Argv) {
    $p = Parse-Opts $Argv @{ '--out' = 'value'; '--allow-sync-dir' = 'switch' }
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret get <path>#<FIELD> | secret get <path> --out <file>' }
    $ref = Sec-ParseRef $p.Pos[0]
    $ctx = Open-Ctx
    $id = Require-Identity
    $e = Need-Entry $ctx $ref.Path
    $out = Opt $p '--out'
    if ($out) {
        if ($null -ne $ref.Field) { Sec-Fail '--out writes the whole entry; drop #FIELD' }
        if ([IO.File]::Exists($out)) { Sec-Fail "refusing to overwrite existing file: $out" }
        $chk = Sec-CheckOutPath $out $ctx.Dir -AllowSyncDir:([bool](Opt $p '--allow-sync-dir'))
        if (-not $chk.Ok) {
            $hint = ''
            if ($chk.Cloud) { $hint = ' (use --allow-sync-dir if you really mean it)' }
            Sec-Fail ('refusing to write plaintext there: ' + $chk.Error + $hint)
        }
        if ($chk.Cloud) { Err-Line ('WARNING: writing plaintext into a cloud-synced folder (' + $chk.Cloud + '); it will be uploaded') }
        $plain = Decrypt-Entry $ctx $e $id
        Sec-WriteFileAtomic $chk.Full $plain -Private
        Err-Line "wrote $out"
        return 0
    }
    if ($null -eq $ref.Field) { Sec-Fail 'need <path>#<FIELD> (or --out <file> for the whole entry)' }
    if ($e.Type -cne 'kv') { Sec-Fail ("#FIELD only works on kv entries; " + $e.Path + " is " + $e.Type) }
    $plain = Decrypt-Entry $ctx $e $id
    $hit = @((Sec-KvParse $plain) | Where-Object { $_.Key -ceq $ref.Field })
    if ($hit.Count -eq 0) { Sec-Fail ("no field '" + $ref.Field + "' in " + $e.Path) }
    $bytes = Sec-Utf8Bytes $hit[0].Value
    $s = [Console]::OpenStandardOutput()
    $s.Write($bytes, 0, $bytes.Length); $s.Flush()
    return 0
}

function Cmd-Run([string[]]$Argv) {
    $es = New-Object 'System.Collections.Generic.List[string]'
    $as = New-Object 'System.Collections.Generic.List[string]'
    $i = 0; $cmdStart = -1; $mask = 'auto'
    while ($i -lt $Argv.Length) {
        $a = $Argv[$i]
        if ($a -ceq '--') { $cmdStart = $i + 1; break }
        if (@('-e', '-a', '--repo', '--identity') -ccontains $a) {
            if ($i + 1 -ge $Argv.Length) { Sec-Fail "option $a needs a value" }
            $v = $Argv[$i + 1]
            if ($a -ceq '-e') { $es.Add($v) } elseif ($a -ceq '-a') { $as.Add($v) } elseif ($a -ceq '--repo') { $script:G.Repo = $v } else { $script:G.Identity = $v }
            $i += 2; continue
        }
        if ($a -ceq '--pull') { $script:G.Pull = $true; $i++; continue }
        if ($a -ceq '--mask') { $mask = 'on'; $i++; continue }
        if ($a -ceq '--no-mask') { $mask = 'off'; $i++; continue }
        if ($a.StartsWith('-')) { Sec-Fail "unknown run option: $a (put the command after --)" }
        $cmdStart = $i; break
    }
    if ($cmdStart -lt 0 -or $cmdStart -ge $Argv.Length) { Sec-Fail 'usage: secret run [-e NAME=<path>#<FIELD>]... [-a [PREFIX=]<path>]... [--mask|--no-mask] -- <command> [args...]' }
    $command = $Argv[$cmdStart]
    $cmdArgs = [string[]]@($Argv | Select-Object -Skip ($cmdStart + 1))
    $launch = Resolve-Launch $command $cmdArgs
    $ctx = Open-Ctx
    $id = Require-Identity
    $cmp = [StringComparer]::Ordinal
    if (Sec-IsWindows) { $cmp = [StringComparer]::OrdinalIgnoreCase }
    $envMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' ($cmp)
    $cache = Sec-NewDict
    $getKv = {
        param($path)
        if ($cache.ContainsKey($path)) { return , $cache[$path] }
        $e = Need-Entry $ctx $path
        if ($e.Type -cne 'kv') { Sec-Fail ("$path is " + $e.Type + "; run only injects kv entries") }
        $pairs = Sec-KvParse (Decrypt-Entry $ctx $e $id)
        $cache[$path] = $pairs
        return , $pairs
    }
    foreach ($x in $es) {
        $eq = $x.IndexOf('=')
        if ($eq -lt 1) { Sec-Fail '-e expects NAME=<path>#<FIELD>' }
        $name = $x.Substring(0, $eq)
        if ($name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*\z') { Sec-Fail "invalid environment variable name: $name" }
        $ref = Sec-ParseRef $x.Substring($eq + 1)
        if ($null -eq $ref.Field) { Sec-Fail "-e $name needs <path>#<FIELD>" }
        $pairs = & $getKv $ref.Path
        $hit = @($pairs | Where-Object { $_.Key -ceq $ref.Field })
        if ($hit.Count -eq 0) { Sec-Fail ("no field '" + $ref.Field + "' in " + $ref.Path) }
        if ($envMap.ContainsKey($name)) { Sec-Fail "environment variable set twice: $name" }
        $envMap[$name] = $hit[0].Value
    }
    foreach ($x in $as) {
        $prefix = ''; $pth = $x
        $eq = $x.IndexOf('=')
        if ($eq -ge 0) { $prefix = $x.Substring(0, $eq); $pth = $x.Substring($eq + 1) }
        if ($prefix -and $prefix -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*\z') { Sec-Fail "invalid prefix: $prefix" }
        $ref = Sec-ParseRef $pth
        if ($null -ne $ref.Field) { Sec-Fail '-a takes a whole kv entry (no #FIELD)' }
        foreach ($kv in (& $getKv $ref.Path)) {
            $name = $prefix + $kv.Key
            if ($envMap.ContainsKey($name)) { Sec-Fail "environment variable set twice: $name" }
            $envMap[$name] = $kv.Value
        }
    }
    # auto: mask exactly the streams that are being captured (see Start-Masked); --mask forces both, --no-mask neither
    $mo = $false; $me = $false
    if ($mask -ceq 'on') { $mo = $true; $me = $true }
    elseif ($mask -ceq 'auto') { $mo = [Console]::IsOutputRedirected; $me = [Console]::IsErrorRedirected }
    return (Start-Masked $launch $envMap $mo $me)
}

function Cmd-Materialize([string[]]$Argv) {
    $p = Parse-Opts $Argv @{ '--approve' = 'switch'; '--force' = 'switch'; '--dry-run' = 'switch' }
    $ctx = Open-Ctx
    $id = Require-Identity
    $localKey = Sec-IdentityPublicKey $id
    $approvals = Sec-ApprovalsRead
    $approvalsChanged = $false
    $dry = [bool](Opt $p '--dry-run')
    $errors = 0
    foreach ($x in $ctx.Catalog.EntryErrors) { Out-Line ("X " + $x); $errors++ }
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($p.Pos.Count -gt 0) {
        foreach ($x in $p.Pos) {
            $e = Need-Entry $ctx $x
            if ($e.Type -cne 'file' -or -not $e.Target) { Sec-Fail "$x has no target (only file entries with target can be materialized)" }
            $list.Add($e)
        }
    } else {
        foreach ($e in $ctx.Catalog.Entries) { if ($e.Type -ceq 'file' -and $e.Target) { $list.Add($e) } }
    }
    foreach ($e in $list) {
        $label = $e.Path + ' -> ' + $e.Target
        if (-not (Sec-EntryAppliesHere $ctx $e $localKey)) {
            if ($p.Pos.Count -gt 0) { Out-Line "- $label (not for this machine)" }
            continue
        }
        $tr = Sec-ResolveTarget $e.Target $ctx.Dir
        if (-not $tr.Ok) { Out-Line ("X $label (invalid target: " + $tr.Error + ")"); $errors++; continue }
        $akey = $e.Path + "`t" + $e.Target
        $approved = $approvals.Contains($akey)
        $sensitive = Sec-TargetIsSensitive $e.Target
        $why = 'script/executable, ssh config or authorized_keys target'
        $cloud = Sec-CloudSyncProvider $tr.Full
        if ($cloud) { $sensitive = $true; $why = 'cloud-synced folder (' + $cloud + '): the plaintext will be uploaded' }
        $flag = ''
        if ($sensitive) { $flag = ' [SENSITIVE: ' + $why + ' -- review before approving]' }
        if (-not $approved -and -not (Opt $p '--approve')) { Out-Line "? $label (not approved; rerun with --approve)$flag"; continue }
        if (-not $approved -and $sensitive) { Err-Line "WARNING: approving SENSITIVE target $label" }
        try { $plain = Decrypt-Entry $ctx $e $id } catch { Out-Line ("X $label (" + $_.Exception.Message + ")"); $errors++; continue }
        $full = $tr.Full
        if (-not $approved -and -not $dry) { [void]$approvals.Add($akey); $approvalsChanged = $true }
        if ([IO.File]::Exists($full)) {
            if ((Sec-Sha256Hex ([IO.File]::ReadAllBytes($full))) -ceq (Sec-Sha256Hex $plain)) { Out-Line "= $label"; continue }
            if (-not (Opt $p '--force')) { Out-Line "! $label (differs; use --force to overwrite)"; continue }
        }
        if ($dry) { Out-Line "+ $label (dry-run)"; continue }
        $private = ($e.Acl -cne 'inherit')
        try {
            Sec-WriteFileAtomic $full $plain -Private:$private
            Out-Line "+ $label"
        } catch { Out-Line ("X $label (" + $_.Exception.Message + ")"); $errors++ }
    }
    if ($approvalsChanged) { Sec-ApprovalsWrite $approvals }
    if ($errors -gt 0) { return 1 }
    return 0
}

function Cmd-List([string[]]$Argv) {
    $p = Parse-Opts $Argv @{}
    $prefix = ''; if ($p.Pos.Count -gt 0) { $prefix = $p.Pos[0] }
    $ctx = Open-Ctx
    foreach ($e in $ctx.Catalog.Entries) {
        if (-not $e.Path.StartsWith($prefix, [StringComparison]::Ordinal)) { continue }
        Out-Line ($e.Path + '  ' + $e.Type + '  ' + $e.Title)
    }
    return 0
}

function Cmd-Info([string[]]$Argv) {
    $p = Parse-Opts $Argv @{}
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret info <path>' }
    $ctx = Open-Ctx
    $e = Need-Entry $ctx (Sec-ParseRef $p.Pos[0]).Path
    Out-Line ('path: ' + $e.Path)
    Out-Line ('type: ' + $e.Type)
    Out-Line ('title: ' + $e.Title)
    if ($null -ne $e.Description) { Out-Line ('description: ' + $e.Description) }
    if ($null -ne $e.Fields) { Out-Line ('fields: ' + (@($e.Fields) -join ', ')) }
    if ($null -ne $e.Target) { Out-Line ('target: ' + $e.Target) }
    if ($null -ne $e.Acl) { Out-Line ('acl: ' + $e.Acl) }
    if ($null -ne $e.Machines) { Out-Line ('machines: ' + (@($e.Machines) -join ', ')) }
    if ($null -ne $e.Tags) { Out-Line ('tags: ' + (@($e.Tags) -join ', ')) }
    if ($null -ne $e.Aliases) { foreach ($a in $e.Aliases) { Out-Line ('alias: ' + $a) } }
    Out-Line ('updated: ' + $e.Updated)
    Out-Line ('store: ' + $e.StorePath)
    return 0
}

function Cmd-Resolve([string[]]$Argv) {
    $p = Parse-Opts $Argv @{}
    if ($p.Pos.Count -ne 1) { Sec-Fail 'usage: secret resolve <old pointer>' }
    $ctx = Open-Ctx
    $n = Sec-AliasNormalize $p.Pos[0]
    if (-not (Sec-AliasHasSource $n.Path)) { Sec-Fail 'old pointer needs its source prefix, e.g. notes:path/to/file.md#Section' }
    $hits = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in $ctx.Catalog.Entries) { foreach ($a in $e.NormAliases) { if ($a.Full -ceq $n.Full -and -not $hits.Contains($e.Path)) { $hits.Add($e.Path) } } }
    if ($hits.Count -eq 0) {
        foreach ($e in $ctx.Catalog.Entries) { foreach ($a in $e.NormAliases) { if ($a.Path -ceq $n.Path -and -not $hits.Contains($e.Path)) { $hits.Add($e.Path) } } }
    }
    if ($hits.Count -eq 0) { Err-Line ('no entry has alias ' + $n.Full); return 1 }
    foreach ($h in $hits) { Out-Line ('secret:' + $h) }
    return 0
}

# Values to look for in local logs: every kv field value, plus credential-looking single lines of file entries
# (>= 12 chars, no whitespace). Labels carry entry path + field name only; values stay inside this process.
function Get-LeakNeedles($Ctx, [string]$Identity, [string]$LocalKey, $Expected, $PlainCache, [bool]$CatOk) {
    $needles = New-Object 'System.Collections.Generic.List[object]'
    if (-not $CatOk -or -not $LocalKey) { return , $needles }
    foreach ($e in $Ctx.Catalog.Entries) {
        if (-not $Expected.ContainsKey($e.StorePath)) { continue }
        if (-not (@($Expected[$e.StorePath].Keys) -ccontains $LocalKey)) { continue }
        if ($e.Type -ceq 'doc') { continue }
        if ($e.Type -ceq 'file' -and $e.Path.EndsWith('-pub', [StringComparison]::Ordinal)) { continue }   # public keys are not secrets
        $plain = $null
        if ($PlainCache.ContainsKey($e.Path)) { $plain = $PlainCache[$e.Path] }
        else {
            $f = Sec-RepoFile $Ctx $e.StorePath
            if ([IO.File]::Exists($f)) { $plain = Sec-AgeDecrypt ([IO.File]::ReadAllBytes($f)) $Identity }
        }
        if ($null -eq $plain) { continue }
        if ($e.Type -ceq 'kv') {
            try { $pairs = Sec-KvParse $plain } catch { continue }
            foreach ($kv in $pairs) {
                if ($kv.Value.Length -lt 8) { continue }   # short values (prod, 8080, true) hit in every log: noise beats signal
                $needles.Add(@{ Label = ($e.Path + '#' + $kv.Key); Value = $kv.Value })
            }
        } elseif (Sec-IsUtf8Text $plain) {
            $ln = 0
            foreach ($line in (Sec-DecodeUtf8 $plain).Split([char]10)) {
                $ln++
                $t = $line.Trim()
                if (Test-CredentialLine $t) { $needles.Add(@{ Label = ($e.Path + '#line' + $ln); Value = $t }) }
            }
        }
    }
    return , $needles
}

function Cmd-Check([string[]]$Argv) {
    $p = Parse-Opts $Argv @{ '--sample' = 'value'; '--web' = 'value'; '--scan-log' = 'multi'; '--no-log-scan' = 'switch'; '--quick' = 'switch' }
    $repo = Get-RepoDir
    $script:ck = @{ Err = 0; Warn = 0 }
    $report = {
        param($level, $item, $name)
        if ($level -ceq 'ERROR') { $script:ck.Err++ } elseif ($level -ceq 'WARN') { $script:ck.Warn++ }
        Out-Line ($level + ' ' + $item + ' ' + $name)
    }
    if ($script:G.Pull) { try { [void](Open-Ctx) } catch { } }
    if (-not [IO.Directory]::Exists($repo)) { & $report 'ERROR' 'repo' $repo; return 1 }
    $ctx = Sec-OpenRepo $repo

    # identity
    $id = Get-IdentityPath
    $localKey = $null
    if (-not [IO.File]::Exists($id)) { & $report 'ERROR' 'identity' "missing: $id" }
    else {
        try { $localKey = Sec-IdentityPublicKey $id; & $report 'OK' 'identity' $id } catch { & $report 'ERROR' 'identity' ("unreadable: " + $id) }
    }
    # toml
    foreach ($x in @(@('recipients.toml', $ctx.Recipients), @('policy.toml', $ctx.Policy), @('catalog.toml', $ctx.Catalog))) {
        if ($x[1].Errors.Count -eq 0) { & $report 'OK' 'toml' $x[0] }
        foreach ($m in $x[1].Errors) {
            $item = 'toml'
            if ($x[0] -ceq 'catalog.toml' -and $ctx.Catalog.EntryErrors.Contains($m)) { $item = 'catalog-entry' }
            & $report 'ERROR' $item $m
        }
    }
    $recOk = ($null -ne $ctx.Recipients.Doc -and $ctx.Recipients.Errors.Count -eq 0)
    $polOk = ($null -ne $ctx.Policy.Doc -and $ctx.Policy.Errors.Count -eq 0)
    if ($recOk) {
        if ($localKey) {
            $me = @($ctx.Recipients.Items | Where-Object { $_.Key -ceq $localKey -and $_.Status -ceq 'active' })
            if ($me.Count -eq 0) { & $report 'ERROR' 'identity-recipient' 'this identity is not an active recipient' }
            else { & $report 'OK' 'identity-recipient' $me[0].Name }
        }
        $recs = @($ctx.Recipients.Items | Where-Object { $_.Type -ceq 'recovery' -and $_.Status -ceq 'active' })
        if ($recs.Count -eq 0) { & $report 'WARN' 'recovery' 'no active recovery recipient' }
        foreach ($r in $recs) {
            if (-not $r.Backup) { & $report 'WARN' 'recovery-backup' ($r.Name + ' (offline backup not confirmed)') }
            else { & $report 'OK' 'recovery-backup' $r.Name }
        }
    }
    if ($recOk -and $polOk) {
        foreach ($rule in $ctx.Policy.Rules) {
            $ex = Sec-ExpandRule $rule $ctx.Recipients
            foreach ($ig in $ex.Ignored) { & $report 'WARN' 'policy-ref' ($ig + ' (in rule ' + $rule.Path + ')') }
            if ($ex.Keys.Count -gt 0 -and -not $ex.HasRecovery) { & $report 'WARN' 'policy-no-recovery' $rule.Path }
        }
    }
    # store / ciphertexts
    $files = Sec-ListStoreFiles $repo
    foreach ($f in $files) {
        if (-not (Sec-IsStorePath $f)) { & $report 'ERROR' 'ciphertext-path' $f; continue }
        if (-not (Sec-HasAgeHeader ([IO.File]::ReadAllBytes((Sec-RepoFile $ctx $f))))) { & $report 'ERROR' 'ciphertext-header' $f }
    }
    $recDir = [IO.Path]::Combine($repo, 'recovery')
    if ([IO.Directory]::Exists($recDir)) {
        foreach ($rf in [IO.Directory]::GetFiles($recDir, '*.age')) {
            if (-not (Sec-HasAgeHeader ([IO.File]::ReadAllBytes($rf)))) { & $report 'ERROR' 'ciphertext-header' ('recovery/' + [IO.Path]::GetFileName($rf)) }
        }
    }
    $catOk = ($null -ne $ctx.Catalog.Doc -and $null -ne $ctx.Catalog.Format)
    if ($catOk) {
        $fileSet = Sec-NewSet; foreach ($f in $files) { [void]$fileSet.Add($f) }
        $entrySet = Sec-NewSet
        foreach ($e in $ctx.Catalog.Entries) {
            [void]$entrySet.Add($e.StorePath)
            if (-not $fileSet.Contains($e.StorePath)) { & $report 'ERROR' 'store-missing' $e.StorePath }
        }
        foreach ($f in $files) {
            if ($entrySet.Contains($f)) { continue }
            if ($ctx.Catalog.InvalidStorePaths.Contains($f)) { & $report 'ERROR' 'orphan-invalid-entry' $f }
            else { & $report 'ERROR' 'store-orphan' $f }
        }
    }
    # policy per file + lock
    $expected = Sec-NewDict
    if ($recOk -and $polOk) {
        foreach ($f in $files) {
            $rule = Sec-EffectiveRule $ctx.Policy $f
            if (-not $rule) { & $report 'ERROR' 'policy-nomatch' $f; continue }
            $ex = Sec-ExpandRule $rule $ctx.Recipients
            if ($ex.Keys.Count -eq 0) { & $report 'ERROR' 'policy-empty' $f; continue }
            $expected[$f] = $ex
        }
    }
    $lock = $null
    try { $lock = Sec-LockRead $repo } catch { & $report 'ERROR' 'lock' $_.Exception.Message }
    if ($null -ne $lock) {
        foreach ($f in $files) {
            if (-not $lock.ContainsKey($f)) { & $report 'ERROR' 'lock-missing' $f; continue }
            $ch = Sec-Sha256Hex ([IO.File]::ReadAllBytes((Sec-RepoFile $ctx $f)))
            $bad = $false
            if ($lock[$f].CHash -cne $ch) { & $report 'ERROR' 'lock-hash' $f; $bad = $true }
            if ($expected.ContainsKey($f) -and $lock[$f].RHash -cne $expected[$f].Hash) { & $report 'ERROR' 'rekey-needed' $f; $bad = $true }
            if (-not $bad -and $expected.ContainsKey($f)) { & $report 'OK' 'lock' $f }
        }
        $fs2 = Sec-NewSet; foreach ($f in $files) { [void]$fs2.Add($f) }
        foreach ($k in $lock.Keys) { if (-not $fs2.Contains($k)) { & $report 'ERROR' 'lock-orphan' $k } }
    }
    # decrypt sample
    $plainCache = Sec-NewDict
    if ($catOk -and $localKey) {
        $cands = @($ctx.Catalog.Entries | Where-Object { $expected.ContainsKey($_.StorePath) -and (@($expected[$_.StorePath].Keys) -ccontains $localKey) })
        $sample = Opt $p '--sample'
        if ($sample) {
            $n = 0
            if (-not [int]::TryParse($sample, [ref]$n) -or $n -lt 0) { Sec-Fail '--sample needs a non-negative integer' }
            if ($n -lt $cands.Count) { $cands = @($cands | Get-Random -Count $n) }
        }
        foreach ($e in $cands) {
            $plain = Sec-AgeDecrypt ([IO.File]::ReadAllBytes((Sec-RepoFile $ctx $e.StorePath))) $id
            if ($null -eq $plain) { & $report 'ERROR' 'decrypt' $e.Path; continue }
            $plainCache[$e.Path] = $plain
            if ($e.Type -ceq 'kv') {
                try { $pairs = Sec-KvParse $plain } catch { & $report 'ERROR' 'kv-parse' $e.Path; continue }
                $a = (Sec-SortOrdinal @($pairs | ForEach-Object { $_.Key })) -join "`n"
                $b = (Sec-SortOrdinal @($e.Fields)) -join "`n"
                if ($a -cne $b) { & $report 'ERROR' 'kv-fields' $e.Path; continue }
            }
            & $report 'OK' 'decrypt' $e.Path
        }
    }
    # materialized targets
    if ($catOk -and $recOk) {
        $approvals = Sec-ApprovalsRead
        foreach ($e in $ctx.Catalog.Entries) {
            if ($e.Type -cne 'file' -or -not $e.Target) { continue }
            if (-not (Sec-EntryAppliesHere $ctx $e $localKey)) { continue }
            $tr = Sec-ResolveTarget $e.Target $repo
            if (-not $tr.Ok) { & $report 'ERROR' 'target-invalid' $e.Path; continue }
            if (-not $approvals.Contains($e.Path + "`t" + $e.Target)) {
                $nm = $e.Path; if (Sec-TargetIsSensitive $e.Target) { $nm += ' (SENSITIVE)' }
                & $report 'WARN' 'target-unapproved' $nm; continue
            }
            if (-not [IO.File]::Exists($tr.Full)) { & $report 'WARN' 'materialized-missing' $e.Path; continue }
            $plain = $null
            if ($plainCache.ContainsKey($e.Path)) { $plain = $plainCache[$e.Path] }
            elseif ([IO.File]::Exists((Sec-RepoFile $ctx $e.StorePath))) { $plain = Sec-AgeDecrypt ([IO.File]::ReadAllBytes((Sec-RepoFile $ctx $e.StorePath))) $id }
            if ($null -eq $plain) { & $report 'ERROR' 'materialized' ($e.Path + ' (cannot decrypt to compare)'); continue }
            if ((Sec-Sha256Hex ([IO.File]::ReadAllBytes($tr.Full))) -cne (Sec-Sha256Hex $plain)) { & $report 'ERROR' 'materialized' $e.Path }
            else { & $report 'OK' 'materialized' $e.Path }
        }
    }
    # INCIDENT.md freshness (regenerated in memory only, never written from check)
    if ($catOk) {
        $invFile = [IO.Path]::Combine($repo, 'INCIDENT.md')
        if (-not [IO.File]::Exists($invFile)) { & $report 'WARN' 'inventory' 'INCIDENT.md is missing (run: secret inventory)' }
        else {
            $have = Sec-DecodeUtf8 ([IO.File]::ReadAllBytes($invFile))
            $want = Build-Inventory $ctx
            if ($have.Replace("`r`n", "`n") -cne $want) { & $report 'WARN' 'inventory' 'INCIDENT.md is out of date (run: secret inventory)' }
            else { & $report 'OK' 'inventory' 'INCIDENT.md' }
        }
    }
    # pre-commit hook installed?
    $wantHooks = ([IO.Path]::Combine($PSScriptRoot, 'githooks')).Replace([char]92, [char]47)
    if (Sec-IsGitRepo $repo) {
        $hp = Sec-Git $repo @('config', '--get', 'core.hooksPath') $null
        $have = ''
        if ($hp.Code -eq 0) { $have = $hp.Out.Trim().Replace([char]92, [char]47) }
        if (-not $have) { & $report 'ERROR' 'hooks' 'core.hooksPath is not set (run: secret hooks install)' }
        elseif (-not (Sec-SamePath $have $wantHooks)) { & $report 'ERROR' 'hooks' ("core.hooksPath is '$have', expected '$wantHooks' (run: secret hooks install)") }
        else { & $report 'OK' 'hooks' $have }
    }
    # values showing up in long-lived local logs (they must never be written there)
    if (-not (Opt $p '--no-log-scan') -and -not (Opt $p '--quick')) {
        $logs = New-Object 'System.Collections.Generic.List[string]'
        # SECRET_SCAN_LOGS: long-lived logs of your own services (paths separated by the platform path separator),
        # so a scheduled `secret check` covers them without repeating --scan-log. Missing files are skipped.
        if ($env:SECRET_SCAN_LOGS) {
            foreach ($f in ($env:SECRET_SCAN_LOGS -split [regex]::Escape([string][IO.Path]::PathSeparator))) {
                if ($f -and [IO.File]::Exists($f)) { $logs.Add([IO.Path]::GetFullPath($f)) }
            }
        }
        $secretLogDir = Sec-StateDir
        if ([IO.Directory]::Exists($secretLogDir)) { foreach ($f in [IO.Directory]::GetFiles($secretLogDir, '*.log')) { $logs.Add($f) } }
        if ($null -ne (Opt $p '--scan-log')) {
            foreach ($f in (Opt $p '--scan-log')) {
                if ([IO.File]::Exists($f)) { $logs.Add([IO.Path]::GetFullPath($f)) } else { & $report 'WARN' 'log-leak' "no such log: $f" }
            }
        }
        $needles = Get-LeakNeedles $ctx $id $localKey $expected $plainCache $catOk
        if ($needles.Count -eq 0 -or $logs.Count -eq 0) { & $report 'OK' 'log-leak' ('scanned ' + $logs.Count + ' log(s)') }
        else {
            $leaks = 0
            foreach ($lf in $logs) {
                foreach ($lbl in (Sec-ScanFileForNeedles $lf $needles)) { & $report 'ERROR' 'log-leak' ([IO.Path]::GetFileName($lf) + ' ' + $lbl); $leaks++ }
            }
            if ($leaks -eq 0) { & $report 'OK' 'log-leak' ('scanned ' + $logs.Count + ' log(s), ' + $needles.Count + ' value(s)') }
        }
    }
    # git: local-vs-upstream drift. Deliberately no `git fetch` here -- @{u} is whatever the last fetch/pull
    # already cached, so this stays offline-safe (no network call to fail and no way for a flaky connection
    # to turn into a false ERROR on a scheduled run). It only catches commits this machine
    # already knows about, which is exactly "did `secret add` actually leave something unpushed".
    if (Sec-IsGitRepo $repo) {
        $st = Sec-Git $repo @('status', '--porcelain') $null
        if ($st.Code -eq 0 -and $st.Out.Trim()) { & $report 'WARN' 'git' 'uncommitted changes' }
        $up = Sec-Git $repo @('rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}') $null
        if ($up.Code -ne 0) { & $report 'WARN' 'git' 'no upstream' }
        else {
            $lr = Sec-Git $repo @('rev-list', '--left-right', '--count', 'HEAD...@{u}') $null
            if ($lr.Code -eq 0 -and $lr.Out.Trim() -match '^(\d+)\s+(\d+)$') {
                if ([int]$Matches[1] -gt 0) { & $report 'WARN' 'git' ('ahead of upstream by ' + $Matches[1] + ' -- not pushed, run: git -C ' + $repo + ' push') }
                if ([int]$Matches[2] -gt 0) { & $report 'WARN' 'git' ('behind upstream by ' + $Matches[2]) }
            }
        }
    } else { & $report 'WARN' 'git' 'not a git work tree' }
    # recovery file left on the desktop
    $desk = Get-DesktopDir
    if ($desk -and [IO.Directory]::Exists($desk)) {
        foreach ($df in [IO.Directory]::GetFiles($desk, 'secret-recovery-identity-*.txt')) { & $report 'WARN' 'recovery-desktop' ([IO.Path]::GetFileName($df)) }
    }
    # web
    $web = Opt $p '--web'
    if ($web) {
        $head = $null
        if (Sec-IsGitRepo $repo) { $h = Sec-Git $repo @('rev-parse', 'HEAD') $null; if ($h.Code -eq 0) { $head = $h.Out.Trim() } }
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Encoding = [Text.Encoding]::UTF8
            $body = $wc.DownloadString($web.TrimEnd('/') + '/health')
            $m = [regex]::Match($body, '[0-9a-f]{40}')
            if (-not $m.Success) { & $report 'WARN' 'web' 'health response has no commit id' }
            elseif ($head -and $m.Value -ceq $head) { & $report 'OK' 'web' ('HEAD ' + $head.Substring(0, 12)) }
            else { & $report 'WARN' 'web' ('web reports ' + $m.Value.Substring(0, 12) + ', local HEAD differs') }
        } catch { & $report 'WARN' 'web' ('unreachable: ' + $web) }
    }
    if ($script:ck.Err -gt 0) { return 1 }
    if ($script:ck.Warn -gt 0) { return 2 }
    return 0
}

function Cmd-Recovery([string[]]$Argv) {
    if ($Argv.Length -eq 0) { Sec-Fail 'usage: secret recovery new|drill|seal|confirm' }
    $sub = $Argv[0]
    $rest = [string[]]@($Argv | Select-Object -Skip 1)
    $p = Parse-Opts $rest (Add-WriteSpec @{ '--out' = 'value'; '--replace' = 'switch'; '--identity' = 'value' }) -LocalIdentity
    switch -CaseSensitive ($sub) {
        'new' {
            $ctx = Open-Ctx -Write
            $same = @($ctx.Recipients.Items | Where-Object { $_.Name -ceq 'recovery' })
            $activeRec = @($ctx.Recipients.Items | Where-Object { $_.Type -ceq 'recovery' -and $_.Status -ceq 'active' })
            if (($activeRec.Count -gt 0 -or $same.Count -gt 0) -and -not (Opt $p '--replace')) { Sec-Fail 'a recovery recipient already exists (use --replace)' }
            $out = Opt $p '--out'
            if (-not $out) { $out = [IO.Path]::Combine((Get-DesktopDir), ('secret-recovery-identity-' + (Get-Date).ToString('yyyyMMdd') + '.txt')) }
            $pub = Sec-NewIdentityFile ([IO.Path]::GetFullPath($out))
            Out-Line $pub
            if ($same.Count -gt 0) { $t = $same[0].Table; $t.Pairs.Clear() } else { $t = Sec-NewTable 'recipient'; $ctx.Recipients.Doc.Tables.Add($t) }
            if (Opt $p '--replace') {
                foreach ($r in $activeRec) { if ($r.Name -cne 'recovery') { $r.Table.Pairs['status'] = 'revoked' } }
            }
            $t.Pairs['name'] = 'recovery'; $t.Pairs['type'] = 'recovery'; $t.Pairs['key'] = $pub; $t.Pairs['status'] = 'active'
            $t.Pairs['added'] = Sec-Today; $t.Pairs['backup'] = ''
            Sec-TomlWriteFile (Sec-RepoFile $ctx 'recipients.toml') $ctx.Recipients.Doc
            Finish-Write $ctx @('recipients.toml') $p 'secret: add recovery recipient'
            Err-Line "recovery identity written to $out (private key not shown)"
            Err-Line "next: 'secret rekey'; store the file offline, delete it, then 'secret recovery confirm'"
            return 0
        }
        'drill' {
            $rid = Opt $p '--identity'
            if (-not $rid) { Sec-Fail 'usage: secret recovery drill --identity <recovery identity file> [<path>]' }
            $ctx = Open-Ctx
            $id = Require-Identity
            if ($p.Pos.Count -gt 0) { $e = Need-Entry $ctx $p.Pos[0] }
            else { if ($ctx.Catalog.Entries.Count -eq 0) { Sec-Fail 'catalog is empty' }; $e = $ctx.Catalog.Entries[0] }
            $f = Sec-RepoFile $ctx $e.StorePath
            if (-not [IO.File]::Exists($f)) { Sec-Fail ('ciphertext missing: ' + $e.StorePath) }
            $c = [IO.File]::ReadAllBytes($f)
            $viaRec = Sec-AgeDecrypt $c $rid
            $viaLocal = Sec-AgeDecrypt $c $id -Throw
            $match = ($null -ne $viaRec -and (Sec-Sha256Hex $viaRec) -ceq (Sec-Sha256Hex $viaLocal))
            if ($match) { Out-Line 'match true'; return 0 }
            Out-Line 'match false'; return 1
        }
        'seal' {
            $rid = Opt $p '--identity'
            if (-not $rid -or -not [IO.File]::Exists($rid)) { Sec-Fail 'usage: secret recovery seal --identity <recovery identity file>' }
            $ctx = Open-Ctx -Write
            $dst = Sec-RepoFile $ctx 'recovery/recovery-identity.age'
            if ([IO.File]::Exists($dst) -and -not (Opt $p '--replace')) { Sec-Fail 'recovery/recovery-identity.age exists (use --replace)' }
            $dir = [IO.Path]::GetDirectoryName($dst)
            if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
            $tmp = [IO.Path]::Combine($dir, '.recovery-identity.age.tmp-' + (Sec-RandHex 4))
            try {
                $launch = New-Object psobject -Property @{ File = (Sec-FindExe 'age'); Args = (Sec-JoinArgs @('-p', '-o', $tmp, $rid)) }
                $code = Start-Inherited $launch $null
                if ($code -ne 0) { Sec-Fail "age -p failed (exit $code)" }
                if (-not (Sec-HasAgeHeader ([IO.File]::ReadAllBytes($tmp)))) { Sec-Fail 'age -p output has no age header' }
                Sec-MoveOver $tmp $dst
            } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
            Finish-Write $ctx @('recovery/recovery-identity.age') $p 'secret: seal recovery identity'
            Err-Line 'sealed recovery/recovery-identity.age'
            return 0
        }
        'confirm' {
            $ctx = Open-Ctx -Write
            $desk = Get-DesktopDir
            if ($desk -and [IO.Directory]::Exists($desk) -and [IO.Directory]::GetFiles($desk, 'secret-recovery-identity-*.txt').Length -gt 0) {
                Sec-Fail 'a secret-recovery-identity-*.txt is still on the desktop; store it offline and delete it first'
            }
            $recs = @($ctx.Recipients.Items | Where-Object { $_.Type -ceq 'recovery' -and $_.Status -ceq 'active' })
            if ($recs.Count -eq 0) { Sec-Fail 'no active recovery recipient' }
            foreach ($r in $recs) { $r.Table.Pairs['backup'] = 'offline ' + (Sec-Today) }
            Sec-TomlWriteFile (Sec-RepoFile $ctx 'recipients.toml') $ctx.Recipients.Doc
            Finish-Write $ctx @('recipients.toml') $p 'secret: recovery backup confirmed'
            Err-Line 'recovery backup confirmed'
            return 0
        }
        default { Sec-Fail "unknown recovery subcommand: $sub" }
    }
}

function Cmd-Hooks([string[]]$Argv) {
    $p = Parse-Opts $Argv @{}
    if ($p.Pos.Count -ne 1 -or $p.Pos[0] -cne 'install') { Sec-Fail 'usage: secret hooks install' }
    $repo = Get-RepoDir
    if (-not (Sec-IsGitRepo $repo)) { Sec-Fail "not a git work tree: $repo" }
    $dir = ([IO.Path]::Combine($PSScriptRoot, 'githooks')).Replace([char]92, [char]47)
    $r = Sec-Git $repo @('config', 'core.hooksPath', $dir) $null
    if ($r.Code -ne 0) { Sec-Fail 'git config failed' }
    Err-Line "core.hooksPath = $dir"
    return 0
}

function Cmd-HookPreCommit([string[]]$Argv) {
    $p = Parse-Opts $Argv @{}
    $repo = Get-RepoDir
    $problems = Sec-PreCommitProblems $repo
    if ($problems.Count -eq 0) { return 0 }
    Err-Line 'secret pre-commit: commit rejected'
    foreach ($x in $problems) { Err-Line "  $x" }
    return 1
}

function Show-Usage {
    Out-Line 'usage: secret [--repo <dir>] [--identity <file>] [--pull] <command> ...'
    Out-Line 'commands: init, recipients, rekey, add, edit, rm, show, get, run, materialize, list, info, inventory, resolve, check, recovery, hooks'
    Out-Line 'see scripts/secrets/README.md'
}

function Invoke-SecretMain([string[]]$Argv) {
    $i = 0
    while ($i -lt $Argv.Length) {
        $a = $Argv[$i]
        if ($a -ceq '--repo' -or $a -ceq '--identity') {
            if ($i + 1 -ge $Argv.Length) { Sec-Fail "option $a needs a value" }
            if ($a -ceq '--repo') { $script:G.Repo = $Argv[$i + 1] } else { $script:G.Identity = $Argv[$i + 1] }
            $i += 2; continue
        }
        if ($a -ceq '--pull') { $script:G.Pull = $true; $i++; continue }
        if ($a -ceq '--lock-timeout') {
            if ($i + 1 -ge $Argv.Length) { Sec-Fail 'option --lock-timeout needs a value' }
            $script:G.LockTimeout = Parse-LockTimeout $Argv[$i + 1]
            $i += 2; continue
        }
        break
    }
    if ($i -ge $Argv.Length) { Show-Usage; return 1 }
    $cmd = $Argv[$i]
    $script:G.Cmd = $cmd
    $rest = [string[]]@($Argv | Select-Object -Skip ($i + 1))
    switch -CaseSensitive ($cmd) {
        'init' { return (Cmd-Init $rest) }
        'recipients' { return (Cmd-Recipients $rest) }
        'rekey' { return (Cmd-Rekey $rest) }
        'add' { return (Cmd-Add $rest) }
        'edit' { return (Cmd-Edit $rest) }
        'rm' { return (Cmd-Rm $rest) }
        'inventory' { return (Cmd-Inventory $rest) }
        'show' { return (Cmd-Show $rest) }
        'get' { return (Cmd-Get $rest) }
        'run' { return (Cmd-Run $rest) }
        'materialize' { return (Cmd-Materialize $rest) }
        'list' { return (Cmd-List $rest) }
        'info' { return (Cmd-Info $rest) }
        'resolve' { return (Cmd-Resolve $rest) }
        'check' { return (Cmd-Check $rest) }
        'recovery' { return (Cmd-Recovery $rest) }
        'hooks' { return (Cmd-Hooks $rest) }
        'hook-pre-commit' { return (Cmd-HookPreCommit $rest) }
        { @('help', '-h', '--help') -ccontains $_ } { Show-Usage; return 0 }
        default { Sec-Fail "unknown command: $cmd" }
    }
}

$prevEnc = $null
try { $prevEnc = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$exitCode = 1
try {
    $exitCode = [int](@(Invoke-SecretMain ([string[]]$args))[-1])
} catch {
    [Console]::Error.Write('secret: ' + $_.Exception.Message + "`n")
    $exitCode = 1
} finally {
    Sec-ReleaseLock $script:G.Lock
    try { [Console]::Out.Flush() } catch { }
    if ($null -ne $prevEnc) { try { [Console]::OutputEncoding = $prevEnc } catch { } }
}
exit $exitCode
