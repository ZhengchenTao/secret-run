# cli/SecretLib.ps1 -- shared library for the `secret` CLI (secret-run data repo, FORMAT.md v1). Dot-source only.
#
# ASCII-only on purpose: Windows PowerShell 5.1 reads BOM-less UTF-8 scripts in the ANSI code page and mangles
# anything non-ASCII (the same applies to any script loaded by 5.1). Must work on 5.1 and pwsh 7: no `??`,
# no ternary, no -AsHashtable, no ProcessStartInfo.ArgumentList, no multi-arg Join-Path.
#
# Contents: env / paths, bytes & hashing, process runner (age / git / icacls, stdin/stdout as bytes, never temp
# files), restricted TOML parser + writer, recipients / policy / catalog models, glob, recipient-set hash, lock,
# kv (dotenv subset), aliases, materialize targets, ACL.
#
# Plaintext rule: values only ever live in byte arrays / strings in memory and in pipes to age. No function here
# puts a value into an exception message or prints it.

$ErrorActionPreference = 'Stop'

$script:SecUtf8 = New-Object System.Text.UTF8Encoding($false, $true)   # strict: throws on invalid bytes
$script:SecAgeHeader = 'age-encryption.org/v1' + "`n"
$script:SecReserved = @('con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8',
    'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9')
$script:SecKeyOrder = @{
    'recipient' = @('name', 'type', 'key', 'status', 'added', 'backup', 'note')
    'rule'      = @('path', 'recipients')
    'meta'      = @('format')
    'entry'     = @('path', 'type', 'title', 'description', 'fields', 'target', 'acl', 'machines', 'tags', 'rotate', 'readers', 'priority', 'linked', 'aliases', 'updated')
}
$script:SecLockHeader = '# secret recipients lock v1'
$script:SecStoreRegex = '^store/([a-z0-9][a-z0-9-]*)/([a-z0-9][a-z0-9-]*)/([a-z0-9][a-z0-9-]*)\.(kv|file|doc)\.age\z'

function Sec-Fail([string]$Message) { throw (New-Object System.InvalidOperationException($Message)) }

# ---------------------------------------------------------------- environment / paths

function Sec-IsWindows { return ($env:OS -eq 'Windows_NT') }

function Sec-Home {
    if ($env:SECRET_HOME) { return $env:SECRET_HOME }   # test-only override
    if (Sec-IsWindows) { return $env:USERPROFILE }       # never HOME: Git Bash rewrites it
    return $env:HOME
}

# {workspace}: the second materialize root (FORMAT 6) and the parent of the default repo. Only exists when
# SECRET_WORKSPACE is set -- there is no guessed default, so {workspace}/ targets are refused until you pick one.
function Sec-Workspace {
    if ($env:SECRET_WORKSPACE) { return $env:SECRET_WORKSPACE }
    return $null
}

# Default data repo: {workspace}/secrets when SECRET_WORKSPACE is set, else ~/secrets. SECRET_REPO / --repo win.
function Sec-DefaultRepo {
    $ws = Sec-Workspace
    if ($ws) { return [IO.Path]::Combine($ws, 'secrets') }
    return [IO.Path]::Combine((Sec-Home), 'secrets')
}

function Sec-DefaultIdentity { return [IO.Path]::Combine([IO.Path]::Combine((Sec-Home), '.config'), [IO.Path]::Combine('secrets', 'identity.txt')) }

function Sec-StateDir {
    if ($env:SECRET_STATE_DIR) { return $env:SECRET_STATE_DIR }   # test-only override
    if (Sec-IsWindows) { return [IO.Path]::Combine($env:LOCALAPPDATA, 'secret') }
    return [IO.Path]::Combine([IO.Path]::Combine((Sec-Home), '.local'), [IO.Path]::Combine('state', 'secret'))
}

function Sec-TmpDir {
    if ($env:SECRET_STATE_DIR) { return [IO.Path]::Combine($env:SECRET_STATE_DIR, 'tmp') }
    if (Sec-IsWindows) { return [IO.Path]::Combine([IO.Path]::Combine($env:LOCALAPPDATA, 'secret'), 'tmp') }
    return [IO.Path]::Combine([IO.Path]::Combine((Sec-Home), '.cache'), [IO.Path]::Combine('secret', 'tmp'))
}

function Sec-DeviceName {
    if ($env:SECRET_DEVICE_NAME) { return $env:SECRET_DEVICE_NAME }
    if (Sec-IsWindows) { return $env:COMPUTERNAME.ToLowerInvariant() }
    return ([System.Net.Dns]::GetHostName() -split '\.')[0].ToLowerInvariant()
}

function Sec-Today { return (Get-Date).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }

function Sec-Nfc([string]$s) { if ($null -eq $s) { return $null }; return $s.Normalize([Text.NormalizationForm]::FormC) }

function Sec-SortOrdinal($items) {
    $arr = [string[]]@($items)
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    return , $arr
}

function Sec-NewSet { return , (New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)) }
function Sec-NewDict { return , (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)) }
function Sec-NewList { return , (New-Object 'System.Collections.Generic.List[object]') }

# ---------------------------------------------------------------- bytes / hashing / files

function Sec-Sha256Hex([byte[]]$Bytes) {
    if ($null -eq $Bytes) { $Bytes = New-Object byte[] 0 }
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { $d = $h.ComputeHash($Bytes) } finally { $h.Dispose() }
    return ([BitConverter]::ToString($d) -replace '-', '').ToLowerInvariant()
}

function Sec-Utf8Bytes([string]$s) { return , ([Text.Encoding]::UTF8.GetBytes($s)) }

function Sec-DecodeUtf8([byte[]]$Bytes) {
    # strict decode; strips one leading BOM (readers tolerate it, FORMAT 2)
    try { $t = $script:SecUtf8.GetString($Bytes) } catch { Sec-Fail 'content is not valid UTF-8' }
    if ($t.Length -gt 0 -and [int]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
    return $t
}

function Sec-IsUtf8Text([byte[]]$Bytes) {
    try { $t = $script:SecUtf8.GetString($Bytes) } catch { return $false }
    foreach ($ch in $t.ToCharArray()) {
        $c = [int]$ch
        if (($c -lt 0x20 -and $c -ne 9 -and $c -ne 10 -and $c -ne 13) -or $c -eq 0x7F) { return $false }
    }
    return $true
}

function Sec-HasAgeHeader([byte[]]$Bytes) {
    $h = [Text.Encoding]::ASCII.GetBytes($script:SecAgeHeader)
    if ($null -eq $Bytes -or $Bytes.Length -lt $h.Length) { return $false }
    for ($i = 0; $i -lt $h.Length; $i++) { if ($Bytes[$i] -ne $h[$i]) { return $false } }
    return $true
}

function Sec-RandHex([int]$n = 8) {
    $b = New-Object byte[] $n
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($b) -replace '-', '').ToLowerInvariant()
}

# Rename over an existing file. The moved file keeps its own ACL (unlike File.Replace, which copies the old ACL).
# pwsh 7: File.Move(overwrite). 5.1 (.NET Framework has no overwrite overload): MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH).
function Sec-MoveOver([string]$Src, [string]$Dst) {
    if ($null -ne [IO.File].GetMethod('Move', [Type[]]@([string], [string], [bool]))) {
        [IO.File]::Move($Src, $Dst, $true)
        return
    }
    if (Sec-IsWindows) {
        if (-not ('SecNative.Fs' -as [type])) {
            Add-Type -Namespace SecNative -Name Fs -MemberDefinition '[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] public static extern bool MoveFileEx(string existing, string replacement, int flags);'
        }
        if (-not [SecNative.Fs]::MoveFileEx($Src, $Dst, 9)) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw (New-Object System.ComponentModel.Win32Exception($code, ("cannot replace " + $Dst + ": " + (New-Object System.ComponentModel.Win32Exception($code)).Message)))
        }
        return
    }
    if ([IO.File]::Exists($Dst)) { [IO.File]::Delete($Dst) }
    [IO.File]::Move($Src, $Dst)
}

# All-or-nothing (best effort) multi-file write. $Changes: ordered list of @{ Path; Bytes } (Bytes $null = delete).
# Phase 1 writes every new content to a temp file next to its target; phase 2 replaces in the given order; any
# failure restores already-replaced files from the old bytes kept in memory. Callers order ciphertexts -> lock -> catalog.
function Sec-ApplyChanges($Changes) {
    $items = New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($c in $Changes) {
            $it = @{ Path = $c.Path; Tmp = $null; Old = $null; Existed = [IO.File]::Exists($c.Path); Done = $false }
            if ($it.Existed) { $it.Old = [IO.File]::ReadAllBytes($c.Path) }
            $items.Add($it)
            if ($null -ne $c.Bytes) {
                $dir = [IO.Path]::GetDirectoryName($c.Path)
                if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
                $it.Tmp = [IO.Path]::Combine($dir, '.' + [IO.Path]::GetFileName($c.Path) + '.tmp-' + (Sec-RandHex 4))
                [IO.File]::WriteAllBytes($it.Tmp, [byte[]]$c.Bytes)
            }
        }
        foreach ($it in $items) {
            if ($it.Tmp) { Sec-MoveOver $it.Tmp $it.Path; $it.Tmp = $null }
            elseif ($it.Existed) { [IO.File]::Delete($it.Path) }
            $it.Done = $true
        }
    } catch {
        $why = $_.Exception.Message
        $incomplete = $false
        for ($i = $items.Count - 1; $i -ge 0; $i--) {
            $it = $items[$i]
            if (-not $it.Done) { continue }
            try {
                if ($it.Existed) {
                    $rb = $it.Path + '.rollback-' + (Sec-RandHex 4)
                    [IO.File]::WriteAllBytes($rb, [byte[]]$it.Old)
                    Sec-MoveOver $rb $it.Path
                } elseif ([IO.File]::Exists($it.Path)) { [IO.File]::Delete($it.Path) }
            } catch { $incomplete = $true }
        }
        if ($incomplete) { Sec-Fail ("write failed and ROLLBACK INCOMPLETE, inspect the repo with git status: " + $why) }
        Sec-Fail ("write failed, all files restored: " + $why)
    } finally {
        foreach ($it in $items) { if ($it.Tmp -and [IO.File]::Exists($it.Tmp)) { try { [IO.File]::Delete($it.Tmp) } catch { } } }
    }
}

# Temp file in the same dir -> (optional private ACL) -> write -> rename. Repo files keep inherited ACL.
function Sec-WriteFileAtomic([string]$Path, [byte[]]$Bytes, [switch]$Private) {
    $dir = [IO.Path]::GetDirectoryName($Path)
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    $tmp = [IO.Path]::Combine($dir, '.' + [IO.Path]::GetFileName($Path) + '.tmp-' + (Sec-RandHex 4))
    try {
        [IO.File]::WriteAllBytes($tmp, (New-Object byte[] 0))
        if ($Private) { Sec-SetPrivateAcl $tmp }
        [IO.File]::WriteAllBytes($tmp, $Bytes)
        Sec-MoveOver $tmp $Path
    } finally {
        if ([IO.File]::Exists($tmp)) { try { [IO.File]::Delete($tmp) } catch { } }
    }
}

function Sec-RemoveFileWiped([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return }
    try {
        $len = (New-Object IO.FileInfo($Path)).Length
        $fs = [IO.File]::Open($Path, 'Open', 'Write')
        try { $fs.Write((New-Object byte[] $len), 0, [int]$len); $fs.Flush() } finally { $fs.Dispose() }
    } catch { }
    [IO.File]::Delete($Path)
}

# ---------------------------------------------------------------- processes

# MSVCRT / CommandLineToArgvW quoting (5.1 has no ProcessStartInfo.ArgumentList).
function Sec-QuoteArg([string]$a) {
    if ($null -eq $a) { $a = '' }
    if ($a.Length -gt 0 -and $a -notmatch '[\s"]') { return $a }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $a.ToCharArray()) {
        if ([int]$ch -eq 92) { $bs++; continue }
        if ([int]$ch -eq 34) { [void]$sb.Append([char]92, 2 * $bs + 1); [void]$sb.Append('"'); $bs = 0; continue }
        if ($bs -gt 0) { [void]$sb.Append([char]92, $bs); $bs = 0 }
        [void]$sb.Append($ch)
    }
    if ($bs -gt 0) { [void]$sb.Append([char]92, 2 * $bs) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Sec-JoinArgs([string[]]$ArgList) {
    if ($null -eq $ArgList) { return '' }
    return ((@($ArgList) | ForEach-Object { Sec-QuoteArg $_ }) -join ' ')
}

function Sec-FindExe([string]$Name) {
    $c = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $c) { Sec-Fail "'$Name' not found in PATH" }
    return $c.Path
}

# Run a program with stdin/stdout/stderr redirected. stdin and stdout are raw bytes (in memory only);
# both output streams are drained asynchronously so a full pipe can never deadlock.
function Sec-Exec([string]$File, [string[]]$ArgList, [byte[]]$Stdin) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = Sec-JoinArgs $ArgList
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # The redirected stdin writer takes Console.InputEncoding; when that is UTF-8 *with* preamble (code page 65001,
    # e.g. inside an sshd session) it emits a BOM before our bytes and age rejects the
    # header ("unexpected intro: <BOM>age-encryption.org/v1"). Force a BOM-less encoding for the child's stdin.
    $noBom = New-Object System.Text.UTF8Encoding($false)
    $restoreIn = $null
    if ($psi.GetType().GetProperty('StandardInputEncoding')) { $psi.StandardInputEncoding = $noBom }
    else { try { $restoreIn = [Console]::InputEncoding; [Console]::InputEncoding = $noBom } catch { $restoreIn = $null } }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try { [void]$p.Start() } finally { if ($null -ne $restoreIn) { try { [Console]::InputEncoding = $restoreIn } catch { } } }
    $outMs = New-Object System.IO.MemoryStream
    $errMs = New-Object System.IO.MemoryStream
    $t1 = $p.StandardOutput.BaseStream.CopyToAsync($outMs)
    $t2 = $p.StandardError.BaseStream.CopyToAsync($errMs)
    try {
        if ($null -ne $Stdin -and $Stdin.Length -gt 0) { $p.StandardInput.BaseStream.Write($Stdin, 0, $Stdin.Length) }
        $p.StandardInput.BaseStream.Flush()
    } catch { } finally { try { $p.StandardInput.Close() } catch { } }
    $t1.Wait(); $t2.Wait(); $p.WaitForExit()
    $r = New-Object psobject -Property @{
        ExitCode = $p.ExitCode
        Stdout   = $outMs.ToArray()
        Stderr   = [Text.Encoding]::UTF8.GetString($errMs.ToArray())
    }
    $p.Dispose()
    return $r
}

function Sec-FirstLine([string]$s) {
    if (-not $s) { return '' }
    $l = @($s.Trim() -split "`r?`n")[0]
    return $l
}

# ---------------------------------------------------------------- age

function Sec-AgeEncrypt([byte[]]$Plain, [string[]]$Keys) {
    if (-not $Keys -or @($Keys).Count -eq 0) { Sec-Fail 'no recipients to encrypt to' }
    $a = New-Object 'System.Collections.Generic.List[string]'
    $a.Add('-e')
    foreach ($k in $Keys) { $a.Add('-r'); $a.Add($k) }
    $r = Sec-Exec (Sec-FindExe 'age') $a.ToArray() $Plain
    if ($r.ExitCode -ne 0) { Sec-Fail ("age encrypt failed (exit " + $r.ExitCode + "): " + (Sec-FirstLine $r.Stderr)) }
    if (-not (Sec-HasAgeHeader $r.Stdout)) { Sec-Fail 'age produced output without the age-encryption.org/v1 header' }
    return , $r.Stdout
}

# Returns $null on failure (so callers decide how to report); -Throw raises instead.
function Sec-AgeDecrypt([byte[]]$Cipher, [string]$Identity, [switch]$Throw) {
    if (-not [IO.File]::Exists($Identity)) {
        if ($Throw) { Sec-Fail "identity file not found: $Identity" }
        return $null
    }
    $r = Sec-Exec (Sec-FindExe 'age') @('-d', '-i', $Identity) $Cipher
    if ($r.ExitCode -ne 0) {
        if ($Throw) { Sec-Fail ("age decrypt failed (exit " + $r.ExitCode + "): " + (Sec-FirstLine $r.Stderr)) }
        return $null
    }
    return , $r.Stdout
}

function Sec-IdentityPublicKey([string]$Identity) {
    if (-not [IO.File]::Exists($Identity)) { Sec-Fail "identity file not found: $Identity" }
    $r = Sec-Exec (Sec-FindExe 'age-keygen') @('-y', $Identity) $null
    if ($r.ExitCode -ne 0) { Sec-Fail ("age-keygen -y failed (exit " + $r.ExitCode + ")") }
    $k = ([Text.Encoding]::ASCII.GetString($r.Stdout)).Trim()
    if ($k -cnotmatch '^age1[02-9ac-hj-np-z]{58}\z') { Sec-Fail 'identity does not hold a single X25519 key' }
    return $k
}

# Generates a new identity into $Path (must not exist): age-keygen writes to our stdout pipe, we write the bytes
# into a file whose ACL was tightened while still empty, then rename. Returns the public key.
function Sec-NewIdentityFile([string]$Path) {
    if ([IO.File]::Exists($Path)) { Sec-Fail "refusing to overwrite existing file: $Path" }
    $r = Sec-Exec (Sec-FindExe 'age-keygen') @() $null
    if ($r.ExitCode -ne 0) { Sec-Fail ("age-keygen failed (exit " + $r.ExitCode + ")") }
    Sec-WriteFileAtomic $Path $r.Stdout -Private
    [Array]::Clear($r.Stdout, 0, $r.Stdout.Length)
    return (Sec-IdentityPublicKey $Path)
}

# ---------------------------------------------------------------- ACL

function Sec-SetPrivateAcl([string]$Path, [switch]$Directory) {
    if (Sec-IsWindows) {
        $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $perm = 'F'
        if ($Directory) { $perm = '(OI)(CI)F' }
        $icacls = [IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'icacls.exe')
        $r = Sec-Exec $icacls @($Path, '/inheritance:r', '/grant:r', ('*' + $sid + ':' + $perm)) $null
        if ($r.ExitCode -ne 0) { Sec-Fail ("icacls failed on $Path (exit " + $r.ExitCode + ")") }
        # An elevated token (e.g. an sshd session) makes BUILTIN\Administrators the owner, and the owner can always
        # rewrite the DACL. Best effort: hand ownership back to the current user (seen on Windows 11).
        [void](Sec-Exec $icacls @($Path, '/setowner', ('*' + $sid)) $null)
    } else {
        $mode = '600'
        if ($Directory) { $mode = '700' }
        $r = Sec-Exec (Sec-FindExe 'chmod') @($mode, $Path) $null
        if ($r.ExitCode -ne 0) { Sec-Fail "chmod failed on $Path" }
    }
}

function Sec-EnsurePrivateDir([string]$Dir) {
    if (-not [IO.Directory]::Exists($Dir)) {
        [void][IO.Directory]::CreateDirectory($Dir)
        Sec-SetPrivateAcl $Dir -Directory
    }
}

# ---------------------------------------------------------------- restricted TOML (FORMAT 3)

function Sec-TpErr($st, [string]$msg) { Sec-Fail ($st.Src + ': line ' + $st.Line + ': ' + $msg) }

function Sec-TpSkipWs($st) {
    while ($st.I -lt $st.N) {
        $c = [int]$st.S[$st.I]
        if ($c -eq 32 -or $c -eq 9) { $st.I++ } else { break }
    }
}

function Sec-TpSkipComment($st) {
    if ($st.I -lt $st.N -and $st.S[$st.I] -eq [char]'#') {
        while ($st.I -lt $st.N -and [int]$st.S[$st.I] -ne 10) {
            $c = [int]$st.S[$st.I]
            if (($c -lt 32 -and $c -ne 9) -or $c -eq 127) { Sec-TpErr $st 'control character in comment' }
            $st.I++
        }
    }
}

function Sec-TpExpectEol($st) {
    Sec-TpSkipWs $st
    Sec-TpSkipComment $st
    if ($st.I -ge $st.N) { return }
    if ([int]$st.S[$st.I] -ne 10) { Sec-TpErr $st 'unexpected content after value' }
    $st.I++; $st.Line++
}

function Sec-TpSkipBlank($st) {
    while ($st.I -lt $st.N) {
        $c = [int]$st.S[$st.I]
        if ($c -eq 32 -or $c -eq 9) { $st.I++ }
        elseif ($c -eq 10) { $st.I++; $st.Line++ }
        elseif ($c -eq 35) { Sec-TpSkipComment $st }
        else { break }
    }
}

function Sec-TpIsBare([int]$c) {
    return (($c -ge 65 -and $c -le 90) -or ($c -ge 97 -and $c -le 122) -or ($c -ge 48 -and $c -le 57) -or $c -eq 95 -or $c -eq 45)
}

function Sec-TpBareKey($st) {
    $start = $st.I
    while ($st.I -lt $st.N -and (Sec-TpIsBare ([int]$st.S[$st.I]))) { $st.I++ }
    if ($st.I -eq $start) { Sec-TpErr $st 'expected a bare key' }
    return $st.S.Substring($start, $st.I - $start)
}

function Sec-TpBasicString($st) {
    if ($st.I + 2 -lt $st.N -and $st.S.Substring($st.I, 3) -ceq '"""') { Sec-TpErr $st 'multi-line strings are not allowed' }
    $st.I++
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        if ($st.I -ge $st.N) { Sec-TpErr $st 'unterminated string' }
        $ch = $st.S[$st.I]; $c = [int]$ch
        if ($c -eq 34) { $st.I++; return $sb.ToString() }
        if ($c -eq 10) { Sec-TpErr $st 'unterminated string' }
        if ($c -eq 92) {
            if ($st.I + 1 -ge $st.N) { Sec-TpErr $st 'unterminated escape' }
            $e = [int]$st.S[$st.I + 1]
            if ($e -eq 34) { [void]$sb.Append('"'); $st.I += 2 }
            elseif ($e -eq 92) { [void]$sb.Append([char]92); $st.I += 2 }
            elseif ($e -eq 110) { [void]$sb.Append([char]10); $st.I += 2 }
            elseif ($e -eq 116) { [void]$sb.Append([char]9); $st.I += 2 }
            elseif ($e -eq 114) { [void]$sb.Append([char]13); $st.I += 2 }
            elseif ($e -eq 117) {
                if ($st.I + 6 -gt $st.N) { Sec-TpErr $st 'bad \u escape' }
                $hex = $st.S.Substring($st.I + 2, 4)
                if ($hex -cnotmatch '^[0-9A-Fa-f]{4}\z') { Sec-TpErr $st 'bad \u escape' }
                $v = [Convert]::ToInt32($hex, 16)
                if ($v -ge 0xD800 -and $v -le 0xDFFF) { Sec-TpErr $st '\u escape in surrogate range' }
                if ($v -lt 32 -or $v -eq 127) { Sec-TpErr $st '\u escape decodes to a control character (only \t \n \r are allowed)' }
                [void]$sb.Append([char]$v); $st.I += 6
            }
            else { Sec-TpErr $st 'invalid escape sequence' }
            continue
        }
        if ($c -lt 32 -or $c -eq 127) { Sec-TpErr $st 'control character in string (use an escape)' }
        [void]$sb.Append($ch); $st.I++
    }
}

function Sec-TpLiteralString($st) {
    if ($st.I + 2 -lt $st.N -and $st.S.Substring($st.I, 3) -ceq "'''") { Sec-TpErr $st 'multi-line strings are not allowed' }
    $st.I++
    $start = $st.I
    while ($true) {
        if ($st.I -ge $st.N) { Sec-TpErr $st 'unterminated string' }
        $c = [int]$st.S[$st.I]
        if ($c -eq 39) { $v = $st.S.Substring($start, $st.I - $start); $st.I++; return $v }
        if ($c -eq 10) { Sec-TpErr $st 'unterminated string' }
        if ($c -lt 32 -or $c -eq 127) { Sec-TpErr $st 'control character in string' }
        $st.I++
    }
}

function Sec-TpValue($st) {
    if ($st.I -ge $st.N) { Sec-TpErr $st 'missing value' }
    $c = [int]$st.S[$st.I]
    if ($c -eq 34) { return (Sec-TpBasicString $st) }
    if ($c -eq 39) { return (Sec-TpLiteralString $st) }
    if ($c -eq 91) {
        $st.I++
        $list = New-Object 'System.Collections.Generic.List[string]'
        while ($true) {
            Sec-TpSkipBlank $st
            if ($st.I -ge $st.N) { Sec-TpErr $st 'unterminated array' }
            $d = [int]$st.S[$st.I]
            if ($d -eq 93) { $st.I++; break }
            if ($d -eq 34) { $list.Add((Sec-TpBasicString $st)) }
            elseif ($d -eq 39) { $list.Add((Sec-TpLiteralString $st)) }
            else { Sec-TpErr $st 'array elements must be strings' }
            Sec-TpSkipBlank $st
            if ($st.I -ge $st.N) { Sec-TpErr $st 'unterminated array' }
            $d = [int]$st.S[$st.I]
            if ($d -eq 44) { $st.I++; continue }
            if ($d -eq 93) { $st.I++; break }
            Sec-TpErr $st 'expected , or ] in array'
        }
        return , ([string[]]$list.ToArray())
    }
    foreach ($w in @('true', 'false')) {
        if ($st.I + $w.Length -le $st.N -and $st.S.Substring($st.I, $w.Length) -ceq $w) {
            $j = $st.I + $w.Length
            if ($j -ge $st.N -or @(32, 9, 10, 35) -contains [int]$st.S[$j]) {
                $st.I = $j
                return ($w -ceq 'true')
            }
        }
    }
    if ($c -eq 123) { Sec-TpErr $st 'inline tables are not allowed' }
    Sec-TpErr $st 'unsupported value (only strings, string arrays, booleans)'
}

# Returns @{ Header = string[] (leading comment lines); Tables = List of @{ Name; Pairs (ordinal OrderedDictionary) } }
function Sec-TomlParse([string]$Text, [string]$Source = 'toml') {
    if ($null -eq $Text) { $Text = '' }
    if ($Text.Length -gt 0 -and [int]$Text[0] -eq 0xFEFF) { $Text = $Text.Substring(1) }
    $Text = $Text.Replace("`r`n", "`n")
    $header = New-Object 'System.Collections.Generic.List[string]'
    foreach ($ln in $Text.Split([char]10)) {
        if ($ln.StartsWith('#')) { $header.Add($ln) } else { break }
    }
    $st = @{ S = $Text; I = 0; N = $Text.Length; Line = 1; Src = $Source }
    $tables = New-Object 'System.Collections.Generic.List[object]'
    $cur = $null
    while ($st.I -lt $st.N) {
        $c = [int]$st.S[$st.I]
        if ($c -eq 32 -or $c -eq 9) { Sec-TpSkipWs $st; continue }
        if ($c -eq 10) { $st.I++; $st.Line++; continue }
        if ($c -eq 35) { Sec-TpSkipComment $st; continue }
        if ($c -eq 91) {
            if ($st.I + 1 -lt $st.N -and [int]$st.S[$st.I + 1] -eq 91) {
                $st.I += 2
                $name = Sec-TpBareKey $st
                if ($st.I + 1 -ge $st.N -or $st.S.Substring($st.I, 2) -cne ']]') { Sec-TpErr $st 'expected ]] (table names are bare keys without spaces or dots)' }
                $st.I += 2
                Sec-TpExpectEol $st
                $cur = New-Object psobject -Property @{ Name = $name; Pairs = (New-Object System.Collections.Specialized.OrderedDictionary([StringComparer]::Ordinal)) }
                $tables.Add($cur)
                continue
            }
            Sec-TpErr $st 'standard tables [name] are not allowed (only [[name]])'
        }
        if (Sec-TpIsBare $c) {
            if ($null -eq $cur) { Sec-TpErr $st 'key/value pair outside of a [[table]]' }
            $key = Sec-TpBareKey $st
            Sec-TpSkipWs $st
            if ($st.I -lt $st.N -and [int]$st.S[$st.I] -eq 46) { Sec-TpErr $st 'dotted keys are not allowed' }
            if ($st.I -ge $st.N -or [int]$st.S[$st.I] -ne 61) { Sec-TpErr $st 'expected =' }
            $st.I++
            Sec-TpSkipWs $st
            $val = Sec-TpValue $st
            if ($cur.Pairs.Contains($key)) { Sec-TpErr $st "duplicate key '$key'" }
            $cur.Pairs.Add($key, $val)
            Sec-TpExpectEol $st
            continue
        }
        if ($c -eq 34 -or $c -eq 39) { Sec-TpErr $st 'quoted keys are not allowed' }
        Sec-TpErr $st 'unexpected character'
    }
    return (New-Object psobject -Property @{ Header = [string[]]$header.ToArray(); Tables = $tables })
}

function Sec-TomlQuote([string]$v) {
    $v = Sec-Nfc $v
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $v.ToCharArray()) {
        $c = [int]$ch
        if ($c -eq 34) { [void]$sb.Append('\"') }
        elseif ($c -eq 92) { [void]$sb.Append('\\') }
        elseif ($c -eq 10) { [void]$sb.Append('\n') }
        elseif ($c -eq 9) { [void]$sb.Append('\t') }
        elseif ($c -eq 13) { [void]$sb.Append('\r') }
        elseif ($c -lt 32 -or $c -eq 127) { Sec-Fail 'string value contains a control character (only tab, LF, CR can be written)' }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Sec-TomlFormatValue($v) {
    if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
    if ($v -is [string]) { return (Sec-TomlQuote $v) }
    if ($v -is [array]) {
        $parts = @(@($v) | ForEach-Object { Sec-TomlQuote ([string]$_) })
        return ('[' + ($parts -join ', ') + ']')
    }
    Sec-Fail 'cannot write value of unsupported type'
}

# Canonical form: header comments, blank line, blocks separated by one blank line, known keys in FORMAT order,
# unknown keys after them in their original order.
function Sec-TomlFormat($Doc) {
    $sb = New-Object System.Text.StringBuilder
    foreach ($h in $Doc.Header) { [void]$sb.Append($h + "`n") }
    $first = $true
    foreach ($t in $Doc.Tables) {
        if ($first) { if ($Doc.Header.Count -gt 0) { [void]$sb.Append("`n") }; $first = $false } else { [void]$sb.Append("`n") }
        [void]$sb.Append('[[' + $t.Name + ']]' + "`n")
        $order = @()
        if ($script:SecKeyOrder.ContainsKey($t.Name)) { $order = $script:SecKeyOrder[$t.Name] }
        $keys = New-Object 'System.Collections.Generic.List[string]'
        foreach ($k in $order) { if ($t.Pairs.Contains($k)) { $keys.Add($k) } }
        foreach ($k in $t.Pairs.Keys) { if (-not ($order -ccontains $k)) { $keys.Add($k) } }
        foreach ($k in $keys) {
            $v = $t.Pairs[$k]
            if ($null -eq $v) { continue }
            [void]$sb.Append($k + ' = ' + (Sec-TomlFormatValue $v) + "`n")
        }
    }
    return $sb.ToString()
}

function Sec-TomlReadFile([string]$Path, [string]$Label) {
    if (-not [IO.File]::Exists($Path)) { Sec-Fail "$Label is missing" }
    $bytes = [IO.File]::ReadAllBytes($Path)
    try { $t = $script:SecUtf8.GetString($bytes) } catch { Sec-Fail "$Label is not valid UTF-8" }
    return (Sec-TomlParse $t $Label)
}

function Sec-TomlWriteFile([string]$Path, $Doc) {
    Sec-WriteFileAtomic $Path (Sec-Utf8Bytes (Sec-TomlFormat $Doc))
}

function Sec-NewTable([string]$Name) {
    return (New-Object psobject -Property @{ Name = $Name; Pairs = (New-Object System.Collections.Specialized.OrderedDictionary([StringComparer]::Ordinal)) })
}

# ---------------------------------------------------------------- validation helpers

function Sec-IsSegment([string]$s) {
    if ($null -eq $s) { return $false }
    if ($s -cnotmatch '^[a-z0-9][a-z0-9-]*\z') { return $false }
    return -not ($script:SecReserved -ccontains $s)
}

function Sec-IsLogicalPath([string]$p) {
    if ($null -eq $p) { return $false }
    $parts = $p -csplit '/'
    if ($parts.Count -ne 3) { return $false }
    foreach ($s in $parts) { if (-not (Sec-IsSegment $s)) { return $false } }
    return $true
}

function Sec-IsStorePath([string]$p) {
    if ($p -cnotmatch $script:SecStoreRegex) { return $false }
    return ((Sec-IsSegment $Matches[1]) -and (Sec-IsSegment $Matches[2]) -and (Sec-IsSegment $Matches[3]))
}

function Sec-StorePathOf([string]$LogicalPath, [string]$Type) { return ('store/' + $LogicalPath + '.' + $Type + '.age') }

function Sec-IsDate([string]$s) {
    if ($null -eq $s -or $s -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}\z') { return $false }   # ASCII digits only (\d is Unicode)
    $d = [DateTime]::MinValue
    return [DateTime]::TryParseExact($s, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)
}
function Sec-IsAgeKey([string]$s) { return ($s -cmatch '^age1[02-9ac-hj-np-z]{58}\z') }
function Sec-IsFieldName([string]$s) { return ($s -cmatch '^[A-Z][A-Z0-9_]*\z') }

# ---------------------------------------------------------------- glob / policy / hash (FORMAT 5)

function Sec-GlobToRegex([string]$Glob) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('^')
    $i = 0
    while ($i -lt $Glob.Length) {
        $ch = $Glob[$i]
        if ($ch -eq [char]'*') {
            if ($i + 1 -lt $Glob.Length -and $Glob[$i + 1] -eq [char]'*') { [void]$sb.Append('.*'); $i += 2; continue }
            [void]$sb.Append('[^/]*'); $i++; continue
        }
        if ($ch -eq [char]'?') { [void]$sb.Append('[^/]'); $i++; continue }
        [void]$sb.Append([regex]::Escape([string]$ch)); $i++
    }
    [void]$sb.Append('\z')
    return $sb.ToString()
}

function Sec-GlobMatch([string]$Glob, [string]$Path) {
    return [regex]::IsMatch($Path, (Sec-GlobToRegex $Glob), [Text.RegularExpressions.RegexOptions]::Singleline)
}

function Sec-RecipientHash([string[]]$Keys) {
    $set = Sec-NewSet
    foreach ($k in @($Keys)) { if ($null -ne $k) { [void]$set.Add($k) } }
    $sorted = Sec-SortOrdinal @($set)
    return (Sec-Sha256Hex (Sec-Utf8Bytes ($sorted -join "`n")))
}

# ---------------------------------------------------------------- repo model

function Sec-TableString($t, [string]$key, $errors, [string]$ctx, [switch]$Required) {
    if (-not $t.Pairs.Contains($key)) {
        if ($Required) { $errors.Add("$ctx`: missing '$key'") }
        return $null
    }
    $v = $t.Pairs[$key]
    if (-not ($v -is [string])) { $errors.Add("$ctx`: '$key' must be a string"); return $null }
    return $v
}

function Sec-TableArray($t, [string]$key, $errors, [string]$ctx, [switch]$Required) {
    if (-not $t.Pairs.Contains($key)) {
        if ($Required) { $errors.Add("$ctx`: missing '$key'") }
        return $null
    }
    $v = $t.Pairs[$key]
    if (-not ($v -is [array])) { $errors.Add("$ctx`: '$key' must be a string array"); return $null }
    return , ([string[]]$v)
}

function Sec-LoadRecipients([string]$Repo) {
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $items = Sec-NewList
    $doc = $null
    try { $doc = Sec-TomlReadFile ([IO.Path]::Combine($Repo, 'recipients.toml')) 'recipients.toml' } catch { $errors.Add($_.Exception.Message) }
    if ($doc) {
        $names = Sec-NewSet; $keys = Sec-NewSet
        $idx = 0
        foreach ($t in $doc.Tables) {
            if ($t.Name -cne 'recipient') { continue }
            $idx++
            $ctx = "recipients.toml [[recipient]] #$idx"
            $e0 = $errors.Count
            $name = Sec-TableString $t 'name' $errors $ctx -Required
            $type = Sec-TableString $t 'type' $errors $ctx -Required
            $key = Sec-TableString $t 'key' $errors $ctx -Required
            $status = Sec-TableString $t 'status' $errors $ctx -Required
            $added = Sec-TableString $t 'added' $errors $ctx -Required
            $backup = Sec-TableString $t 'backup' $errors $ctx
            $note = Sec-TableString $t 'note' $errors $ctx
            if ($null -ne $name -and -not (Sec-IsSegment $name)) { $errors.Add("$ctx`: invalid name") }
            if ($null -ne $type -and -not (@('device', 'service', 'recovery') -ccontains $type)) { $errors.Add("$ctx`: invalid type") }
            if ($null -ne $key -and -not (Sec-IsAgeKey $key)) { $errors.Add("$ctx`: invalid key (must be lowercase age1... X25519)") }
            if ($null -ne $status -and -not (@('active', 'pending', 'revoked') -ccontains $status)) { $errors.Add("$ctx`: invalid status") }
            if ($null -ne $added -and -not (Sec-IsDate $added)) { $errors.Add("$ctx`: invalid added date") }
            if ($t.Pairs.Contains('backup') -and $type -cne 'recovery') { $errors.Add("$ctx`: 'backup' is only allowed on recovery") }
            if ($null -ne $name) { if (-not $names.Add($name)) { $errors.Add("$ctx`: duplicate name '$name'") } }
            if ($null -ne $key) { if (-not $keys.Add($key)) { $errors.Add("$ctx`: duplicate key (same key in two records)") } }
            if ($errors.Count -eq $e0) {
                $items.Add((New-Object psobject -Property @{ Name = $name; Type = $type; Key = $key; Status = $status; Added = $added; Backup = $backup; Note = $note; Table = $t }))
            }
        }
    }
    return (New-Object psobject -Property @{ Doc = $doc; Items = $items; Errors = $errors })
}

function Sec-LoadPolicy([string]$Repo) {
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $rules = Sec-NewList
    $doc = $null
    try { $doc = Sec-TomlReadFile ([IO.Path]::Combine($Repo, 'policy.toml')) 'policy.toml' } catch { $errors.Add($_.Exception.Message) }
    if ($doc) {
        $idx = 0
        foreach ($t in $doc.Tables) {
            if ($t.Name -cne 'rule') { continue }
            $idx++
            $ctx = "policy.toml [[rule]] #$idx"
            $e0 = $errors.Count
            $path = Sec-TableString $t 'path' $errors $ctx -Required
            $rcp = Sec-TableArray $t 'recipients' $errors $ctx -Required
            if ($errors.Count -eq $e0) {
                $rules.Add((New-Object psobject -Property @{ Path = $path; Recipients = $rcp; Regex = (Sec-GlobToRegex $path); Index = $idx }))
            }
        }
    }
    return (New-Object psobject -Property @{ Doc = $doc; Rules = $rules; Errors = $errors })
}

function Sec-EffectiveRule($Policy, [string]$StorePath) {
    $hit = $null
    foreach ($r in $Policy.Rules) {
        if ([regex]::IsMatch($StorePath, $r.Regex, [Text.RegularExpressions.RegexOptions]::Singleline)) { $hit = $r }
    }
    return $hit
}

# -> @{ Keys (sorted, unique); Ignored (names not existing / not active); HasRecovery; Hash }
function Sec-ExpandRule($Rule, $Recipients) {
    $keys = Sec-NewSet
    $ignored = New-Object 'System.Collections.Generic.List[string]'
    $hasRec = $false
    foreach ($ref in $Rule.Recipients) {
        $matched = @()
        if ($ref -ceq '@all') { $matched = @($Recipients.Items | Where-Object { $_.Status -ceq 'active' }) }
        elseif (@('@device', '@service', '@recovery') -ccontains $ref) {
            $ty = $ref.Substring(1)
            $matched = @($Recipients.Items | Where-Object { $_.Status -ceq 'active' -and $_.Type -ceq $ty })
        } else {
            $matched = @($Recipients.Items | Where-Object { $_.Status -ceq 'active' -and $_.Name -ceq $ref })
            if ($matched.Count -eq 0) { $ignored.Add($ref) }
        }
        foreach ($m in $matched) { [void]$keys.Add($m.Key); if ($m.Type -ceq 'recovery') { $hasRec = $true } }
    }
    $sorted = Sec-SortOrdinal @($keys)
    return (New-Object psobject -Property @{ Keys = $sorted; Ignored = [string[]]$ignored.ToArray(); HasRecovery = $hasRec; Hash = (Sec-RecipientHash $sorted) })
}

# Alias normalization (FORMAT 8). -> @{ Path; Anchor ($null if none); Full }
function Sec-AliasNormalize([string]$Alias) {
    $s = $Alias.Trim()
    if ($s.Length -ge 4 -and $s.StartsWith('[[', [StringComparison]::Ordinal) -and $s.EndsWith(']]', [StringComparison]::Ordinal)) {
        $s = $s.Substring(2, $s.Length - 4).Trim()
    }
    $s = Sec-Nfc ($s.Replace([char]92, [char]47))
    $anchor = $null
    $h = $s.LastIndexOf([char]'#')
    $p = $s
    if ($h -ge 0) { $p = $s.Substring(0, $h); $anchor = $s.Substring($h + 1) }
    if ($p.EndsWith('.md', [StringComparison]::Ordinal)) { $p = $p.Substring(0, $p.Length - 3) }
    $full = $p
    if ($null -ne $anchor) { $full = $p + '#' + $anchor }
    return (New-Object psobject -Property @{ Path = $p; Anchor = $anchor; Full = $full })
}

function Sec-AliasHasSource([string]$NormalizedPath) {
    return ($NormalizedPath -cmatch '^[a-z][a-z0-9-]*:')
}

# A source prefix (^[a-z][a-z0-9-]*:) and a non-empty path part (FORMAT 6 value constraints).
function Sec-AliasIsValid($Normalized) {
    return ($Normalized.Path -cmatch '^[a-z][a-z0-9-]*:.')
}

# Catalog model. Errors split in two (FORMAT 6): Fatal (toml parse, [[meta]], format) makes the catalog unusable;
# EntryErrors only make that entry unusable (it is left out of Entries, its store path goes to InvalidStorePaths).
function Sec-LoadCatalog([string]$Repo, $Recipients) {
    $fatal = New-Object 'System.Collections.Generic.List[string]'
    $entryErrors = New-Object 'System.Collections.Generic.List[string]'
    $entries = Sec-NewList
    $invalidStore = Sec-NewSet
    $doc = $null
    $format = $null
    try { $doc = Sec-TomlReadFile ([IO.Path]::Combine($Repo, 'catalog.toml')) 'catalog.toml' } catch { $fatal.Add($_.Exception.Message) }
    if ($doc) {
        if ($doc.Tables.Count -eq 0 -or $doc.Tables[0].Name -cne 'meta') {
            $fatal.Add('catalog.toml: first block must be [[meta]]')
        } else {
            $format = $doc.Tables[0].Pairs['format']
            if (-not ($format -is [string]) -or $format -cne '1') { $fatal.Add('catalog.toml: unsupported or missing format (expected "1")'); $format = $null }
        }
        if (@($doc.Tables | Where-Object { $_.Name -ceq 'meta' }).Count -gt 1) { $fatal.Add('catalog.toml: more than one [[meta]] block'); $format = $null }
    }
    if ($doc -and $null -ne $format) {
        $pathCount = Sec-NewDict
        $aliasCount = Sec-NewDict
        foreach ($t in $doc.Tables) {
            if ($t.Name -cne 'entry') { continue }
            if ($t.Pairs['path'] -is [string]) {
                $pp = $t.Pairs['path']
                if ($pathCount.ContainsKey($pp)) { $pathCount[$pp] = $pathCount[$pp] + 1 } else { $pathCount[$pp] = 1 }
            }
            if ($t.Pairs['aliases'] -is [array]) {
                foreach ($a in $t.Pairs['aliases']) {
                    $full = (Sec-AliasNormalize $a).Full
                    if ($aliasCount.ContainsKey($full)) { $aliasCount[$full] = $aliasCount[$full] + 1 } else { $aliasCount[$full] = 1 }
                }
            }
        }
        $idx = 0
        foreach ($t in $doc.Tables) {
            if ($t.Name -cne 'entry') { continue }
            $idx++
            $errors = New-Object 'System.Collections.Generic.List[string]'
            $ctx = "catalog.toml [[entry]] #$idx"
            $path = Sec-TableString $t 'path' $errors $ctx -Required
            if ($path) { $ctx = "catalog.toml entry '$path'" }
            $type = Sec-TableString $t 'type' $errors $ctx -Required
            $title = Sec-TableString $t 'title' $errors $ctx -Required
            $desc = Sec-TableString $t 'description' $errors $ctx
            $updated = Sec-TableString $t 'updated' $errors $ctx -Required
            $target = Sec-TableString $t 'target' $errors $ctx
            $acl = Sec-TableString $t 'acl' $errors $ctx
            $fields = Sec-TableArray $t 'fields' $errors $ctx
            $machines = Sec-TableArray $t 'machines' $errors $ctx
            $tags = Sec-TableArray $t 'tags' $errors $ctx
            $priority = Sec-TableString $t 'priority' $errors $ctx
            $linked = Sec-TableArray $t 'linked' $errors $ctx
            $rotate = Sec-TableString $t 'rotate' $errors $ctx
            $readers = Sec-TableArray $t 'readers' $errors $ctx
            $aliases = Sec-TableArray $t 'aliases' $errors $ctx
            foreach ($pair in @(@('path', $path), @('type', $type), @('title', $title), @('updated', $updated))) {
                if ($null -ne $pair[1] -and $pair[1].Length -eq 0) { $errors.Add($ctx + ": '" + $pair[0] + "' is empty") }
            }
            if ($path -and -not (Sec-IsLogicalPath $path)) { $errors.Add("$ctx`: invalid path") }
            if ($path -and $pathCount[$path] -gt 1) { $errors.Add("$ctx`: duplicate path") }
            if ($type -and -not (@('kv', 'file', 'doc') -ccontains $type)) { $errors.Add("$ctx`: invalid type") }
            if ($updated -and -not (Sec-IsDate $updated)) { $errors.Add("$ctx`: updated is not a real YYYY-MM-DD date") }
            if ($type -ceq 'kv') {
                if (-not $t.Pairs.Contains('fields')) { $errors.Add("$ctx`: kv entry needs 'fields'") }
                elseif ($null -ne $fields) {
                    if ($fields.Length -eq 0) { $errors.Add("$ctx`: kv 'fields' is empty") }
                    $fs = Sec-NewSet
                    foreach ($f in $fields) {
                        if (-not (Sec-IsFieldName $f)) { $errors.Add("$ctx`: invalid field name") }
                        elseif (-not $fs.Add($f)) { $errors.Add("$ctx`: duplicate field name") }
                    }
                }
            } elseif ($t.Pairs.Contains('fields')) { $errors.Add("$ctx`: 'fields' is only allowed on kv") }
            if ($type -cne 'file') {
                foreach ($k in @('target', 'acl', 'machines')) { if ($t.Pairs.Contains($k)) { $errors.Add("$ctx`: '$k' is only allowed on file") } }
            }
            if ($null -ne $acl -and -not (@('private', 'inherit') -ccontains $acl)) { $errors.Add("$ctx`: invalid acl") }
            if ($null -ne $target) {
                $tr = Sec-CheckTargetSyntax $target
                if (-not $tr.Ok) { $errors.Add("$ctx`: invalid target: " + $tr.Error) }
            }
            if ($null -ne $machines -and $Recipients) {
                foreach ($m in $machines) {
                    if (@($Recipients.Items | Where-Object { $_.Name -ceq $m -and $_.Type -ceq 'device' }).Count -eq 0) {
                        $errors.Add("$ctx`: machines entry '$m' is not a device recipient")
                    }
                }
            }
            if ($null -ne $tags) { foreach ($tg in $tags) { if ($tg.Length -eq 0) { $errors.Add("$ctx`: empty tag") } } }
            if ($null -ne $priority -and -not (@('high', 'normal', 'low') -ccontains $priority)) { $errors.Add("$ctx`: invalid priority (high / normal / low)") }
            if ($null -ne $linked) {
                foreach ($lk in $linked) {
                    if ($lk.Length -eq 0) { $errors.Add("$ctx`: empty linked entry") }
                    elseif (-not $pathCount.ContainsKey($lk)) { $errors.Add("$ctx`: linked entry '$lk' does not exist") }
                    elseif ($lk -ceq $path) { $errors.Add("$ctx`: linked entry points at itself") }
                }
            }
            if ($null -ne $rotate -and $rotate.Length -eq 0) { $errors.Add("$ctx`: 'rotate' is empty") }
            if ($null -ne $readers) { foreach ($rd in $readers) { if ($rd.Length -eq 0) { $errors.Add("$ctx`: empty readers entry") } } }
            $normAliases = New-Object 'System.Collections.Generic.List[object]'
            if ($null -ne $aliases) {
                foreach ($a in $aliases) {
                    $n = Sec-AliasNormalize $a
                    if (-not (Sec-AliasIsValid $n)) { $errors.Add("$ctx`: alias needs a known source prefix and a non-empty path"); continue }
                    if ($aliasCount[$n.Full] -gt 1) { $errors.Add("$ctx`: duplicate alias '" + $n.Full + "'") }
                    $normAliases.Add($n)
                }
            }
            if ($errors.Count -eq 0) {
                $entries.Add((New-Object psobject -Property @{
                            Path = $path; Type = $type; Title = $title; Description = $desc; Fields = $fields; Target = $target
                            Acl = $acl; Machines = $machines; Tags = $tags; Aliases = $aliases; NormAliases = $normAliases
                            Rotate = $rotate; Readers = $readers; Priority = $priority; Linked = $linked
                            Updated = $updated; Table = $t; StorePath = (Sec-StorePathOf $path $type)
                        }))
            } else {
                foreach ($x in $errors) { $entryErrors.Add($x) }
                if ($path -and $type) { [void]$invalidStore.Add((Sec-StorePathOf $path $type)) }
            }
        }
    }
    $all = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in $fatal) { $all.Add($x) }
    foreach ($x in $entryErrors) { $all.Add($x) }
    return (New-Object psobject -Property @{ Doc = $doc; Entries = $entries; Errors = $all; Fatal = $fatal; EntryErrors = $entryErrors; InvalidStorePaths = $invalidStore; Format = $format })
}

# Loads everything. -Strict throws on any error (write commands). -Strict -AllowEntryErrors throws only on
# recipients / policy errors and fatal catalog errors; invalid entries are left out and listed in .Notes (read commands).
# Library functions never write to the console.
function Sec-OpenRepo([string]$Repo, [switch]$Strict, [switch]$AllowEntryErrors) {
    if (-not [IO.Directory]::Exists($Repo)) { Sec-Fail "secrets repo not found: $Repo (set --repo or SECRET_REPO)" }
    $rc = Sec-LoadRecipients $Repo
    $po = Sec-LoadPolicy $Repo
    $ca = Sec-LoadCatalog $Repo $rc
    if ($Strict) {
        foreach ($x in @($rc, $po)) { if ($x.Errors.Count -gt 0) { Sec-Fail $x.Errors[0] } }
        if ($ca.Fatal.Count -gt 0) { Sec-Fail $ca.Fatal[0] }
        if ($ca.EntryErrors.Count -gt 0 -and -not $AllowEntryErrors) {
            Sec-Fail ("catalog.toml has invalid entries, refusing to write:`n  " + (@($ca.EntryErrors) -join "`n  ") +
                "`nfix: edit catalog.toml by hand to correct those values or delete the whole [[entry]] block, then run 'secret check'")
        }
    }
    # Notes: invalid entries that were skipped; returned as data, printing is up to the caller (the CLI does it).
    $notes = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in $ca.EntryErrors) { $notes.Add('skipping invalid entry: ' + $x) }
    return (New-Object psobject -Property @{ Dir = $Repo; Recipients = $rc; Policy = $po; Catalog = $ca; Notes = $notes })
}

function Sec-RepoFile($Ctx, [string]$Rel) { return [IO.Path]::Combine($Ctx.Dir, $Rel.Replace([char]47, [IO.Path]::DirectorySeparatorChar)) }

function Sec-FindEntry($Ctx, [string]$Path) {
    foreach ($e in $Ctx.Catalog.Entries) { if ($e.Path -ceq $Path) { return $e } }
    return $null
}

# Store files actually on disk (relative, forward slashes), excluding the lock.
function Sec-ListStoreFiles([string]$Repo) {
    $root = [IO.Path]::Combine($Repo, 'store')
    $out = New-Object 'System.Collections.Generic.List[string]'
    if (-not [IO.Directory]::Exists($root)) { return , $out }
    $base = (New-Object IO.DirectoryInfo($Repo)).FullName.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    foreach ($f in [IO.Directory]::GetFiles($root, '*', [IO.SearchOption]::AllDirectories)) {
        $rel = (New-Object IO.FileInfo($f)).FullName.Substring($base.Length).Replace([char]92, [char]47)
        if ($rel -ceq 'store/.recipients.lock') { continue }
        if ([IO.Path]::GetFileName($rel).StartsWith('.') -and $rel -cmatch '\.tmp-[0-9a-f]+\z') { continue }
        $out.Add($rel)
    }
    return , $out
}

# Keys + hash that a store path must be encrypted to right now. Throws if no rule / empty set.
function Sec-KeysFor($Ctx, [string]$StorePath) {
    $rule = Sec-EffectiveRule $Ctx.Policy $StorePath
    if (-not $rule) { Sec-Fail "no policy rule matches $StorePath" }
    $ex = Sec-ExpandRule $rule $Ctx.Recipients
    if ($ex.Keys.Count -eq 0) { Sec-Fail "policy for $StorePath expands to an empty recipient set" }
    return $ex
}

# ---------------------------------------------------------------- lock (FORMAT 10)

# -> ordinal Dictionary storePath -> @{ RHash; CHash }. Throws when malformed.
function Sec-LockParse([byte[]]$Bytes) {
    try { $t = $script:SecUtf8.GetString($Bytes) } catch { Sec-Fail 'lock: not valid UTF-8' }
    if ($t.Length -gt 0 -and [int]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
    if (-not $t.EndsWith("`n")) { Sec-Fail 'lock: must end with a newline' }
    $lines = $t.Substring(0, $t.Length - 1).Split([char]10)
    $d = Sec-NewDict
    $prev = $null
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $l = $lines[$i]
        if ($l.EndsWith("`r")) { $l = $l.Substring(0, $l.Length - 1) }
        if ($i -eq 0) {
            if ($l -cne $script:SecLockHeader) { Sec-Fail 'lock: bad header line' }
            continue
        }
        if ($l -cnotmatch '^([0-9a-f]{64})  ([0-9a-f]{64})  (store/[^\r\n]+)\z') { Sec-Fail ('lock: malformed line ' + ($i + 1)) }
        $p = $Matches[3]
        if ($d.ContainsKey($p)) { Sec-Fail ('lock: duplicate path on line ' + ($i + 1)) }
        if ($null -ne $prev -and [string]::CompareOrdinal($prev, $p) -ge 0) { Sec-Fail ('lock: lines not sorted (line ' + ($i + 1) + ')') }
        $prev = $p
        $d[$p] = New-Object psobject -Property @{ RHash = $Matches[1]; CHash = $Matches[2] }
    }
    return , $d
}

function Sec-LockFormat($Dict) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($script:SecLockHeader + "`n")
    foreach ($p in (Sec-SortOrdinal @($Dict.Keys))) {
        [void]$sb.Append($Dict[$p].RHash + '  ' + $Dict[$p].CHash + '  ' + $p + "`n")
    }
    return $sb.ToString()
}

function Sec-LockPath([string]$Repo) { return [IO.Path]::Combine([IO.Path]::Combine($Repo, 'store'), '.recipients.lock') }

function Sec-LockRead([string]$Repo) {
    $f = Sec-LockPath $Repo
    if (-not [IO.File]::Exists($f)) { return , (Sec-NewDict) }
    return , (Sec-LockParse ([IO.File]::ReadAllBytes($f)))
}

function Sec-LockWrite([string]$Repo, $Dict) {
    Sec-WriteFileAtomic (Sec-LockPath $Repo) (Sec-Utf8Bytes (Sec-LockFormat $Dict))
}

# ---------------------------------------------------------------- kv (FORMAT 7)

# -> List of @{ Key; Value }. Throws on any invalid line; messages carry line numbers only, never content.
function Sec-KvParse([byte[]]$Bytes) {
    $t = Sec-DecodeUtf8 $Bytes
    $pairs = New-Object 'System.Collections.Generic.List[object]'
    $seen = Sec-NewSet
    $lines = $t.Split([char]10)
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $l = $lines[$i]
        if ($l.EndsWith("`r")) { $l = $l.Substring(0, $l.Length - 1) }
        if ($l.Length -eq 0 -or $l.StartsWith('#')) { continue }
        $eq = $l.IndexOf([char]'=')
        if ($eq -lt 1) { Sec-Fail ('kv: line ' + ($i + 1) + ': expected KEY=VALUE') }
        $k = $l.Substring(0, $eq)
        if (-not (Sec-IsFieldName $k)) { Sec-Fail ('kv: line ' + ($i + 1) + ': invalid key (must match ^[A-Z][A-Z0-9_]*$)') }
        $v = $l.Substring($eq + 1)
        if ($v.IndexOf([char]13) -ge 0 -or $v.IndexOf([char]0) -ge 0) { Sec-Fail ('kv: line ' + ($i + 1) + ': value contains CR or NUL') }
        if (-not $seen.Add($k)) { Sec-Fail ('kv: line ' + ($i + 1) + ': duplicate key') }
        $pairs.Add((New-Object psobject -Property @{ Key = $k; Value = $v }))
    }
    return , $pairs
}

# Writer form: validates, strips BOM, one CR per line, LF endings, trailing LF. Comments/blank lines kept.
function Sec-KvCanonical([byte[]]$Bytes) {
    [void](Sec-KvParse $Bytes)
    $t = Sec-DecodeUtf8 $Bytes
    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($l in $t.Split([char]10)) {
        if ($l.EndsWith("`r")) { $l = $l.Substring(0, $l.Length - 1) }
        $lines.Add($l)
    }
    if ($lines.Count -gt 0 -and $lines[$lines.Count - 1].Length -eq 0) { $lines.RemoveAt($lines.Count - 1) }
    if ($lines.Count -eq 0) { return , (New-Object byte[] 0) }
    return , (Sec-Utf8Bytes (($lines.ToArray() -join "`n") + "`n"))
}

# "secret:<path>#<FIELD>" / "<path>#<FIELD>" / "<path>" -> @{ Path; Field }
function Sec-ParseRef([string]$Ref) {
    $r = $Ref
    if ($r.StartsWith('secret:', [StringComparison]::Ordinal)) { $r = $r.Substring(7) }
    $h = $r.LastIndexOf([char]'#')
    $field = $null
    if ($h -ge 0) { $field = $r.Substring($h + 1); $r = $r.Substring(0, $h) }
    return (New-Object psobject -Property @{ Path = $r; Field = $field })
}

# ---------------------------------------------------------------- materialize targets (FORMAT 6)

# Syntax only (no filesystem): -> @{ Ok; Error; Root ('home-ssh' | 'workspace'); Rest (segments) }
function Sec-CheckTargetSyntax([string]$Target) {
    $fail = { param($m) return (New-Object psobject -Property @{ Ok = $false; Error = $m; Root = $null; Rest = $null }) }
    if ($null -eq $Target -or $Target.Length -eq 0) { return (& $fail 'empty') }
    $root = $null; $rest = $null
    if ($Target.StartsWith('~/.ssh/', [StringComparison]::Ordinal)) { $root = 'home-ssh'; $rest = $Target.Substring(7) }
    elseif ($Target.StartsWith('{workspace}/', [StringComparison]::Ordinal)) { $root = 'workspace'; $rest = $Target.Substring(12) }
    elseif ($Target.StartsWith('~/', [StringComparison]::Ordinal)) { return (& $fail 'outside the allowed roots (~/.ssh/, {workspace}/)') }
    else { return (& $fail 'must start with ~/.ssh/ or {workspace}/') }
    if ($rest.Length -eq 0) { return (& $fail 'no file name after the root') }
    foreach ($ch in $rest.ToCharArray()) {
        $c = [int]$ch
        if ($c -lt 32 -or $c -eq 127) { return (& $fail 'control character') }
        if ($c -eq 92) { return (& $fail 'backslash') }
        if ($c -eq 123 -or $c -eq 125) { return (& $fail 'placeholder outside the start') }
        if ($c -eq 58) { return (& $fail 'drive letter or colon') }
    }
    $segs = $rest -csplit '/'
    foreach ($s in $segs) {
        if ($s.Length -eq 0) { return (& $fail 'empty segment') }
        if ($s -ceq '.' -or $s -ceq '..') { return (& $fail '. or .. segment') }
        if ($s.EndsWith('.') -or $s.EndsWith(' ')) { return (& $fail 'segment ending in dot or space') }
        $stem = ($s -split '\.')[0].ToLowerInvariant()
        if (($script:SecReserved + @('conin$', 'conout$')) -ccontains $stem) { return (& $fail 'Windows reserved name segment') }
    }
    return (New-Object psobject -Property @{ Ok = $true; Error = $null; Root = $root; Rest = $segs })
}

# Full path on this machine; also refuses anything that ends up inside the secrets repo.
function Sec-ResolveTarget([string]$Target, [string]$Repo) {
    $r = Sec-CheckTargetSyntax $Target
    if (-not $r.Ok) { return $r }
    $sep = [IO.Path]::DirectorySeparatorChar
    if ($r.Root -ceq 'home-ssh') { $base = [IO.Path]::Combine((Sec-Home), '.ssh') } else { $base = Sec-Workspace }
    if (-not $base) { return (New-Object psobject -Property @{ Ok = $false; Error = '{workspace} is not set (SECRET_WORKSPACE)'; Full = $null }) }
    $base = [IO.Path]::GetFullPath($base).TrimEnd($sep)
    $full = [IO.Path]::GetFullPath($base + $sep + ($r.Rest -join [string]$sep))
    $cmp = [StringComparison]::Ordinal
    if (Sec-IsWindows) { $cmp = [StringComparison]::OrdinalIgnoreCase }
    if (-not $full.StartsWith($base + $sep, $cmp)) {
        return (New-Object psobject -Property @{ Ok = $false; Error = 'resolves outside its root'; Full = $null })
    }
    if ($Repo) {
        $rp = [IO.Path]::GetFullPath($Repo).TrimEnd($sep)
        if ($full.StartsWith($rp + $sep, $cmp) -or $full.Equals($rp, $cmp)) {
            return (New-Object psobject -Property @{ Ok = $false; Error = 'inside the secrets repo'; Full = $null })
        }
    }
    # no junction / symlink anywhere from the root (home for ~/.ssh) down to the parent dir, nor the file itself
    $chain = New-Object 'System.Collections.Generic.List[string]'
    if ($r.Root -ceq 'home-ssh') { $cur = [IO.Path]::GetFullPath((Sec-Home)).TrimEnd($sep); $chain.Add($cur); $cur = $cur + $sep + '.ssh' }
    else { $cur = $base }
    $chain.Add($cur)
    for ($i = 0; $i -lt $r.Rest.Count; $i++) { $cur = $cur + $sep + $r.Rest[$i]; $chain.Add($cur) }
    foreach ($pth in $chain) {
        if (-not ([IO.Directory]::Exists($pth) -or [IO.File]::Exists($pth))) { continue }
        if (([IO.File]::GetAttributes($pth) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return (New-Object psobject -Property @{ Ok = $false; Error = ('path goes through a junction / symlink: ' + $pth); Full = $null })
        }
    }
    return (New-Object psobject -Property @{ Ok = $true; Error = $null; Full = $full })
}

# Cloud-synced folders: writing plaintext there copies it to somebody else's server. Returns the provider name or $null.
function Sec-CloudSyncProvider([string]$FullPath) {
    $sep = [IO.Path]::DirectorySeparatorChar
    $cmp = [StringComparison]::Ordinal
    if (Sec-IsWindows) { $cmp = [StringComparison]::OrdinalIgnoreCase }
    foreach ($v in @('OneDrive', 'OneDriveCommercial', 'OneDriveConsumer')) {
        $root = [Environment]::GetEnvironmentVariable($v)
        if ($root) {
            try { $root = [IO.Path]::GetFullPath($root) } catch { continue }   # normalise: forward slashes, trailing sep, relative bits
            $root = $root.TrimEnd($sep, [char]47)
            if ($FullPath.StartsWith($root + $sep, $cmp) -or $FullPath.Equals($root, $cmp)) { return $v }
        }
    }
    foreach ($seg in ($FullPath -split '[\\/]')) {
        $l = $seg.ToLowerInvariant()
        foreach ($name in @('onedrive', 'dropbox', 'google drive', 'googledrive', 'google_drive', 'iclouddrive', 'icloud drive', 'nextcloud', 'syncthing')) {
            if ($l -ceq $name -or $l.StartsWith($name + ' -') -or $l.StartsWith($name + '-')) { return $seg }
        }
    }
    return $null
}

# Checks an arbitrary output path (secret get --out): inside the repo, junction / symlink in the chain, Windows
# reserved name segments, cloud-synced folders. -> @{ Ok; Error; Full; Cloud (provider name or $null) }
function Sec-CheckOutPath([string]$Path, [string]$Repo, [switch]$AllowSyncDir) {
    $bad = { param($m, $full, $cloud) return (New-Object psobject -Property @{ Ok = $false; Error = $m; Full = $full; Cloud = $cloud }) }
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return (& $bad 'cannot resolve path' $null $null) }
    $sep = [IO.Path]::DirectorySeparatorChar
    $cmp = [StringComparison]::Ordinal
    if (Sec-IsWindows) { $cmp = [StringComparison]::OrdinalIgnoreCase }
    if ($Repo) {
        $rp = [IO.Path]::GetFullPath($Repo).TrimEnd($sep)
        if ($full.StartsWith($rp + $sep, $cmp) -or $full.Equals($rp, $cmp)) { return (& $bad 'inside the secrets repo' $full $null) }
    }
    $parts = $full.Split($sep)
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $seg = $parts[$i]
        if ($seg.Length -eq 0) { continue }
        $stem = ($seg -split '\.')[0].ToLowerInvariant()
        if (($script:SecReserved + @('conin$', 'conout$')) -ccontains $stem) { return (& $bad 'Windows reserved name segment' $full $null) }
    }
    $cur = $parts[0]
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $cur = $cur + $sep + $parts[$i]
        if (-not ([IO.Directory]::Exists($cur) -or [IO.File]::Exists($cur))) { continue }
        if (([IO.File]::GetAttributes($cur) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return (& $bad ('path goes through a junction / symlink: ' + $cur) $full $null)
        }
    }
    $cloud = Sec-CloudSyncProvider $full
    if ($cloud -and -not $AllowSyncDir) { return (& $bad ('inside a cloud-synced folder (' + $cloud + ')') $full $cloud) }
    return (New-Object psobject -Property @{ Ok = $true; Error = $null; Full = $full; Cloud = $cloud })
}

# Targets that deserve a loud warning before approval: executables / scripts, ssh config, authorized_keys.
function Sec-TargetIsSensitive([string]$Target) {
    if ($Target.StartsWith('~/.ssh/config', [StringComparison]::Ordinal)) { return $true }
    $leaf = @($Target -csplit '/')[-1]
    if (@('authorized_keys', 'authorized_keys2') -contains $leaf.ToLowerInvariant()) { return $true }
    $ext = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
    return (@('.ps1', '.psm1', '.cmd', '.bat', '.exe', '.dll', '.js', '.vbs') -ccontains $ext)
}

function Sec-ApprovalsFile { return [IO.Path]::Combine((Sec-StateDir), 'approved-targets.txt') }

function Sec-ApprovalsRead {
    $set = Sec-NewSet
    $f = Sec-ApprovalsFile
    if ([IO.File]::Exists($f)) {
        foreach ($l in ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($f))).Split([char]10)) {
            $x = $l.TrimEnd([char]13)
            if ($x.Length -gt 0) { [void]$set.Add($x) }
        }
    }
    return , $set
}

function Sec-ApprovalsWrite($Set) {
    $dir = Sec-StateDir
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    $lines = Sec-SortOrdinal @($Set)
    $text = ''
    if ($lines.Length -gt 0) { $text = ($lines -join "`n") + "`n" }
    Sec-WriteFileAtomic (Sec-ApprovalsFile) (Sec-Utf8Bytes $text)
}

# Entry applies to this machine? machines list, else "can decrypt it" (local key in the policy set).
function Sec-EntryAppliesHere($Ctx, $Entry, [string]$LocalKey) {
    if ($null -ne $Entry.Machines) { return (@($Entry.Machines) -ccontains (Sec-DeviceName)) }
    if (-not $LocalKey) { return $false }
    try { $ex = Sec-KeysFor $Ctx $Entry.StorePath } catch { return $false }
    return (@($ex.Keys) -ccontains $LocalKey)
}

# ---------------------------------------------------------------- log leak scan

# A line of a file entry that looks like a single-line credential: long, no whitespace, letters AND digits, and
# enough distinct characters (keeps out markdown rules like |---|---| and runs of one character).
function Test-CredentialLine([string]$Line) {
    if ($Line.Length -lt 12) { return $false }
    if ($Line -cmatch '\s') { return $false }
    if ($Line -cnotmatch '[A-Za-z]' -or $Line -cnotmatch '[0-9]') { return $false }
    $set = Sec-NewSet
    foreach ($ch in $Line.ToCharArray()) { [void]$set.Add([string]$ch) }
    return ($set.Count -ge 6)
}


# Needle = @{ Label; Value }. Returns the labels whose value appears in the file. The file is read in blocks with
# an overlap, so nothing is ever loaded whole; matching is done on byte-preserving latin1 strings so both UTF-8 and
# UTF-16LE (Windows tools) encodings of an ASCII value are caught. Values never leave this function.
function Sec-ScanFileForNeedles([string]$Path, $Needles) {
    $hits = Sec-NewSet
    if (-not [IO.File]::Exists($Path)) { return , $hits }
    $latin = [Text.Encoding]::GetEncoding(28591)
    $pats = New-Object 'System.Collections.Generic.List[object]'
    $maxLen = 1
    foreach ($n in $Needles) {
        $b = [Text.Encoding]::UTF8.GetBytes($n.Value)
        $forms = New-Object 'System.Collections.Generic.List[string]'
        $forms.Add($latin.GetString($b))
        $w = [Text.Encoding]::Unicode.GetBytes($n.Value)
        $forms.Add($latin.GetString($w))
        foreach ($f in $forms) { if ($f.Length -gt $maxLen) { $maxLen = $f.Length } }
        $pats.Add(@{ Label = $n.Label; Forms = $forms })
    }
    $block = 262144
    $buf = New-Object byte[] $block
    $carry = ''
    $fs = $null
    try { $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite) } catch { return , $hits }
    try {
        while ($true) {
            $n = $fs.Read($buf, 0, $block)
            if ($n -le 0) { break }
            $hay = $carry + $latin.GetString($buf, 0, $n)
            $left = New-Object 'System.Collections.Generic.List[object]'
            foreach ($p in $pats) {
                $hit = $false
                foreach ($f in $p.Forms) { if ($hay.IndexOf($f, [StringComparison]::Ordinal) -ge 0) { $hit = $true; break } }
                if ($hit) { [void]$hits.Add($p.Label) } else { $left.Add($p) }
            }
            $pats = $left
            if ($pats.Count -eq 0) { break }
            $keep = $maxLen - 1
            if ($keep -gt $hay.Length) { $keep = $hay.Length }
            $carry = $hay.Substring($hay.Length - $keep)
        }
    } finally { $fs.Dispose() }
    return , $hits
}

# ---------------------------------------------------------------- reuse from other PowerShell scripts

# Whole plaintext of an entry as bytes (in memory only). For scripts that dot-source this file instead of capturing
# `secret get` output (capturing a child's stdout decodes with the console code page unless the caller first sets
# [Console]::OutputEncoding to UTF-8).
function Sec-GetEntryBytes([string]$Repo, [string]$Identity, [string]$Path) {
    $ctx = Sec-OpenRepo $Repo -Strict -AllowEntryErrors
    $e = Sec-FindEntry $ctx $Path
    if (-not $e) { Sec-Fail "no such entry: $Path" }
    $f = Sec-RepoFile $ctx $e.StorePath
    if (-not [IO.File]::Exists($f)) { Sec-Fail ('ciphertext missing: ' + $e.StorePath) }
    return , (Sec-AgeDecrypt ([IO.File]::ReadAllBytes($f)) $Identity -Throw)
}

# One kv field as a .NET string (exact, UTF-8 decoded).
function Sec-GetField([string]$Repo, [string]$Identity, [string]$Path, [string]$Field) {
    $ctx = Sec-OpenRepo $Repo -Strict -AllowEntryErrors
    $e = Sec-FindEntry $ctx $Path
    if (-not $e) { Sec-Fail "no such entry: $Path" }
    if ($e.Type -cne 'kv') { Sec-Fail ("$Path is " + $e.Type + ", not kv") }
    $plain = Sec-GetEntryBytes $Repo $Identity $Path
    foreach ($kv in (Sec-KvParse $plain)) { if ($kv.Key -ceq $Field) { return $kv.Value } }
    Sec-Fail "no field '$Field' in $Path"
}

# Readers (notify scripts, service wrappers) use this: default repo / identity with the SECRET_REPO /
# SECRET_IDENTITY overrides, exactly like the CLI. Returns the value as a string; throws without the value.
function Sec-ReadField([string]$Path, [string]$Field) {
    $repo = $env:SECRET_REPO
    if (-not $repo) { $repo = Sec-DefaultRepo }
    $id = $env:SECRET_IDENTITY
    if (-not $id) { $id = Sec-DefaultIdentity }
    return (Sec-GetField $repo $id $Path $Field)
}

# ---------------------------------------------------------------- local write lock

# One writer at a time per repo, on this machine. The lock lives outside the repo (nothing of it is ever committed):
# an exclusive FileStream (FileShare.None) works on Windows and POSIX alike, and the OS drops the handle when the
# process dies, so a leftover lock file never blocks anybody. Holder info goes into a separate readable file so a
# waiter can name who has it. Never blocks readers: only the write commands call this.
function Sec-LockFileFor([string]$Repo) {
    # Normalise first, or the same repo reached through a junction / symlink would get a second, useless lock.
    # git resolves reparse points for us; fall back to .NET (pwsh 7 only) and then to the plain path.
    $full = $null
    try {
        $g = Sec-Git $Repo @('rev-parse', '--show-toplevel') $null
        if ($g.Code -eq 0 -and $g.Out.Trim()) { $full = $g.Out.Trim() }
    } catch { }
    if (-not $full) {
        try {
            $m = [IO.Directory].GetMethod('ResolveLinkTarget', [Type[]]@([string], [bool]))
            if ($m) {
                $t = $m.Invoke($null, @([IO.Path]::GetFullPath($Repo), $true))
                if ($t) { $full = $t.FullName }
            }
        } catch { }
    }
    if (-not $full) { try { $full = [IO.Path]::GetFullPath($Repo) } catch { $full = $Repo } }
    $full = $full.Replace([char]92, [char]47).TrimEnd([char]47)
    if (Sec-IsWindows) { $full = $full.ToLowerInvariant() }
    $h = (Sec-Sha256Hex (Sec-Utf8Bytes $full)).Substring(0, 16)
    $dir = [IO.Path]::Combine((Sec-StateDir), 'locks')
    if (-not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    return [IO.Path]::Combine($dir, $h + '.lock')
}

function Sec-ReadLockOwner([string]$LockFile) {
    $o = $LockFile + '.owner'
    if (-not [IO.File]::Exists($o)) { return '' }
    try { return ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($o))).Trim() } catch { return '' }
}

function Sec-AcquireLock([string]$Repo, [int]$TimeoutSec, [string]$What) {
    $lf = Sec-LockFileFor $Repo
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $last = $null
    while ($true) {
        try {
            $fs = New-Object IO.FileStream($lf, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $info = '' + [Diagnostics.Process]::GetCurrentProcess().Id + ' ' + $What + ' ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            try { [IO.File]::WriteAllBytes($lf + '.owner', (Sec-Utf8Bytes $info)) } catch { }
            return (New-Object psobject -Property @{ Stream = $fs; File = $lf })
        } catch {
            # only "file is in use" is worth retrying; anything else (no permission, bad path) is a real error
            $ex = $_.Exception
            if ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
            if (-not ($ex -is [IO.IOException]) -or ($ex -is [IO.FileNotFoundException]) -or ($ex -is [IO.DirectoryNotFoundException])) {
                Sec-Fail ('cannot take the write lock (' + $lf + '): ' + $ex.GetType().Name + ': ' + $ex.Message)
            }
            $last = $ex
        }
        if ((Get-Date) -ge $deadline) {
            $owner = Sec-ReadLockOwner $lf
            $who = 'another secret process'
            if ($owner) { $who = 'pid ' + $owner }
            Sec-Fail ("another write is in progress on this repo ($who); waited $TimeoutSec s. Retry later or raise --lock-timeout")
        }
        Start-Sleep -Milliseconds 100
    }
}

function Sec-ReleaseLock($Lock) {
    if ($null -eq $Lock) { return }
    try { $Lock.Stream.Dispose() } catch { }
    try { if ([IO.File]::Exists($Lock.File + '.owner')) { [IO.File]::Delete($Lock.File + '.owner') } } catch { }
}

# ---------------------------------------------------------------- git

function Sec-Git([string]$Repo, [string[]]$GitArgs, [byte[]]$Stdin) {
    $a = New-Object 'System.Collections.Generic.List[string]'
    $a.Add('-C'); $a.Add($Repo)
    foreach ($x in $GitArgs) { $a.Add($x) }
    $r = Sec-Exec (Sec-FindExe 'git') $a.ToArray() $Stdin
    return (New-Object psobject -Property @{ Code = $r.ExitCode; Out = [Text.Encoding]::UTF8.GetString($r.Stdout); OutBytes = $r.Stdout; Err = $r.Stderr })
}

# Compare two paths for equality (case-insensitive on Windows), tolerating separator style and trailing slash.
function Sec-SamePath([string]$A, [string]$B) {
    if (-not $A -or -not $B) { return $false }
    try { $x = [IO.Path]::GetFullPath($A); $y = [IO.Path]::GetFullPath($B) } catch { return $false }
    $x = $x.TrimEnd([char]92, [char]47); $y = $y.TrimEnd([char]92, [char]47)
    if (Sec-IsWindows) { return [string]::Equals($x, $y, [StringComparison]::OrdinalIgnoreCase) }
    return [string]::Equals($x, $y, [StringComparison]::Ordinal)
}

function Sec-IsGitRepo([string]$Repo) {
    try { $r = Sec-Git $Repo @('rev-parse', '--is-inside-work-tree') $null } catch { return $false }
    return ($r.Code -eq 0 -and $r.Out.Trim() -ceq 'true')
}

# ---------------------------------------------------------------- pre-commit (FORMAT 11)

# Checks the index of $Repo. Returns list of problems (empty = ok).
function Sec-PreCommitProblems([string]$Repo) {
    $problems = New-Object 'System.Collections.Generic.List[string]'
    $r = Sec-Git $Repo @('diff', '--cached', '--name-only', '-z', '--diff-filter=ACMRT') $null
    if ($r.Code -ne 0) { $problems.Add('git diff --cached failed'); return , $problems }
    # Keep in step with the repo's .gitignore whitelist (FORMAT 11). INCIDENT.md is generated by `secret inventory`.
    $allowed = @('FORMAT.md', 'README.md', 'INCIDENT.md', 'recipients.toml', 'policy.toml', 'catalog.toml', 'store/.recipients.lock', '.gitattributes', '.gitignore')
    foreach ($p in ($r.Out.Split([char]0) | Where-Object { $_.Length -gt 0 })) {
        if ($allowed -ccontains $p) { continue }
        $isAge = $false
        if (Sec-IsStorePath $p) { $isAge = $true }
        elseif ($p -cmatch '^recovery/[^/]+\.age\z') { $isAge = $true }
        elseif ($p.EndsWith('.age', [StringComparison]::Ordinal)) { $problems.Add("$p`: .age file at a path not allowed by FORMAT 7"); continue }
        else { $problems.Add("$p`: file is not on the whitelist"); continue }
        if ($isAge) {
            $b = Sec-Git $Repo @('cat-file', 'blob', (':' + $p)) $null
            if ($b.Code -ne 0) { $problems.Add("$p`: cannot read staged blob"); continue }
            if (-not (Sec-HasAgeHeader $b.OutBytes)) { $problems.Add("$p`: missing age-encryption.org/v1 header (not a binary age file)") }
        }
    }
    return , $problems
}
