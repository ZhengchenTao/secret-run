# Deterministic transaction failure tests. Uses only synthetic data in a new temporary directory.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. ([IO.Path]::Combine((Split-Path -Parent $here), 'SecretLib.ps1'))
$dir = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'secret-transaction-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir)
$originalMove = ${function:Sec-MoveOver}
$script:testMove = $originalMove
$script:failAt = $null
$script:failRollback = $false
function Sec-MoveOver([string]$Src, [string]$Dst) {
    if ($Dst -ceq $script:failAt -or ($script:failRollback -and $Src.Contains('.rollback-'))) {
        throw 'injected transaction failure'
    }
    & $script:testMove $Src $Dst
}
function Bytes([string]$s) { return ,([Text.Encoding]::UTF8.GetBytes($s)) }
function Expect([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
try {
    $a = [IO.Path]::Combine($dir, 'a')
    $added = [IO.Path]::Combine($dir, 'new')
    $deleted = [IO.Path]::Combine($dir, 'deleted')
    $last = [IO.Path]::Combine($dir, 'last')
    [IO.File]::WriteAllBytes($a, (Bytes 'original-a'))
    [IO.File]::WriteAllBytes($deleted, (Bytes 'original-deleted'))
    [IO.File]::WriteAllBytes($last, (Bytes 'original-last'))
    $hasUnixMode = -not (Sec-IsWindows) -and $null -ne [IO.File].GetMethod('GetUnixFileMode', [Type[]]@([string]))
    if ($hasUnixMode) {
        [IO.File]::SetUnixFileMode($a, [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)
        $originalMode = [IO.File]::GetUnixFileMode($a)
    }
    $changes = @(
        @{ Path = $a; Bytes = (Bytes 'new-a') },
        @{ Path = $added; Bytes = (Bytes 'new-file') },
        @{ Path = $deleted; Bytes = $null },
        @{ Path = $last; Bytes = (Bytes 'new-last') }
    )
    $script:failAt = $last
    $failure = ''
    try { Sec-ApplyChanges $changes } catch { $failure = $_.Exception.Message }
    Expect ($failure.Contains('all files restored')) 'failure was not reported as a successful rollback'
    Expect ([IO.File]::ReadAllText($a) -ceq 'original-a') 'overwritten file not restored'
    Expect (-not [IO.File]::Exists($added)) 'new file not removed on rollback'
    Expect ([IO.File]::ReadAllText($deleted) -ceq 'original-deleted') 'deleted file not restored'
    Expect ([IO.File]::ReadAllText($last) -ceq 'original-last') 'failed target changed'
    if ($hasUnixMode) { Expect ([IO.File]::GetUnixFileMode($a) -eq $originalMode) 'rollback changed original POSIX mode' }
    Expect ([IO.Directory]::GetFiles($dir, '*.tmp-*').Length -eq 0) 'temporary file left after successful rollback'
    $script:failAt = $null

    # Both replacement and deletion must honor a read-only destination, even on POSIX.
    [IO.File]::SetAttributes($last, [IO.FileAttributes]::ReadOnly)
    try {
        foreach ($replacement in @($true, $false)) {
            $lastBytes = $null
            if ($replacement) { $lastBytes = Bytes 'new-last' }
            $failure = ''
            try { Sec-ApplyChanges @(@{Path=$a; Bytes=(Bytes 'new-a')}, @{Path=$last; Bytes=$lastBytes}) }
            catch { $failure = $_.Exception.Message }
            Expect ($failure.Contains('all files restored')) 'read-only destination did not fail with rollback'
            Expect ([IO.File]::ReadAllText($a) -ceq 'original-a') 'read-only failure failed to restore earlier write'
            Expect ([IO.File]::ReadAllText($last) -ceq 'original-last') 'read-only destination changed'
        }
    } finally { [IO.File]::SetAttributes($last, [IO.FileAttributes]::Normal) }

    # A failure during rollback must not be reported as successful.
    $script:failAt = $last
    $script:failRollback = $true
    $failure = ''
    try { Sec-ApplyChanges @(@{Path=$a; Bytes=(Bytes 'new-a')}, @{Path=$last; Bytes=(Bytes 'new-last')}) }
    catch { $failure = $_.Exception.Message }
    Expect ($failure.Contains('ROLLBACK INCOMPLETE')) 'rollback failure was not reported'
    [Console]::Out.WriteLine('transaction tests passed')
} finally {
    ${function:Sec-MoveOver} = $originalMove
    foreach ($f in [IO.Directory]::GetFiles($dir, '*', [IO.SearchOption]::AllDirectories)) {
        [IO.File]::SetAttributes($f, [IO.FileAttributes]::Normal)
    }
    [IO.Directory]::Delete($dir, $true)
}
