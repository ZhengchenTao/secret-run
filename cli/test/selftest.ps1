# cli/test/selftest.ps1 -- self test for the `secret` CLI. ASCII-only; run under both hosts:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File cli/test/selftest.ps1
#   pwsh -NoProfile -File cli/test/selftest.ps1
# Uses only a temp repo, age-keygen test identities and random test values; never touches real secrets,
# ~/.config/secrets, %LOCALAPPDATA%\secret or ~/.ssh (SECRET_HOME / SECRET_WORKSPACE / SECRET_STATE_DIR point
# into the temp dir). The CLI is invoked as a child of the same host, so each host tests itself. Exit 0 = all pass.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
. ([IO.Path]::Combine($root, 'SecretLib.ps1'))
$cli = [IO.Path]::Combine($root, 'secret.ps1')
$hostExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

$script:pass = 0; $script:fail = 0
$script:allOutput = New-Object System.Text.StringBuilder   # everything the CLI printed, except get/show
function Assert([bool]$Cond, [string]$Name) {
    if ($Cond) { $script:pass++ } else { $script:fail++; [Console]::Out.WriteLine("FAIL  $Name") }
}
function Throws([scriptblock]$Sb) { try { [void](& $Sb); return $false } catch { return $true } }
function RunCli([string[]]$A, [byte[]]$Stdin, [switch]$ValueOutput) {
    $r = Sec-Exec $hostExe (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $cli) + $A) $Stdin
    $text = [Text.Encoding]::UTF8.GetString($r.Stdout)
    $r | Add-Member -NotePropertyName Text -NotePropertyValue $text
    if (-not $ValueOutput) { [void]$script:allOutput.Append($text).Append($r.Stderr) }
    return $r
}
function B([string]$s) { return , ([Text.Encoding]::UTF8.GetBytes($s)) }
# start the CLI without waiting (for the concurrency test)
function StartCli([string[]]$A) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $hostExe
    $psi.Arguments = Sec-JoinArgs (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $cli) + $A)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    return [Diagnostics.Process]::Start($psi)
}
function BytesEq([byte[]]$a, [byte[]]$b) { return ((Sec-Sha256Hex $a) -ceq (Sec-Sha256Hex $b)) }
function HasLine([string]$Text, [string]$Regex) { foreach ($l in $Text.Split([char]10)) { if ($l.TrimEnd([char]13) -cmatch $Regex) { return $true } }; return $false }
function Only-UserAcl([string]$Path) {
    if (-not (Sec-IsWindows)) {
        $r = Sec-Exec (Sec-FindExe 'stat') @('-c', '%a', $Path) $null
        return ([Text.Encoding]::ASCII.GetString($r.Stdout).Trim() -ceq '600')
    }
    $icacls = [IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'icacls.exe')
    $r = Sec-Exec $icacls @($Path) $null
    if ($r.ExitCode -ne 0) { return $false }
    $text = [Text.Encoding]::Default.GetString($r.Stdout)
    if ($text.StartsWith($Path)) { $text = $text.Substring($Path.Length) }
    $aces = @($text.Split([char]10) | ForEach-Object { $_.Trim() } | Where-Object { $_ -match ':\(' })
    if ($aces.Count -ne 1) { return $false }
    if ($aces[0] -match '\(I\)') { return $false }
    if ($aces[0] -notmatch '\(F\)') { return $false }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    return $aces[0].StartsWith($me + ':', [StringComparison]::OrdinalIgnoreCase)
}

[Console]::Out.WriteLine('host: ' + $hostExe + ' ' + $PSVersionTable.PSVersion.ToString())

# ================================================================ unit: TOML
$sample = [char]0xFEFF + "# header one`r`n# header two`r`n`r`n[[recipient]]`r`nname=`t""a-1""  # c`r`nnote = 'lit # not comment'`r`n" +
"esc = ""q\""b\\s\n\t\r\u00e9""`r`n" + "arr = [`r`n  ""x"", # c`r`n  'y',`r`n]`r`nempty = []`r`nflag = true`r`n`r`n[[other]]`r`nk = false`r`n"
$doc = Sec-TomlParse $sample 't'
Assert ($doc.Header.Count -eq 2) 'toml header lines'
Assert ($doc.Tables.Count -eq 2) 'toml two tables'
$pr = $doc.Tables[0].Pairs
Assert ($pr['name'] -ceq 'a-1') 'toml basic string'
Assert ($pr['note'] -ceq 'lit # not comment') 'toml literal string with #'
Assert ($pr['esc'] -ceq ('q"b\s' + "`n`t`r" + [char]0xE9)) 'toml escapes'
Assert (($pr['arr'] -is [array]) -and ($pr['arr'] -join '|') -ceq 'x|y') 'toml multiline array trailing comma'
Assert (($pr['empty'] -is [array]) -and @($pr['empty']).Count -eq 0) 'toml empty array'
Assert ($pr['flag'] -is [bool] -and $pr['flag']) 'toml bool'
Assert ($doc.Tables[1].Pairs['k'] -is [bool] -and -not $doc.Tables[1].Pairs['k']) 'toml false'
$re = Sec-TomlParse (Sec-TomlFormat $doc) 't2'
Assert ((Sec-TomlFormat $re) -ceq (Sec-TomlFormat $doc)) 'toml canonical round trip'
Assert ((Sec-TomlFormat $doc).Contains('"lit # not comment"')) 'toml writer uses basic strings'
$bad = @(
    @('integer', "[[a]]`nk = 1`n"), @('inline table', "[[a]]`nk = {x = ""y""}`n"), @('dotted key', "[[a]]`nk.b = ""x""`n"),
    @('invalid escape', "[[a]]`nk = ""\q""`n"), @('raw tab in string', "[[a]]`nk = ""a`tb""`n"), @('control char', ("[[a]]`nk = ""a" + [char]1 + """`n")),
    @('standard table', "[a]`nk = ""x""`n"), @('key outside table', "k = ""x""`n"), @('duplicate key', "[[a]]`nk = ""x""`nk = ""y""`n"),
    @('surrogate escape', "[[a]]`nk = ""\uD800""`n"), @('int in array', "[[a]]`nk = [""a"", 1]`n"), @('multiline string', "[[a]]`nk = """"""x""""""`n"),
    @('quoted key', "[[a]]`n""k"" = ""x""`n"), @('float', "[[a]]`nk = 1.5`n"), @('two values', "[[a]]`nk = ""x"" ""y""`n"),
    @('literal with control', ("[[a]]`nk = 'a" + [char]0x7F + "'`n"))
)
foreach ($b in $bad) { Assert (Throws { Sec-TomlParse $b[1] 'bad' }) ('toml rejects ' + $b[0]) }
foreach ($u in @('0001', '0009', '000A', '001F', '007F', '0000')) {
    $u = [string][char]92 + 'u' + $u
    Assert (Throws { Sec-TomlParse ("[[a]]`nk = ""x" + $u + """`n") 'bad' }) "toml rejects escape $u (control char)"
}
Assert ((Sec-TomlParse "[[a]]`nk = ""\t\n\r""`n" 't').Tables[0].Pairs['k'] -ceq "`t`n`r") 'toml accepts \t \n \r escapes'
Assert (Throws { Sec-TomlQuote ('a' + [char]1) }) 'toml writer refuses control char'
Assert (Throws { Sec-TomlQuote ('a' + [char]0x7F) }) 'toml writer refuses DEL'
Assert ((Sec-TomlQuote ("a`tb")) -ceq '"a\tb"') 'toml writer escapes tab'
Assert (-not (Sec-IsDate '2026-02-30')) 'date: 2026-02-30 invalid'
Assert (Sec-IsDate '2024-02-29') 'date: leap day valid'
Assert (-not (Sec-IsDate ('2026-0' + [char]0xFF11 + '-01'))) 'date: non-ASCII digit invalid'
Assert (-not (Sec-IsDate '2026-13-01')) 'date: month 13 invalid'

# ================================================================ unit: kv
$kv = Sec-KvParse (B ("# comment`r`nAPP_ID=abc`r`nEMPTY=`nSPACED= a = b `n`nX_1=q""uote'd`n"))
Assert ($kv.Count -eq 4) 'kv count'
Assert ($kv[0].Key -ceq 'APP_ID' -and $kv[0].Value -ceq 'abc') 'kv CRLF stripped once'
Assert ($kv[1].Value -ceq '') 'kv empty value'
Assert ($kv[2].Value -ceq ' a = b ') 'kv value raw (spaces, =)'
Assert ($kv[3].Value -ceq 'q"uote''d') 'kv quotes untouched'
foreach ($b in @(@('lowercase key', "app=1`n"), @('leading space', " A=1`n"), @('export', "export A=1`n"), @('no equals', "A`n"),
        @('duplicate', "A=1`nA=2`n"), @('double CR', "A=1`r`r`n"), @('empty key', "=1`n"), @('NUL', ("A=1" + [char]0 + "`n")))) {
    Assert (Throws { Sec-KvParse (B $b[1]) }) ('kv rejects ' + $b[0])
}
Assert (Throws { Sec-KvParse ([byte[]](0x41, 0x3D, 0xFF, 0x0A)) }) 'kv rejects invalid UTF-8'
Assert (BytesEq (Sec-KvCanonical (B "A=1`r`nB=2")) (B "A=1`nB=2`n")) 'kv canonical LF + trailing newline'

# ================================================================ unit: glob, hash, lock, alias, target
Assert (Sec-GlobMatch 'store/**' 'store/personal/ssh/a.file.age') 'glob store/**'
Assert (-not (Sec-GlobMatch 'store/personal/*' 'store/personal/ssh/a.file.age')) 'glob * does not cross /'
Assert (Sec-GlobMatch 'store/**/a.file.age' 'store/personal/ssh/a.file.age') 'glob **/ in middle'
Assert (-not (Sec-GlobMatch 'store/**/x.kv.age' 'store/x.kv.age')) 'glob **/ not zero segments'
Assert (-not (Sec-GlobMatch 'store/a.b' 'store/aXb')) 'glob dot is literal'
$k1 = 'age1' + ('q' * 58); $k2 = 'age1' + ('p' * 58)
Assert ((Sec-RecipientHash @($k1, $k2, $k1)) -ceq (Sec-Sha256Hex (B ($k2 + "`n" + $k1)))) 'recipient hash: dedupe, ordinal sort, \n join'
$ld = Sec-NewDict
$ld['store/work/b/c.kv.age'] = New-Object psobject -Property @{ RHash = ('a' * 64); CHash = ('b' * 64) }
$ld['store/personal/b/c.kv.age'] = New-Object psobject -Property @{ RHash = ('c' * 64); CHash = ('d' * 64) }
$lt = Sec-LockFormat $ld
Assert ($lt -ceq ("# secret recipients lock v1`n" + ('c' * 64) + '  ' + ('d' * 64) + "  store/personal/b/c.kv.age`n" + ('a' * 64) + '  ' + ('b' * 64) + "  store/work/b/c.kv.age`n")) 'lock format sorted'
Assert ((Sec-LockParse (B $lt)).Count -eq 2) 'lock parse'
Assert (Throws { Sec-LockParse (B ("# secret recipients lock v1`n" + ('a' * 64) + '  ' + ('b' * 64) + "  store/z`n" + ('a' * 64) + '  ' + ('b' * 64) + "  store/a`n")) }) 'lock rejects unsorted'
Assert (Throws { Sec-LockParse (B "# secret recipients lock v1`n`n") }) 'lock rejects blank line'
$zh = [string]([char]0x98DE) + [char]0x4E66
$al = Sec-AliasNormalize (' [[notes:secrets\' + $zh + '\app.md#App Secret]] ')
Assert ($al.Full -ceq ('notes:secrets/' + $zh + '/app#App Secret')) 'alias normalization'
Assert ((Sec-AliasNormalize '[[ wiki:old/a.md ]]').Full -ceq 'wiki:old/a') 'alias trims inside [[ ]]'
Assert (-not (Sec-AliasIsValid (Sec-AliasNormalize 'wiki:'))) 'alias with empty path invalid'
Assert (-not (Sec-AliasIsValid (Sec-AliasNormalize 'wiki:.md#x'))) 'alias with empty path after .md strip invalid'
foreach ($t in @('~/.ssh/nul.txt', '{workspace}/con', '{workspace}/a/COM1.log', '~/.ssh/aux')) { Assert (-not (Sec-CheckTargetSyntax $t).Ok) "target rejects reserved $t" }
Assert (Sec-TargetIsSensitive '{workspace}/x/run.ps1') 'sensitive: .ps1'
Assert (Sec-TargetIsSensitive '~/.ssh/config') 'sensitive: ssh config'
Assert (Sec-TargetIsSensitive '~/.ssh/authorized_keys') 'sensitive: authorized_keys'
Assert (-not (Sec-TargetIsSensitive '~/.ssh/id_x')) 'not sensitive: key file'
Assert ((Sec-CheckTargetSyntax '~/.ssh/id_x').Ok) 'target ~/.ssh ok'
Assert ((Sec-CheckTargetSyntax '{workspace}/proj/.env').Ok) 'target workspace ok'
foreach ($t in @('~/Documents/x', '~/.ssh/../x', '{workspace}/a/../b', 'C:/x', '~/.ssh/a\b', '~/.ssh/', '/etc/passwd', '~/.ssh/{workspace}/x', '{workspace}/a//b', '~/.ssh/./x', '{workspace}/a/C:x')) {
    Assert (-not (Sec-CheckTargetSyntax $t).Ok) "target rejects $t"
}
Assert (Sec-IsStorePath 'store/personal/ssh/a-b.file.age') 'store path ok'
Assert (-not (Sec-IsStorePath 'store/personal/con/a.file.age')) 'store path reserved name'
Assert (-not (Sec-IsLogicalPath 'personal/a')) 'logical path needs 3 segments'
Assert ((Sec-IsLogicalPath 'team-a/app/key') -and (Sec-IsStorePath 'store/team-a/app/key.kv.age')) 'any domain segment is accepted'
Assert (-not (Sec-IsLogicalPath 'Team/app/key') -and -not (Sec-IsStorePath 'store/nul/app/key.kv.age')) 'domain follows the segment rules'
Assert ((Sec-AliasIsValid (Sec-AliasNormalize 'my-notes:a/b.md#x')) -and -not (Sec-AliasIsValid (Sec-AliasNormalize 'Notes:a')) -and -not (Sec-AliasIsValid (Sec-AliasNormalize 'a/b.md'))) 'alias source prefix is generic but required'
$wsSaved = $env:SECRET_WORKSPACE; $env:SECRET_WORKSPACE = $null
Assert (-not (Sec-ResolveTarget '{workspace}/x/y.env' 'C:\nonexistent-repo').Ok) '{workspace} target refused while SECRET_WORKSPACE is unset'
Assert ((Sec-DefaultRepo) -ceq [IO.Path]::Combine((Sec-Home), 'secrets')) 'default repo is ~/secrets without SECRET_WORKSPACE'
$env:SECRET_WORKSPACE = $wsSaved
Assert ((Sec-QuoteArg 'a"b\') -ceq '"a\"b\\"') 'msvcrt quoting'
# FORMAT 6 fixes the key order; unknown keys keep their order after `updated`
$et = Sec-NewTable 'entry'
foreach ($k in @('updated', 'zz-unknown', 'aliases', 'linked', 'priority', 'readers', 'rotate', 'tags', 'machines', 'acl', 'target', 'fields', 'description', 'title', 'type', 'path', 'aa-unknown')) {
    if (@('fields', 'machines', 'tags', 'readers', 'linked', 'aliases') -ccontains $k) { $et.Pairs[$k] = [string[]]@('x') } else { $et.Pairs[$k] = 'x' }
}
$doc2 = New-Object psobject -Property @{ Header = [string[]]@(); Tables = (New-Object 'System.Collections.Generic.List[object]') }
$doc2.Tables.Add($et)
$written = @((Sec-TomlFormat $doc2).Split([char]10) | Where-Object { $_.Contains(' = ') } | ForEach-Object { $_.Split(' ')[0] })
Assert (($written -join ',') -ceq 'path,type,title,description,fields,target,acl,machines,tags,rotate,readers,priority,linked,aliases,updated,zz-unknown,aa-unknown') 'toml writer uses the FORMAT 6 key order, unknown keys last'

# ================================================================ integration setup
$T = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'secret-selftest-' + (Sec-RandHex 6))
[void][IO.Directory]::CreateDirectory($T)
$saved = @{}
foreach ($v in @('SECRET_REPO', 'SECRET_IDENTITY', 'SECRET_HOME', 'SECRET_WORKSPACE', 'SECRET_STATE_DIR', 'SECRET_DESKTOP', 'SECRET_DEVICE_NAME', 'SECRET_SCAN_LOGS', 'SECRET_INVENTORY_TEMPLATE', 'OneDrive', 'EDITOR')) { $saved[$v] = [Environment]::GetEnvironmentVariable($v) }
try {
    $repo = [IO.Path]::Combine($T, 'repo')
    [void][IO.Directory]::CreateDirectory($repo)
    $env:SECRET_REPO = $repo
    $env:SECRET_IDENTITY = [IO.Path]::Combine([IO.Path]::Combine($T, 'idA'), 'identity.txt')
    $env:SECRET_HOME = [IO.Path]::Combine($T, 'home')
    $env:SECRET_WORKSPACE = [IO.Path]::Combine($T, 'ws')
    $env:SECRET_STATE_DIR = [IO.Path]::Combine($T, 'state')
    $env:SECRET_DESKTOP = [IO.Path]::Combine($T, 'desktop')
    $env:SECRET_DEVICE_NAME = 'dev-a'
    $env:OneDrive = $null
    foreach ($d in @($env:SECRET_HOME, $env:SECRET_WORKSPACE, $env:SECRET_DESKTOP)) { [void][IO.Directory]::CreateDirectory($d) }
    [IO.File]::WriteAllBytes([IO.Path]::Combine($repo, 'recipients.toml'), (B "# recipients (public keys)`n"))
    [IO.File]::WriteAllBytes([IO.Path]::Combine($repo, 'policy.toml'), (B "[[rule]]`npath = ""store/**""`nrecipients = [""@all""]`n"))
    [IO.File]::WriteAllBytes([IO.Path]::Combine($repo, 'catalog.toml'), (B "[[meta]]`nformat = ""1""`n"))
    foreach ($g in @(@('init', '-q'), @('config', 'user.email', 'selftest@example.invalid'), @('config', 'user.name', 'selftest'), @('config', 'core.autocrlf', 'false'))) {
        Assert ((Sec-Git $repo $g $null).Code -eq 0) ('git ' + ($g -join ' '))
    }
    $v1 = 'tv1-' + (Sec-RandHex 16)
    $v2 = 'tv2-' + (Sec-RandHex 16)
    $binPlain = New-Object byte[] 512
    for ($i = 0; $i -lt 256; $i++) { $binPlain[$i] = [byte]$i }
    $rnd = New-Object byte[] 256; ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($rnd); [Array]::Copy($rnd, 0, $binPlain, 256, 256)
    $docPlain = B ("# " + [char]0x4E2D + [char]0x6587 + " doc`r`nline " + $v2 + "`n")

    # ---- init
    $r = RunCli @('init', '--name', 'dev-a')
    Assert ($r.ExitCode -eq 0) 'init exit 0'
    $pubA = $r.Text.Trim()
    Assert (Sec-IsAgeKey $pubA) 'init prints public key'
    Assert (Only-UserAcl $env:SECRET_IDENTITY) 'init identity ACL only current user'
    $r = RunCli @('init', '--name', 'dev-a')
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('already registered')) 'init idempotent'
    $r = RunCli @('init', '--name', 'other')
    Assert ($r.ExitCode -eq 1) 'init refuses same key under another name'

    # ---- hooks (R5)
    $r = RunCli @('check')
    Assert (HasLine $r.Text '^ERROR hooks core\.hooksPath is not set') 'check: hooks not installed is ERROR'
    Assert ((RunCli @('hooks', 'install')).ExitCode -eq 0) 'hooks install'
    Assert (HasLine (RunCli @('check')).Text '^OK hooks ') 'check: hooks OK after install'
    [void](Sec-Git $repo @('config', 'core.hooksPath', 'somewhere/else') $null)
    Assert (HasLine (RunCli @('check')).Text "^ERROR hooks core\.hooksPath is 'somewhere/else'") 'check: wrong hooksPath is ERROR'
    [void](RunCli @('hooks', 'install'))

    # ---- recovery new
    $recFile = [IO.Path]::Combine($T, 'rec-identity.txt')
    $r = RunCli @('recovery', 'new', '--out', $recFile)
    Assert ($r.ExitCode -eq 0 -and (Sec-IsAgeKey $r.Text.Trim())) 'recovery new prints public key'
    Assert (-not $r.Text.Contains('AGE-SECRET-KEY') -and -not $r.Stderr.Contains('AGE-SECRET-KEY')) 'recovery new never prints private key'
    Assert (Only-UserAcl $recFile) 'recovery identity ACL'
    Assert ((RunCli @('recovery', 'new', '--out', ($recFile + '2'))).ExitCode -eq 1) 'recovery new refuses second without --replace'
    $rc = Sec-LoadRecipients $repo
    Assert (@($rc.Items | Where-Object { $_.Type -ceq 'recovery' -and $_.Status -ceq 'active' -and $_.Backup -ceq '' }).Count -eq 1) 'recovery registered active with empty backup'

    # ---- add / get round trips
    $r = RunCli @('add', 'personal/test/kv1', '--type', 'kv', '--title', 'Test kv', '--stdin', '--alias', ('notes:secrets/' + $zh + '/app.md#App'), '--tag', 't1') (B ("# c`r`nAPI_KEY=$v1`r`nEMPTY=`r`nSP= a b `r`n"))
    Assert ($r.ExitCode -eq 0) 'add kv via stdin'
    $g = RunCli @('get', 'personal/test/kv1#API_KEY') -ValueOutput
    Assert ($g.ExitCode -eq 0 -and (BytesEq $g.Stdout (B $v1))) 'get kv field exact bytes, no newline'
    $g = RunCli @('get', 'secret:personal/test/kv1#SP') -ValueOutput
    Assert (BytesEq $g.Stdout (B ' a b ')) 'get keeps spaces'
    $g = RunCli @('get', 'personal/test/kv1#EMPTY') -ValueOutput
    Assert ($g.ExitCode -eq 0 -and $g.Stdout.Length -eq 0) 'get empty value'
    $r = RunCli @('get', 'personal/test/kv1#MISSING')
    Assert ($r.ExitCode -eq 1) 'get missing field fails'
    $r = RunCli @('add', 'personal/test/badkv', '--type', 'kv', '--title', 'bad', '--stdin') (B "lower=$v1`n")
    Assert ($r.ExitCode -eq 1) 'add rejects invalid kv'
    $cat = Sec-LoadCatalog $repo $null
    Assert ((@($cat.Entries[0].Fields) -join ',') -ceq 'API_KEY,EMPTY,SP') 'catalog fields in content order'

    $binFile = [IO.Path]::Combine($T, 'bin.dat'); [IO.File]::WriteAllBytes($binFile, $binPlain)
    $r = RunCli @('add', 'personal/test/key', '--type', 'file', '--title', 'Test key', '--from-file', $binFile, '--target', '~/.ssh/test_key')
    Assert ($r.ExitCode -eq 0) 'add binary file'
    $outBin = [IO.Path]::Combine($T, 'out.bin')
    $r = RunCli @('get', 'personal/test/key', '--out', $outBin)
    Assert ($r.ExitCode -eq 0 -and (BytesEq ([IO.File]::ReadAllBytes($outBin)) $binPlain)) 'get --out binary round trip'
    Assert (Only-UserAcl $outBin) 'get --out ACL'
    Assert ((RunCli @('get', 'personal/test/key', '--out', $outBin)).ExitCode -eq 1) 'get --out refuses overwrite'
    # R4: get --out reuses the landing checks
    $r = RunCli @('get', 'personal/test/key', '--out', [IO.Path]::Combine($repo, 'leak.bin'))
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('inside the secrets repo') -and -not [IO.File]::Exists([IO.Path]::Combine($repo, 'leak.bin'))) 'get --out refuses writing into the repo'
    Assert ((RunCli @('get', 'personal/test/key', '--out', [IO.Path]::Combine($T, 'nul.txt'))).ExitCode -eq 1) 'get --out refuses reserved name'
    if (Sec-IsWindows) {
        $elsewhere2 = [IO.Path]::Combine($T, 'elsewhere2'); [void][IO.Directory]::CreateDirectory($elsewhere2)
        $linkOut = [IO.Path]::Combine($T, 'linkout')
        [void](Sec-Exec ([IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'cmd.exe')) @('/d', '/c', 'mklink', '/J', $linkOut, $elsewhere2) $null)
        $r = RunCli @('get', 'personal/test/key', '--out', [IO.Path]::Combine($linkOut, 'x.bin'))
        Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('junction') -and -not [IO.File]::Exists([IO.Path]::Combine($elsewhere2, 'x.bin'))) 'get --out refuses junction in the path'
        [IO.Directory]::Delete($linkOut, $false)
    }
    $cloudDir = [IO.Path]::Combine($T, 'OneDrive - Contoso'); [void][IO.Directory]::CreateDirectory($cloudDir)
    $cloudOut = [IO.Path]::Combine($cloudDir, 'x.bin')
    $r = RunCli @('get', 'personal/test/key', '--out', $cloudOut)
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('cloud-synced') -and $r.Stderr.Contains('--allow-sync-dir') -and -not [IO.File]::Exists($cloudOut)) 'get --out refuses cloud-synced folder'
    $r = RunCli @('get', 'personal/test/key', '--out', $cloudOut, '--allow-sync-dir')
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('WARNING') -and (BytesEq ([IO.File]::ReadAllBytes($cloudOut)) $binPlain)) 'get --out --allow-sync-dir writes and warns'
    [IO.File]::Delete($cloudOut)
    $env:OneDrive = [IO.Path]::Combine($T, 'cloudenv')
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($env:OneDrive, 'sub'))
    $r = RunCli @('get', 'personal/test/key', '--out', [IO.Path]::Combine([IO.Path]::Combine($env:OneDrive, 'sub'), 'x.bin'))
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('OneDrive')) 'get --out honours $env:OneDrive (backslashes)'
    $env:OneDrive = ([IO.Path]::Combine($T, 'cloudenv')).Replace('\', '/') + '/'
    $envOut = [IO.Path]::Combine([IO.Path]::Combine($T, 'cloudenv'), 'sub/y.bin')
    $r = RunCli @('get', 'personal/test/key', '--out', $envOut)
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('cloud-synced') -and -not [IO.File]::Exists($envOut)) 'get --out honours $env:OneDrive written with forward slashes'
    $env:OneDrive = $null
    $s = RunCli @('show', 'personal/test/key') -ValueOutput
    Assert ($s.Text.Contains('binary file, 512 bytes')) 'show binary summary'

    $docFile = [IO.Path]::Combine($T, 'doc.md'); [IO.File]::WriteAllBytes($docFile, $docPlain)
    $decomposedTitle = 'Cafe' + [char]0x0301 + ' ' + $zh
    $r = RunCli @('add', 'work/test/doc1', '--type', 'doc', '--title', $decomposedTitle, '--from-file', $docFile)
    Assert ($r.ExitCode -eq 0) 'add doc (Chinese)'
    $outDoc = [IO.Path]::Combine($T, 'out.md')
    [void](RunCli @('get', 'work/test/doc1', '--out', $outDoc))
    Assert (BytesEq ([IO.File]::ReadAllBytes($outDoc)) $docPlain) 'doc round trip bytes'
    $s = RunCli @('show', 'work/test/doc1') -ValueOutput
    Assert ($s.Text.Contains([string][char]0x4E2D + [char]0x6587)) 'show doc text'
    $catText = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes([IO.Path]::Combine($repo, 'catalog.toml')))
    Assert ($catText.Contains('Caf' + [char]0xE9 + ' ' + $zh)) 'catalog title stored as NFC'
    Assert (-not $catText.Contains($v1) -and -not $catText.Contains($v2)) 'catalog contains no values'

    Assert ((RunCli @('add', 'personal/test/kv1', '--type', 'kv', '--title', 'dup', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add refuses existing without --replace'
    Assert ((RunCli @('add', 'personal/test/e1', '--type', 'kv', '--title', '', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add rejects empty title'
    Assert ((RunCli @('add', 'personal/test/e2', '--type', 'kv', '--title', 't', '--stdin') (B "# only a comment`n")).ExitCode -eq 1) 'add rejects kv without fields'
    Assert ((RunCli @('add', 'personal/test/e3', '--type', 'kv', '--title', 't', '--alias', 'wiki:', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add rejects alias with empty path'
    Assert ((RunCli @('add', 'personal/test/e4', '--type', 'kv', '--title', 't', '--tag', '', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add rejects empty tag'
    Assert ((RunCli @('add', 'personal/test/e6', '--type', 'kv', '--title', 't', '--priority', 'urgent', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add rejects invalid --priority'
    Assert ((RunCli @('add', 'personal/test/e7', '--type', 'kv', '--title', 't', '--linked', 'personal/test/nope', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add rejects --linked to a missing entry'
    Assert ((RunCli @('add', 'personal/test/e8', '--type', 'kv', '--title', 't', '--linked', 'personal/test/e8', '--stdin') (B "A=1`n")).ExitCode -eq 1) 'add rejects --linked to itself'
    # reuse from PowerShell: Sec-GetField / Sec-GetEntryBytes with a non-ASCII value
    $zhVal = 'v-' + [char]0x5BC6 + [char]0x94A5 + '-' + (Sec-RandHex 8)
    Assert ((RunCli @('add', 'personal/test/zh', '--type', 'kv', '--title', 'zh', '--stdin') (B "ZH=$zhVal`n")).ExitCode -eq 0) 'add kv with non-ASCII value'
    Assert ((Sec-GetField $repo $env:SECRET_IDENTITY 'personal/test/zh' 'ZH') -ceq $zhVal) 'Sec-GetField returns exact non-ASCII string'
    Assert (BytesEq (Sec-GetEntryBytes $repo $env:SECRET_IDENTITY 'personal/test/zh') (B "ZH=$zhVal`n")) 'Sec-GetEntryBytes'
    $g = RunCli @('get', 'personal/test/zh#ZH') -ValueOutput
    Assert (BytesEq $g.Stdout (B $zhVal)) 'get non-ASCII value: raw UTF-8 bytes on stdout'
    foreach ($bt in @('~/.ssh/../evil', '~/Documents/x', '{workspace}/a/../b', 'C:/evil', '~/.ssh/nul.txt', '{workspace}/con')) {
        Assert ((RunCli @('add', 'personal/test/evil', '--type', 'file', '--title', 'e', '--from-file', $binFile, '--target', $bt)).ExitCode -eq 1) "add rejects target $bt"
    }

    # ---- list / info / resolve
    $r = RunCli @('list', 'personal/')
    Assert ($r.ExitCode -eq 0 -and (HasLine $r.Text '^personal/test/kv1  kv  Test kv$') -and -not $r.Text.Contains('work/')) 'list with prefix'
    $r = RunCli @('info', 'personal/test/key')
    Assert ((HasLine $r.Text '^target: ~/\.ssh/test_key$') -and (HasLine $r.Text '^type: file$')) 'info'
    $r = RunCli @('resolve', ('secrets\' + $zh + '\app.md#App'))
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('source prefix')) 'resolve refuses a pointer without source prefix'
    $r = RunCli @('resolve', ('notes:secrets\' + $zh + '\app.md#App'))
    Assert ($r.ExitCode -eq 0 -and $r.Text.Trim() -ceq 'secret:personal/test/kv1') 'resolve exact with anchor'
    $r = RunCli @('resolve', ('[[notes:secrets/' + $zh + '/app]]'))
    Assert ($r.ExitCode -eq 0 -and $r.Text.Trim() -ceq 'secret:personal/test/kv1') 'resolve falls back to path without anchor'
    Assert ((RunCli @('resolve', 'wiki:old/nothing.md')).ExitCode -eq 1) 'resolve no match exit 1'

    # ---- check clean
    $r = RunCli @('check')
    Assert ($r.ExitCode -ne 1 -and -not (HasLine $r.Text '^ERROR ')) 'check: no ERROR after adds'
    Assert (HasLine $r.Text '^WARN recovery-backup recovery') 'check: recovery backup WARN'
    Assert (HasLine $r.Text '^WARN target-unapproved personal/test/key$') 'check: unapproved target WARN'

    # ---- FORMAT 6 value constraints: per-entry ERROR, other entries stay usable
    $catPath = [IO.Path]::Combine($repo, 'catalog.toml')
    $catGood = [IO.File]::ReadAllBytes($catPath)
    $badEntries = "`n[[entry]]`npath = ""personal/bad/p1""`ntype = ""doc""`ntitle = ""x""`npriority = ""urgent""`nupdated = ""2026-09-17""`n" +
    "`n[[entry]]`npath = ""personal/bad/l1""`ntype = ""doc""`ntitle = ""x""`nlinked = [""personal/test/nope""]`nupdated = ""2026-09-17""`n" +
    "`n[[entry]]`npath = ""personal/bad/t1""`ntype = ""doc""`ntitle = """"`nupdated = ""2026-09-17""`n" +
    "`n[[entry]]`npath = ""personal/bad/f1""`ntype = ""kv""`ntitle = ""x""`nfields = []`nupdated = ""2026-09-17""`n" +
    "`n[[entry]]`npath = ""personal/bad/d1""`ntype = ""doc""`ntitle = ""x""`nupdated = ""2026-02-30""`n" +
    "`n[[entry]]`npath = ""personal/bad/a1""`ntype = ""doc""`ntitle = ""x""`naliases = [""wiki:""]`nupdated = ""2026-09-17""`n" +
    "`n[[entry]]`npath = ""personal/bad/g1""`ntype = ""doc""`ntitle = ""x""`ntags = [""""]`nupdated = ""2026-09-17""`n"
    [IO.File]::WriteAllBytes($catPath, (B ([Text.Encoding]::UTF8.GetString($catGood) + $badEntries)))
    $cc = Sec-LoadCatalog $repo $null
    Assert ($cc.Fatal.Count -eq 0 -and $cc.EntryErrors.Count -eq 7 -and @($cc.Entries | Where-Object { $_.Path.StartsWith('personal/bad/') }).Count -eq 0) 'catalog: seven invalid entries are entry errors, not fatal'
    $r = RunCli @('check')
    $okAll = ($r.ExitCode -eq 1)
    foreach ($bp in @('t1', 'f1', 'd1', 'a1', 'g1', 'p1', 'l1')) { if (-not (HasLine $r.Text ("^ERROR catalog-entry catalog\.toml entry 'personal/bad/" + $bp + "'"))) { $okAll = $false } }
    Assert $okAll 'check: empty title / fields / bad date / bad alias / empty tag / bad priority / dangling linked are ERROR catalog-entry'
    $g = RunCli @('get', 'personal/test/kv1#API_KEY') -ValueOutput
    Assert ($g.ExitCode -eq 0 -and (BytesEq $g.Stdout (B $v1))) 'get still works with invalid entries elsewhere'
    $r = RunCli @('add', 'personal/test/e5', '--type', 'kv', '--title', 't', '--stdin') (B "A=1`n")
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains("personal/bad/f1") -and $r.Stderr.Contains("personal/bad/d1") -and $r.Stderr.Contains('[[entry]] block')) 'add refuses listing every invalid entry and how to fix'
    $ctxN = Sec-OpenRepo $repo -Strict -AllowEntryErrors
    Assert ($ctxN.Notes.Count -eq 7) 'library returns skipped entries as Notes'
    $libErr = New-Object System.IO.StringWriter; $oldErr = [Console]::Error; [Console]::SetError($libErr)
    try { $zz = Sec-GetField $repo $env:SECRET_IDENTITY 'personal/test/zh' 'ZH' } finally { [Console]::SetError($oldErr) }
    Assert ($libErr.ToString().Length -eq 0 -and $zz -ceq $zhVal) 'Sec-GetField writes nothing to stderr'
    $g = RunCli @('get', 'personal/test/zh#ZH') -ValueOutput
    Assert ($g.Stderr.Contains('note: skipping invalid entry')) 'CLI prints the skip notes'
    # ciphertext whose entry is invalid -> orphan-invalid-entry
    $zhCipher = [IO.File]::ReadAllBytes([IO.Path]::Combine($repo, 'store/personal/test/zh.kv.age'))
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($repo, 'store/personal/bad'))
    [IO.File]::WriteAllBytes([IO.Path]::Combine($repo, 'store/personal/bad/f1.kv.age'), $zhCipher)
    $r = RunCli @('check')
    Assert ((HasLine $r.Text '^ERROR orphan-invalid-entry store/personal/bad/f1\.kv\.age$') -and -not (HasLine $r.Text '^ERROR store-orphan store/personal/bad/f1')) 'check: orphan-invalid-entry for ciphertext of invalid entry'
    [IO.Directory]::Delete([IO.Path]::Combine($repo, 'store/personal/bad'), $true)
    [IO.File]::WriteAllBytes($catPath, $catGood)

    # ---- run
    $child = [IO.Path]::Combine($T, 'child.ps1')
    [IO.File]::WriteAllBytes($child, (B (
                'param($expected, $a1, $a2, $a3)' + "`n" +
                '$v = [Environment]::GetEnvironmentVariable("TESTVAL")' + "`n" +
                '$h = [System.Security.Cryptography.SHA256]::Create()' + "`n" +
                '$hex = ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$v))) -replace "-","").ToLowerInvariant()' + "`n" +
                '$p = [Environment]::GetEnvironmentVariable("P_API_KEY")' + "`n" +
                '$hp = ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$p))) -replace "-","").ToLowerInvariant()' + "`n" +
                '[Console]::Out.WriteLine("child-match=" + ($hex -eq $expected))' + "`n" +
                '[Console]::Out.WriteLine("child-prefix-match=" + ($hp -eq $expected))' + "`n" +
                '[Console]::Out.WriteLine("child-args=" + $a1 + "|" + $a2 + "|" + $a3)' + "`n" +
                'exit 7' + "`n")))
    $h1 = Sec-Sha256Hex (B $v1)
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '-a', 'P_=personal/test/kv1', '--', $child, $h1, 'a b', 'q"z', 'tr\')
    Assert ($r.ExitCode -eq 7) 'run returns child exit code'
    Assert ($r.Text.Contains('child-match=True')) 'run child sees value (-e)'
    Assert ($r.Text.Contains('child-prefix-match=True')) 'run child sees value (-a PREFIX=)'
    Assert ($r.Text.Contains('child-args=a b|q"z|tr\')) 'run passes args verbatim'
    Assert (-not ($r.Text + $r.Stderr).Contains($v1)) 'run: value not in parent stdout/stderr'
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', $child, $h1)
    Assert ($r.ExitCode -eq 7 -and $r.Text.Contains('child-match=True')) 'run without --'
    $cmdChild = [IO.Path]::Combine($T, 'child.cmd')
    if (Sec-IsWindows) {
        [IO.File]::WriteAllBytes($cmdChild, (B "@echo off`r`nif defined TESTVAL (echo cmd-defined) else (echo cmd-undefined)`r`nexit /b 3`r`n"))
        $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '--', $cmdChild)
        Assert ($r.ExitCode -eq 3 -and $r.Text.Contains('cmd-defined') -and -not $r.Text.Contains($v1)) 'run .cmd via cmd.exe'
    }
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#NOPE', '--', $child, $h1)
    Assert ($r.ExitCode -eq 1 -and -not $r.Text.Contains('child-match')) 'run fails before start on missing field'
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/key#X', '--', $child, $h1)
    Assert ($r.ExitCode -eq 1) 'run refuses non-kv'
    if (Sec-IsWindows) {
        $noext = [IO.Path]::Combine($T, 'noext-script')
        [IO.File]::WriteAllBytes($noext, (B "#!/bin/sh`necho ran`n"))
        $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '--', $noext)
        Assert ($r.ExitCode -eq 1 -and -not $r.Text.Contains('ran') -and ($r.Stderr.Contains('PATHEXT') -or $r.Stderr.Contains('not found'))) 'run refuses extension-less script'
    }
    # run output masking: RunCli captures stdout/stderr, so `auto` masks both
    $leaky = [IO.Path]::Combine($T, 'leaky.ps1')
    [IO.File]::WriteAllBytes($leaky, (B (
                'param($mode)' + "`n" +
                '$v = [Environment]::GetEnvironmentVariable("TESTVAL")' + "`n" +
                '$o = [Console]::OpenStandardOutput()' + "`n" +
                'function W([string]$s) { $b = [Text.Encoding]::UTF8.GetBytes($s); $o.Write($b, 0, $b.Length); $o.Flush() }' + "`n" +
                'if ($mode -eq "plain") { W ("out=" + $v + "`n"); [Console]::Error.WriteLine("err=" + $v); exit 5 }' + "`n" +
                'if ($mode -eq "split") { $h = [int]($v.Length / 2); W ("a=" + $v.Substring(0, $h)); Start-Sleep -Milliseconds 50; W ($v.Substring($h) + "=b`n"); exit 0 }' + "`n" +
                'if ($mode -eq "bin") { $b = New-Object byte[] 256; for ($i = 0; $i -lt 256; $i++) { $b[$i] = [byte]$i }; $o.Write($b, 0, 256); $o.Flush(); exit 0 }' + "`n")))
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '--', $leaky, 'plain')
    Assert ($r.ExitCode -eq 5) 'run mask: child exit code kept'
    Assert ($r.Text.Contains('out=<concealed:TESTVAL>') -and -not $r.Text.Contains($v1)) 'run mask: stdout value concealed'
    Assert ($r.Stderr.Contains('err=<concealed:TESTVAL>') -and -not $r.Stderr.Contains($v1)) 'run mask: stderr value concealed'
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '--', $leaky, 'split')
    Assert ($r.Text.Contains('a=<concealed:TESTVAL>=b') -and -not $r.Text.Contains($v1)) 'run mask: value split across two writes'
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '--', $leaky, 'bin')
    $want = New-Object byte[] 256; for ($i = 0; $i -lt 256; $i++) { $want[$i] = [byte]$i }
    Assert ($r.ExitCode -eq 0 -and (BytesEq $r.Stdout $want)) 'run mask: binary output passes through byte-exact'
    $r = RunCli @('run', '-e', 'TESTVAL=personal/test/kv1#API_KEY', '--no-mask', '--', $leaky, 'plain') -ValueOutput
    Assert ($r.ExitCode -eq 5 -and $r.Text.Contains('out=' + $v1)) 'run --no-mask: value passes through'

    # ---- materialize
    $sshTarget = [IO.Path]::Combine([IO.Path]::Combine($env:SECRET_HOME, '.ssh'), 'test_key')
    $r = RunCli @('materialize')
    Assert ($r.ExitCode -eq 0 -and (HasLine $r.Text '^\? personal/test/key -> ~/\.ssh/test_key') -and -not [IO.File]::Exists($sshTarget)) 'materialize: unapproved skipped'
    $r = RunCli @('materialize', '--approve', '--dry-run')
    Assert (-not [IO.File]::Exists($sshTarget)) 'materialize --dry-run writes nothing'
    $r = RunCli @('materialize', '--approve')
    Assert ($r.ExitCode -eq 0 -and (HasLine $r.Text '^\+ personal/test/key') -and [IO.File]::Exists($sshTarget)) 'materialize --approve writes'
    Assert (BytesEq ([IO.File]::ReadAllBytes($sshTarget)) $binPlain) 'materialized bytes'
    Assert (Only-UserAcl $sshTarget) 'materialized ACL: only current user, no inheritance'
    Assert (([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes([IO.Path]::Combine($env:SECRET_STATE_DIR, 'approved-targets.txt')))) -ceq ("personal/test/key`t~/.ssh/test_key`n")) 'approval recorded'
    $r = RunCli @('materialize')
    Assert (HasLine $r.Text '^= personal/test/key') 'materialize same -> ='
    [IO.File]::WriteAllBytes($sshTarget, (B 'locally changed'))
    $r = RunCli @('materialize')
    Assert ((HasLine $r.Text '^! personal/test/key') -and (BytesEq ([IO.File]::ReadAllBytes($sshTarget)) (B 'locally changed'))) 'materialize differs -> ! not overwritten'
    $r = RunCli @('check')
    Assert ($r.ExitCode -eq 1 -and (HasLine $r.Text '^ERROR materialized personal/test/key$')) 'check: materialized mismatch ERROR'
    $r = RunCli @('materialize', '--force')
    Assert ((HasLine $r.Text '^\+ personal/test/key') -and (BytesEq ([IO.File]::ReadAllBytes($sshTarget)) $binPlain)) 'materialize --force overwrites'
    Assert (Only-UserAcl $sshTarget) 'materialize --force ACL'
    # sensitive target + junction in the target chain
    $lockPath = [IO.Path]::Combine([IO.Path]::Combine($repo, 'store'), '.recipients.lock')
    $catKeep = [IO.File]::ReadAllBytes($catPath); $lockKeep = [IO.File]::ReadAllBytes($lockPath)
    $apprPath = [IO.Path]::Combine($env:SECRET_STATE_DIR, 'approved-targets.txt'); $apprKeep = [IO.File]::ReadAllBytes($apprPath)
    $scriptFile = [IO.Path]::Combine($T, 'tool.ps1'); [IO.File]::WriteAllBytes($scriptFile, (B "Write-Output 'hi'`n"))
    Assert ((RunCli @('add', 'personal/test/script', '--type', 'file', '--title', 's', '--from-file', $scriptFile, '--target', '{workspace}/tools/run.ps1')).ExitCode -eq 0) 'add file with script target'
    $r = RunCli @('materialize', 'personal/test/script')
    Assert ((HasLine $r.Text '^\? personal/test/script .*SENSITIVE') -and -not [IO.File]::Exists([IO.Path]::Combine([IO.Path]::Combine($env:SECRET_WORKSPACE, 'tools'), 'run.ps1'))) 'materialize flags SENSITIVE target before approval'
    $r = RunCli @('materialize', '--approve', 'personal/test/script')
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('SENSITIVE') -and [IO.File]::Exists([IO.Path]::Combine([IO.Path]::Combine($env:SECRET_WORKSPACE, 'tools'), 'run.ps1'))) 'materialize --approve still allowed, warns SENSITIVE'
    Assert ((RunCli @('add', 'personal/test/cloudt', '--type', 'file', '--title', 'c', '--from-file', $binFile, '--target', '{workspace}/Dropbox/x.bin')).ExitCode -eq 0) 'add file with cloud-synced target'
    $r = RunCli @('materialize', 'personal/test/cloudt')
    Assert ((HasLine $r.Text '^\? personal/test/cloudt .*SENSITIVE.*cloud-synced') -and $r.ExitCode -eq 0) 'materialize flags cloud-synced target as SENSITIVE (not blocked)'
    $r = RunCli @('materialize', '--approve', 'personal/test/cloudt')
    Assert ($r.ExitCode -eq 0 -and [IO.File]::Exists([IO.Path]::Combine([IO.Path]::Combine($env:SECRET_WORKSPACE, 'Dropbox'), 'x.bin'))) 'materialize into a cloud-synced target still allowed with --approve'
    if (Sec-IsWindows) {
        $elsewhere = [IO.Path]::Combine($T, 'elsewhere'); [void][IO.Directory]::CreateDirectory($elsewhere)
        $link = [IO.Path]::Combine($env:SECRET_WORKSPACE, 'linked')
        $mk = Sec-Exec ([IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'cmd.exe')) @('/d', '/c', 'mklink', '/J', $link, $elsewhere) $null
        Assert ($mk.ExitCode -eq 0) 'create junction for test'
        Assert ((RunCli @('add', 'personal/test/linked', '--type', 'file', '--title', 'l', '--from-file', $binFile, '--target', '{workspace}/linked/x.bin')).ExitCode -eq 0) 'add file with target through junction'
        $r = RunCli @('materialize', '--approve', 'personal/test/linked')
        Assert ($r.ExitCode -eq 1 -and $r.Text.Contains('junction') -and -not [IO.File]::Exists([IO.Path]::Combine($elsewhere, 'x.bin'))) 'materialize refuses target through junction'
        $r = RunCli @('check')
        Assert (HasLine $r.Text '^ERROR target-invalid personal/test/linked$') 'check: junction target ERROR'
        [IO.Directory]::Delete($link, $false)
    }
    foreach ($x in @('store/personal/test/script.file.age', 'store/personal/test/linked.file.age', 'store/personal/test/cloudt.file.age')) { $xf = [IO.Path]::Combine($repo, $x); if ([IO.File]::Exists($xf)) { [IO.File]::Delete($xf) } }
    [IO.File]::WriteAllBytes($catPath, $catKeep); [IO.File]::WriteAllBytes($lockPath, $lockKeep); [IO.File]::WriteAllBytes($apprPath, $apprKeep)
    Assert (-not (HasLine (RunCli @('check')).Text '^ERROR ')) 'state restored after sensitive/junction tests'
    # invalid target injected directly into catalog (bypassing add)
    $catBackup = [IO.File]::ReadAllBytes($catPath)
    [IO.File]::WriteAllBytes($catPath, (B ([Text.Encoding]::UTF8.GetString($catBackup).Replace('target = "~/.ssh/test_key"', 'target = "~/.ssh/../escaped"'))))
    $r = RunCli @('materialize', '--approve')
    Assert ($r.ExitCode -eq 1 -and -not [IO.File]::Exists([IO.Path]::Combine($env:SECRET_HOME, 'escaped'))) 'materialize refuses .. target'
    $r = RunCli @('check')
    Assert ($r.ExitCode -eq 1 -and $r.Text.Contains('invalid target')) 'check: invalid target ERROR'
    [IO.File]::WriteAllBytes($catPath, (B ([Text.Encoding]::UTF8.GetString($catBackup).Replace('target = "~/.ssh/test_key"', 'target = "~/Documents/x"'))))
    $r = RunCli @('materialize', '--approve')
    Assert ($r.ExitCode -eq 1 -and -not [IO.Directory]::Exists([IO.Path]::Combine($env:SECRET_HOME, 'Documents'))) 'materialize refuses target outside whitelist'
    [IO.File]::WriteAllBytes($catPath, $catBackup)

    # ---- edit (EDITOR = script that appends a field / does nothing)
    $edAppend = [IO.Path]::Combine($T, 'ed-append.ps1')
    [IO.File]::WriteAllBytes($edAppend, (B ('param($f)' + "`n" + '[IO.File]::AppendAllText($f, "NEW_FIELD=1`n")' + "`n")))
    $edNoop = [IO.Path]::Combine($T, 'ed-noop.ps1')
    [IO.File]::WriteAllBytes($edNoop, (B ('param($f)' + "`n" + 'exit 0' + "`n")))
    $env:EDITOR = $edNoop
    $r = RunCli @('edit', 'personal/test/kv1')
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('unchanged')) 'edit unchanged writes nothing'
    $env:EDITOR = $edAppend
    $r = RunCli @('edit', 'personal/test/kv1')
    Assert ($r.ExitCode -eq 0) 'edit changed'
    $cat = Sec-LoadCatalog $repo $null
    Assert ((@(($cat.Entries | Where-Object { $_.Path -ceq 'personal/test/kv1' }).Fields) -join ',') -ceq 'API_KEY,EMPTY,SP,NEW_FIELD') 'edit syncs fields'
    $tmpDir = [IO.Path]::Combine($env:SECRET_STATE_DIR, 'tmp')
    Assert ([IO.Directory]::GetFiles($tmpDir).Length -eq 0) 'edit temp files removed'
    $env:EDITOR = $saved['EDITOR']
    $r = RunCli @('check')
    Assert (-not (HasLine $r.Text '^ERROR ')) 'check clean after edit'

    # ---- edit: invalid kv -> reopen editor (content kept) / abort on EOF
    $marker = [IO.Path]::Combine($T, 'editor-marker')
    $edTwice = [IO.Path]::Combine($T, 'ed-twice.ps1')
    [IO.File]::WriteAllBytes($edTwice, (B ('param($f)' + "`n" + '$m = ''' + $marker + '''' + "`n" +
                'if (-not (Test-Path -LiteralPath $m)) { [IO.File]::AppendAllText($f, "bad line`n"); [IO.File]::WriteAllText($m, "1") }' + "`n" +
                'else { $t = [IO.File]::ReadAllText($f).Replace("bad line`n", "FIXED=1`n"); [IO.File]::WriteAllText($f, $t) }' + "`n")))
    $env:EDITOR = $edTwice
    $r = RunCli @('edit', 'personal/test/zh') (B "y`n")
    $zhFields = @((Sec-LoadCatalog $repo $null).Entries | Where-Object { $_.Path -ceq 'personal/test/zh' })[0].Fields
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('reopen the editor') -and (@($zhFields) -join ',') -ceq 'ZH,FIXED') 'edit: invalid kv reopens editor with content kept'
    [IO.File]::Delete($marker)
    $before = [IO.File]::ReadAllBytes($catPath)
    $r = RunCli @('edit', 'personal/test/zh')
    Assert ($r.ExitCode -eq 1 -and (BytesEq ([IO.File]::ReadAllBytes($catPath)) $before)) 'edit: invalid kv + EOF on stdin aborts, nothing written'
    Assert ([IO.Directory]::GetFiles($tmpDir).Length -eq 0) 'edit temp files removed after abort'
    [IO.File]::Delete($marker)
    $env:EDITOR = $saved['EDITOR']

    # ---- all-or-nothing writes: a read-only lock / catalog makes rekey / add / edit fail with the repo unchanged
    $snap = {
        $d = @{}
        $baseLen = $repo.TrimEnd('\', '/').Length + 1
        foreach ($f in [IO.Directory]::GetFiles($repo, '*', [IO.SearchOption]::AllDirectories)) {
            $rel = $f.Substring($baseLen).Replace('\', '/')
            if ($rel.StartsWith('.git/')) { continue }
            $d[$rel] = Sec-Sha256Hex ([IO.File]::ReadAllBytes($f))
        }
        return $d
    }
    $same = { param($a, $b) if ($a.Count -ne $b.Count) { return $false }; foreach ($k in $a.Keys) { if (-not $b.ContainsKey($k) -or $b[$k] -cne $a[$k]) { return $false } }; return $true }
    $lockPath = [IO.Path]::Combine([IO.Path]::Combine($repo, 'store'), '.recipients.lock')
    $s0 = & $snap
    [IO.File]::SetAttributes($lockPath, [IO.FileAttributes]::ReadOnly)
    $r = RunCli @('rekey', '--all')
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('restored') -and (& $same $s0 (& $snap))) 'rekey with read-only lock: fails, ciphertexts rolled back'
    $r = RunCli @('add', 'personal/test/txn', '--type', 'kv', '--title', 't', '--stdin') (B "A=1`n")
    Assert ($r.ExitCode -eq 1 -and (& $same $s0 (& $snap))) 'add with read-only lock: fails, repo unchanged'
    [IO.File]::SetAttributes($lockPath, [IO.FileAttributes]::Normal)
    [IO.File]::SetAttributes($catPath, [IO.FileAttributes]::ReadOnly)
    $r = RunCli @('add', 'personal/test/txn', '--type', 'kv', '--title', 't', '--stdin') (B "A=1`n")
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('restored') -and (& $same $s0 (& $snap))) 'add with read-only catalog: ciphertext + lock rolled back'
    $edTxn = [IO.Path]::Combine($T, 'ed-txn.ps1')
    [IO.File]::WriteAllBytes($edTxn, (B ('param($f)' + "`n" + '[IO.File]::AppendAllText($f, "TXN_FIELD=1`n")' + "`n")))
    $env:EDITOR = $edTxn
    $r = RunCli @('edit', 'personal/test/kv1')
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('restored') -and (& $same $s0 (& $snap))) 'edit with read-only catalog: rolled back'
    $env:EDITOR = $saved['EDITOR']
    [IO.File]::SetAttributes($catPath, [IO.FileAttributes]::Normal)
    $r = RunCli @('check')
    Assert (-not (HasLine $r.Text '^ERROR ')) 'check: no ERROR after failed writes'

    # ---- M1: one writer at a time (machine-local lock)
    $slowEd = [IO.Path]::Combine($T, 'ed-slow.ps1')
    [IO.File]::WriteAllBytes($slowEd, (B ('param($f)' + "`n" + 'Start-Sleep -Seconds 6' + "`n" + '[IO.File]::AppendAllText($f, "SLOW=abcd1234`n")' + "`n")))
    $env:EDITOR = $slowEd
    $bg = StartCli @('add', 'personal/test/lockme', '--type', 'kv', '--title', 'l')
    $lockFile = Sec-LockFileFor $repo
    $waited = 0
    while (-not [IO.File]::Exists($lockFile + '.owner') -and $waited -lt 50) { Start-Sleep -Milliseconds 100; $waited++ }
    Assert ([IO.File]::Exists($lockFile + '.owner')) 'writer took the lock'
    $r = RunCli @('--lock-timeout', '1', 'add', 'personal/test/locked-out', '--type', 'kv', '--title', 'o', '--stdin') (B "A=abcd1234`n")
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('another write is in progress') -and $r.Stderr.Contains('pid ')) 'second writer times out and names the holder'
    Assert ($null -eq (Sec-FindEntry (Sec-OpenRepo $repo -Strict -AllowEntryErrors) 'personal/test/locked-out')) 'blocked writer wrote nothing'
    $bg.WaitForExit()
    $bgErr = $bg.StandardError.ReadToEnd(); [void]$bg.StandardOutput.ReadToEnd()
    Assert ($bg.ExitCode -eq 0 -and $null -ne (Sec-FindEntry (Sec-OpenRepo $repo -Strict) 'personal/test/lockme')) 'first writer finished normally'
    $env:EDITOR = $saved['EDITOR']
    $r = RunCli @('add', 'personal/test/locked-out', '--type', 'kv', '--title', 'o', '--stdin') (B "A=abcd1234`n")
    Assert ($r.ExitCode -eq 0) 'lock is free again once the first writer exits'
    # L3: the same repo reached through a junction shares the lock
    if (Sec-IsWindows) {
        $repoLink = [IO.Path]::Combine($T, 'repolink')
        $mk = Sec-Exec ([IO.Path]::Combine([IO.Path]::Combine($env:SystemRoot, 'System32'), 'cmd.exe')) @('/d', '/c', 'mklink', '/J', $repoLink, $repo) $null
        Assert ($mk.ExitCode -eq 0) 'junction to the repo created'
        Assert ((Sec-LockFileFor $repoLink) -ceq (Sec-LockFileFor $repo)) 'lock key is the same through a junction'
        $env:EDITOR = $slowEd
        $bg2 = StartCli @('add', 'personal/test/lockme2', '--type', 'kv', '--title', 'l')
        $waited = 0
        while (-not [IO.File]::Exists($lockFile + '.owner') -and $waited -lt 50) { Start-Sleep -Milliseconds 100; $waited++ }
        $r = RunCli @('--repo', $repoLink, '--lock-timeout', '1', 'add', 'personal/test/viajunction', '--type', 'kv', '--title', 'j', '--stdin') (B "A=abcd1234`n")
        Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('another write is in progress')) 'a writer coming in through the junction waits on the same lock'
        $bg2.WaitForExit(); [void]$bg2.StandardError.ReadToEnd(); [void]$bg2.StandardOutput.ReadToEnd()
        $env:EDITOR = $saved['EDITOR']
        [void](RunCli @('rm', 'personal/test/lockme2', '--yes'))
        [IO.Directory]::Delete($repoLink, $false)
    }
    # a leftover lock file (process was killed) must not block anybody
    [IO.File]::WriteAllBytes($lockFile, (B 'stale'))
    [IO.File]::WriteAllBytes(($lockFile + '.owner'), (B '999999 add 2026-01-01 00:00:00'))
    $r = RunCli @('--lock-timeout', '0', 'rm', 'personal/test/locked-out', '--yes')
    Assert ($r.ExitCode -eq 0) 'stale lock file does not block the next writer'
    [void](RunCli @('rm', 'personal/test/lockme', '--yes'))
    Assert (-not (HasLine (RunCli @('check')).Text '^ERROR ')) 'check: no ERROR after the lock test'

    # ---- M2: commit semantics
    $headFiles = {
        $g = Sec-Git $repo @('show', '--name-only', '--format=', 'HEAD') $null
        return @($g.Out.Split([char]10) | ForEach-Object { $_.TrimEnd([char]13) } | Where-Object { $_ })
    }
    $r = RunCli @('add', 'personal/test/cmt', '--type', 'kv', '--title', 'c', '--stdin') (B "A=abcd1234`n")
    $files = & $headFiles
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('committed: secret: add personal/test/cmt (kv)')) 'add commits by default with a generated message'
    Assert ((($files | Sort-Object) -join ',') -ceq 'catalog.toml,store/.recipients.lock,store/personal/test/cmt.kv.age') 'commit contains exactly the files of this command'
    $headBefore = (Sec-Git $repo @('rev-parse', 'HEAD') $null).Out.Trim()
    $env:EDITOR = $edTxn
    $r = RunCli @('edit', 'personal/test/cmt', '--no-commit')
    $env:EDITOR = $saved['EDITOR']
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('--no-commit') -and (Sec-Git $repo @('rev-parse', 'HEAD') $null).Out.Trim() -ceq $headBefore) '--no-commit stages only'
    # unrelated dirty file: warn, and keep it out of the commit
    $polPath = [IO.Path]::Combine($repo, 'policy.toml')
    $polBytes = [IO.File]::ReadAllBytes($polPath)
    [IO.File]::WriteAllBytes($polPath, (B ([Text.Encoding]::UTF8.GetString($polBytes) + "`n# scratch`n")))
    $r = RunCli @('add', 'personal/test/cmt2', '--type', 'kv', '--title', 'c2', '--stdin') (B "A=abcd1234`n")
    $files = & $headFiles
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('WARN: the repo has other uncommitted changes') -and $r.Stderr.Contains('policy.toml')) 'unrelated dirty files only warn'
    Assert (-not ($files -ccontains 'policy.toml') -and ($files -ccontains 'catalog.toml')) 'the unrelated file is not swept into the commit'
    [IO.File]::WriteAllBytes($polPath, $polBytes)
    [void](RunCli @('rm', 'personal/test/cmt', '--yes')); [void](RunCli @('rm', 'personal/test/cmt2', '--yes'))

    # ---- R2: log leak scan (values never printed, only entry + field names)
    $pemLine = 'AAAAB3NzaC1yc2E-' + (Sec-RandHex 12)
    $pemFile = [IO.Path]::Combine($T, 'fake-key.txt'); [IO.File]::WriteAllBytes($pemFile, (B ("-----BEGIN TEST KEY-----`n" + $pemLine + "`n-----END TEST KEY-----`n")))
    Assert ((RunCli @('add', 'personal/test/pem', '--type', 'file', '--title', 'pem', '--from-file', $pemFile)).ExitCode -eq 0) 'add file entry for log scan'
    $mcpLogDir = [IO.Path]::Combine($T, 'svc'); [void][IO.Directory]::CreateDirectory($mcpLogDir)
    $mcpLog = [IO.Path]::Combine($mcpLogDir, 'server.log')
    $env:SECRET_SCAN_LOGS = [IO.Path]::Combine($T, 'no-such.log') + [IO.Path]::PathSeparator + $mcpLog   # missing entries are skipped
    # value sits across a 256 KiB read boundary, so the block overlap has to work
    [IO.File]::WriteAllBytes($mcpLog, (B (('x' * (262144 - 5)) + "env dump: API_KEY=$v1`nnothing else`n")))
    $stateLog = [IO.Path]::Combine($env:SECRET_STATE_DIR, 'reader.log')
    [IO.File]::WriteAllBytes($stateLog, (B ("line`n" + $pemLine + "`n")))
    $r = RunCli @('check')
    Assert ($r.ExitCode -eq 1 -and (HasLine $r.Text '^ERROR log-leak server\.log personal/test/kv1#API_KEY$')) 'check: value found in a log is ERROR log-leak'
    Assert (HasLine $r.Text '^ERROR log-leak reader\.log personal/test/pem#line2$') 'check: file entry credential line found in a log'
    Assert (-not $r.Text.Contains($v1) -and -not $r.Text.Contains($pemLine)) 'check: log-leak prints names only, never values'
    $r = RunCli @('check', '--no-log-scan')
    Assert (-not (HasLine $r.Text '^ERROR log-leak')) 'check --no-log-scan skips the scan'
    $r = RunCli @('check', '--quick')
    Assert (-not (HasLine $r.Text '^ERROR log-leak')) 'check --quick skips the scan'
    $extraLog = [IO.Path]::Combine($T, 'extra.log'); [IO.File]::WriteAllBytes($extraLog, (B "nothing here`n"))
    $r = RunCli @('check', '--scan-log', $extraLog, '--no-log-scan')
    Assert (-not (HasLine $r.Text 'log-leak')) '--no-log-scan wins over --scan-log'
    [IO.File]::Delete($mcpLog); [IO.File]::Delete($stateLog); $env:SECRET_SCAN_LOGS = $null
    $r = RunCli @('check', '--scan-log', $extraLog)
    Assert (-not (HasLine $r.Text '^ERROR log-leak') -and (HasLine $r.Text '^OK log-leak scanned 1 log')) 'check: clean logs are OK'
    # P4: thresholds keep the noise out (short kv values, markdown rules, single-character runs, *-pub entries)
    Assert (-not (Test-CredentialLine '|---|---|---|')) 'needle filter: markdown rule is not a credential'
    Assert (-not (Test-CredentialLine 'aaaaaaaaaaaaaa1')) 'needle filter: too few distinct characters'
    Assert (-not (Test-CredentialLine 'abcdefghijklmn')) 'needle filter: letters only'
    Assert (-not (Test-CredentialLine 'short1a')) 'needle filter: too short'
    Assert (Test-CredentialLine 'ghp_Ab12Cd34Ef56') 'needle filter: token-looking line'
    [void](RunCli @('add', 'personal/test/noise', '--type', 'kv', '--title', 'n', '--stdin') (B "ENV=prod`nPORT=8080`nLONGONE=abcd1234efgh`n"))
    $pubLine = 'AAAAC3NzaC1lZDI1-' + (Sec-RandHex 10)
    $pubFile = [IO.Path]::Combine($T, 'host.pub'); [IO.File]::WriteAllBytes($pubFile, (B ($pubLine + "`n")))
    [void](RunCli @('add', 'personal/test/host-pub', '--type', 'file', '--title', 'p', '--from-file', $pubFile))
    $noiseLog = [IO.Path]::Combine($T, 'noise.log')
    [IO.File]::WriteAllBytes($noiseLog, (B ("ENV=prod listening on PORT=8080`n|---|---|---|`n" + $pubLine + "`nLONGONE=abcd1234efgh`n")))
    $r = RunCli @('check', '--scan-log', $noiseLog)
    Assert (-not (HasLine $r.Text '^ERROR log-leak noise\.log personal/test/noise#ENV$') -and -not (HasLine $r.Text '^ERROR log-leak noise\.log personal/test/noise#PORT$')) 'log-leak: short kv values are not reported'
    Assert (-not (HasLine $r.Text '^ERROR log-leak .*personal/test/host-pub')) 'log-leak: *-pub file entries are skipped'
    Assert (HasLine $r.Text '^ERROR log-leak noise\.log personal/test/noise#LONGONE$') 'log-leak: a long value is still reported'
    [void](RunCli @('rm', 'personal/test/noise', '--yes')); [void](RunCli @('rm', 'personal/test/host-pub', '--yes'))
    Assert ((RunCli @('rm', 'personal/test/pem', '--yes')).ExitCode -eq 0) 'rm the log-scan file entry'

    # ---- rm
    $r = RunCli @('rm', 'personal/test/zh')
    Assert ($r.ExitCode -eq 2 -and (HasLine $r.Text '^path: personal/test/zh$') -and (HasLine $r.Text '^lock line: will be removed$')) 'rm without --yes: summary only, exit 2'
    Assert ($null -ne (Sec-FindEntry (Sec-OpenRepo $repo -Strict) 'personal/test/zh')) 'rm without --yes changes nothing'
    $r = RunCli @('rm', 'personal/test/zh', '--yes')
    $ctxR = Sec-OpenRepo $repo -Strict
    $lockR = Sec-LockRead $repo
    Assert ($r.ExitCode -eq 0 -and $null -eq (Sec-FindEntry $ctxR 'personal/test/zh') -and -not [IO.File]::Exists([IO.Path]::Combine($repo, 'store/personal/test/zh.kv.age')) -and -not $lockR.ContainsKey('store/personal/test/zh.kv.age')) 'rm --yes removes ciphertext, catalog entry and lock line'
    Assert (-not (HasLine (RunCli @('check')).Text '^ERROR ')) 'check: no ERROR after rm'
    Assert ((RunCli @('rm', 'personal/test/nosuch', '--yes')).ExitCode -eq 1) 'rm of a missing entry fails'
    # rm with a materialized file: it is listed, not deleted
    $rmKeyFile = [IO.Path]::Combine($T, 'rmkey.bin'); [IO.File]::WriteAllBytes($rmKeyFile, $binPlain)
    [void](RunCli @('add', 'personal/test/rmtarget', '--type', 'file', '--title', 'r', '--from-file', $rmKeyFile, '--target', '~/.ssh/rm_test_key'))
    [void](RunCli @('materialize', '--approve', 'personal/test/rmtarget'))
    $landed = [IO.Path]::Combine([IO.Path]::Combine($env:SECRET_HOME, '.ssh'), 'rm_test_key')
    Assert ([IO.File]::Exists($landed)) 'rmtarget materialized'
    $apprFile = [IO.Path]::Combine($env:SECRET_STATE_DIR, 'approved-targets.txt')
    Assert (([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($apprFile))).Contains('personal/test/rmtarget')) 'approval recorded before rm'
    $r = RunCli @('rm', 'personal/test/rmtarget', '--yes')
    Assert ($r.ExitCode -eq 0 -and (HasLine $r.Text '^target: ~/\.ssh/rm_test_key  \(materialized file exists, NOT deleted\)$') -and $r.Stderr.Contains('still on disk') -and [IO.File]::Exists($landed)) 'rm lists the materialized file and leaves it alone'
    $apprNow = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($apprFile))
    Assert (-not $apprNow.Contains('personal/test/rmtarget') -and $apprNow.Contains('personal/test/key') -and $r.Stderr.Contains('approved target record')) 'rm drops only its own approved-target records'
    [IO.File]::Delete($landed)
    # P2: a failing --push must not leave the approval behind
    [void](RunCli @('add', 'personal/test/rmpush', '--type', 'file', '--title', 'r', '--from-file', $rmKeyFile, '--target', '~/.ssh/rm_push_key'))
    [void](RunCli @('materialize', '--approve', 'personal/test/rmpush'))
    Assert (([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($apprFile))).Contains('personal/test/rmpush')) 'rmpush approval recorded'
    $r = RunCli @('rm', 'personal/test/rmpush', '--yes', '--push')
    $apprNow = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($apprFile))
    Assert ($r.ExitCode -eq 1 -and $null -eq (Sec-FindEntry (Sec-OpenRepo $repo -Strict) 'personal/test/rmpush') -and -not $apprNow.Contains('personal/test/rmpush')) 'rm drops the approval even when --push fails'
    [IO.File]::Delete([IO.Path]::Combine([IO.Path]::Combine($env:SECRET_HOME, '.ssh'), 'rm_push_key'))
    # rm of an entry that others link to
    [void](RunCli @('add', 'personal/test/alpha', '--type', 'doc', '--title', 'a', '--from-file', $docFile))
    [void](RunCli @('add', 'personal/test/beta', '--type', 'doc', '--title', 'b', '--from-file', $docFile, '--linked', 'personal/test/alpha'))
    [void](RunCli @('add', 'work/test/gamma', '--type', 'doc', '--title', 'g', '--from-file', $docFile, '--linked', 'personal/test/alpha'))
    $r = RunCli @('rm', 'personal/test/alpha', '--yes')
    Assert ($r.ExitCode -eq 1 -and (HasLine $r.Text '^linked from: personal/test/beta, work/test/gamma$') -and $r.Stderr.Contains('--force')) 'rm refuses while other entries link to it'
    # M3: the summary names the readers and linked entries of the entry itself
    [void](RunCli @('add', 'personal/test/withmeta', '--type', 'kv', '--title', 'w', '--stdin', '--reader', 'console tools/x.ps1', '--reader', 'human', '--linked', 'personal/test/kv1') (B "A=abcd1234`n"))
    $r = RunCli @('rm', 'personal/test/withmeta')
    Assert ($r.ExitCode -eq 2 -and (HasLine $r.Text '^readers: console tools/x\.ps1; human$') -and (HasLine $r.Text '^linked: personal/test/kv1$') -and $r.Stderr.Contains('switched over')) 'rm summary lists readers and linked'
    $r = RunCli @('rm', 'personal/test/kv1')
    Assert (HasLine $r.Text '^readers: \(not registered\)$') 'rm summary marks missing readers'
    [void](RunCli @('rm', 'personal/test/withmeta', '--yes'))
    Assert ($null -ne (Sec-FindEntry (Sec-OpenRepo $repo -Strict) 'personal/test/alpha')) 'rm refused: nothing changed'
    $sL = & $snap
    [IO.File]::SetAttributes($catPath, [IO.FileAttributes]::ReadOnly)
    $r = RunCli @('rm', 'personal/test/alpha', '--yes', '--force')
    Assert ($r.ExitCode -eq 1 -and (& $same $sL (& $snap))) 'rm --force with read-only catalog: rolled back, links intact'
    [IO.File]::SetAttributes($catPath, [IO.FileAttributes]::Normal)
    $r = RunCli @('rm', 'personal/test/alpha', '--yes', '--force')
    $ctxL = Sec-OpenRepo $repo -Strict
    $beta = Sec-FindEntry $ctxL 'personal/test/beta'
    $gamma = Sec-FindEntry $ctxL 'work/test/gamma'
    Assert ($r.ExitCode -eq 0 -and $null -eq (Sec-FindEntry $ctxL 'personal/test/alpha') -and $null -eq $beta.Linked -and $null -eq $gamma.Linked) 'rm --force drops the dangling links'
    Assert (-not (HasLine (RunCli @('check')).Text '^ERROR ')) 'check: no ERROR after rm --force'
    [void](RunCli @('rm', 'work/test/gamma', '--yes'))
    # a referrer with two links keeps the other one
    [void](RunCli @('add', 'personal/test/alpha', '--type', 'doc', '--title', 'a', '--from-file', $docFile))
    [void](RunCli @('add', 'personal/test/beta', '--type', 'doc', '--title', 'b', '--replace', '--from-file', $docFile, '--linked', 'personal/test/alpha', '--linked', 'personal/test/kv1'))
    [void](RunCli @('rm', 'personal/test/alpha', '--yes', '--force'))
    $beta = Sec-FindEntry (Sec-OpenRepo $repo -Strict) 'personal/test/beta'
    Assert ((@($beta.Linked) -join ',') -ceq 'personal/test/kv1') 'rm --force keeps the referrer other links'
    [void](RunCli @('rm', 'personal/test/beta', '--yes'))
    # rm rollback: read-only catalog
    [void](RunCli @('add', 'work/test/rmroll', '--type', 'doc', '--title', 'x', '--from-file', $docFile))
    $s2 = & $snap
    [IO.File]::SetAttributes($catPath, [IO.FileAttributes]::ReadOnly)
    $r = RunCli @('rm', 'work/test/rmroll', '--yes')
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('restored') -and (& $same $s2 (& $snap))) 'rm with read-only catalog: ciphertext + lock rolled back'
    [IO.File]::SetAttributes($catPath, [IO.FileAttributes]::Normal)
    Assert ((RunCli @('rm', 'work/test/rmroll', '--yes')).ExitCode -eq 0) 'rm after clearing read-only'
    Assert (-not (HasLine (RunCli @('check')).Text '^ERROR ')) 'check: no ERROR after rm rollback test'

    # ---- inventory
    # labels come from the template so this file can stay ASCII-only
    $tplLabels = @{}
    foreach ($tl in (Sec-DecodeUtf8 ([IO.File]::ReadAllBytes([IO.Path]::Combine($root, 'inventory-template.md')))).Split([char]10)) {
        if ($tl.StartsWith('@') -and $tl.Contains('=')) { $tplLabels[$tl.Substring(1, $tl.IndexOf('=') - 1)] = $tl.Substring($tl.IndexOf('=') + 1).TrimEnd([char]13) }
    }
    $notReg = $tplLabels['not-registered']
    [void](RunCli @('add', 'personal/test/rot', '--type', 'kv', '--title', 'rot', '--stdin', '--rotate', 'Test console -> Reset token', '--reader', 'script a', '--reader', 'human', '--linked', 'personal/test/kv1', '--priority', 'low') (B "TOK=abc12345`n"))
    [void](RunCli @('add', 'personal/test/urgent', '--type', 'kv', '--title', 'u', '--stdin', '--priority', 'high') (B "TOK=xyz98765`n"))
    $r = RunCli @('inventory', '--stdout')
    Assert ($r.ExitCode -eq 0 -and $r.Text.Contains('## personal/test') -and $r.Text.Contains('| low | personal/test/rot | kv |')) 'inventory: grouped table'
    Assert ($r.Text.Contains('Test console -> Reset token') -and $r.Text.Contains('script a; human')) 'inventory: rotate / readers columns'
    Assert ($r.Text.Contains($notReg)) 'inventory: missing rotate / readers marked as not registered'
    Assert ($r.Text.Contains($tplLabels['all-machines']) -and $r.Text.Contains('| personal/test/kv1 |') -and $r.Text.Contains('| 2026-')) 'inventory: machines default, linked and updated columns'
    $invLines = @($r.Text.Split([char]10) | ForEach-Object { $_.TrimEnd([char]13) } | Where-Object { $_.StartsWith('| ') -and -not $_.StartsWith('|---') })
    $hdr = @($invLines[0].Split([char]124) | Where-Object { $_.Trim() })
    Assert ($hdr.Count -eq 11) 'inventory: 11 columns'
    $rowPaths = @($invLines | Where-Object { $_ -cmatch '^\| (high|normal|low) \| personal/test/' } | ForEach-Object { @($_.Split([char]124))[1].Trim() })
    Assert ($rowPaths[0] -ceq 'high' -and $rowPaths[$rowPaths.Count - 1] -ceq 'low') 'inventory: sorted high -> normal -> low'
    $normalPaths = @($invLines | Where-Object { $_ -cmatch '^\| normal \| personal/test/' } | ForEach-Object { @($_.Split([char]124))[2].Trim() })
    Assert (($normalPaths -join ',') -ceq ((Sec-SortOrdinal $normalPaths) -join ',')) 'inventory: same priority sorted by path'
    Assert (-not $r.Text.Contains($v1) -and -not $r.Text.Contains($v2)) 'inventory contains no values'
    $invOut = [IO.Path]::Combine($T, 'INCIDENT.md')
    Assert ((RunCli @('inventory', '--out', $invOut)).ExitCode -eq 0) 'inventory --out'
    Assert ((Sec-DecodeUtf8 ([IO.File]::ReadAllBytes($invOut))) -ceq $r.Text.Replace("`r`n", "`n")) 'inventory --out matches stdout'
    $zhTpl = [IO.Path]::Combine($root, 'inventory-template.zh-CN.md')
    $zhHeader = @((Sec-DecodeUtf8 ([IO.File]::ReadAllBytes($zhTpl))).Split([char]10) | Where-Object { $_.StartsWith('@table-header=') })[0].Substring(14).TrimEnd([char]13)
    $env:SECRET_INVENTORY_TEMPLATE = $zhTpl
    $rz = RunCli @('inventory', '--stdout')
    $env:SECRET_INVENTORY_TEMPLATE = $null
    Assert ($rz.ExitCode -eq 0 -and $rz.Text.Contains($zhHeader) -and $rz.Text.Contains('| personal/test/rot |')) 'inventory: SECRET_INVENTORY_TEMPLATE switches the wording'
    $invRepo = [IO.Path]::Combine($repo, 'INCIDENT.md')
    Assert ((RunCli @('inventory')).ExitCode -eq 0 -and [IO.File]::Exists($invRepo)) 'inventory writes <repo>/INCIDENT.md by default'
    Assert ((Sec-DecodeUtf8 ([IO.File]::ReadAllBytes($invRepo))) -ceq $r.Text.Replace("`r`n", "`n")) 'default INCIDENT.md matches --stdout'
    Assert ((RunCli @('inventory', '--out', [IO.Path]::Combine($cloudDir, 'INCIDENT.md'))).ExitCode -eq 1) 'inventory --out refuses a cloud-synced folder'
    [IO.File]::Delete($invRepo)
    # self-check: a kv value that leaked into metadata stops the write
    $leakVal = 'leak-' + (Sec-RandHex 10)
    [void](RunCli @('add', 'personal/test/leaky', '--type', 'kv', '--title', 'l', '--stdin') (B "TOK=$leakVal`n"))
    [void](RunCli @('add', 'work/test/titled', '--type', 'doc', '--title', ('see ' + $leakVal), '--from-file', $docFile))
    $r = RunCli @('inventory')
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('personal/test/leaky#TOK') -and -not $r.Stderr.Contains($leakVal) -and -not [IO.File]::Exists($invRepo)) 'inventory refuses to write when it would contain a kv value'
    # the same value in a second entry's metadata makes it identifier-like (user / db / env name): note, not a leak
    [void](RunCli @('add', 'work/test/titled2', '--type', 'doc', '--title', ('also ' + $leakVal), '--from-file', $docFile))
    $r = RunCli @('inventory')
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('personal/test/leaky#TOK') -and -not $r.Stderr.Contains($leakVal) -and [IO.File]::Exists($invRepo)) 'inventory: a value shared by 2+ catalog entries is a note, not a leak'
    [void](RunCli @('rm', 'work/test/titled2', '--yes'))
    [IO.File]::Delete($invRepo)
    [void](RunCli @('rm', 'work/test/titled', '--yes')); [void](RunCli @('rm', 'personal/test/leaky', '--yes'))
    # documented residual: twice inside ONE entry counts 2, so it lands in the note (named) instead of refusing
    $leakVal2 = 'leak2-' + (Sec-RandHex 10)
    [void](RunCli @('add', 'personal/test/leaky2', '--type', 'kv', '--title', 'l2', '--stdin') (B "TOK=$leakVal2`n"))
    [void](RunCli @('add', 'work/test/titled3', '--type', 'doc', '--title', ('t ' + $leakVal2), '--description', ('d ' + $leakVal2), '--from-file', $docFile))
    $r = RunCli @('inventory')
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('personal/test/leaky2#TOK') -and -not $r.Stderr.Contains($leakVal2)) 'inventory: a value repeated inside one entry is named in the note'
    [void](RunCli @('rm', 'work/test/titled3', '--yes')); [void](RunCli @('rm', 'personal/test/leaky2', '--yes'))
    [IO.File]::Delete($invRepo)
    # check: INCIDENT.md freshness (check itself must not write it)
    $r = RunCli @('check')
    Assert (HasLine $r.Text '^WARN inventory INCIDENT\.md is missing') 'check: missing INCIDENT.md is WARN'
    Assert ((RunCli @('inventory')).ExitCode -eq 0) 'inventory regenerated'
    Assert (HasLine (RunCli @('check')).Text '^OK inventory INCIDENT\.md$') 'check: fresh INCIDENT.md is OK'
    $stale = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($invRepo)) + "stale`n"
    [IO.File]::WriteAllBytes($invRepo, (B $stale))
    $r = RunCli @('check')
    Assert ((HasLine $r.Text '^WARN inventory INCIDENT\.md is out of date') -and ([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($invRepo))) -ceq $stale) 'check: stale INCIDENT.md is WARN and check does not rewrite it'
    [IO.File]::Delete($invRepo)
    [void](RunCli @('rm', 'personal/test/urgent', '--yes'))
    [void](RunCli @('rm', 'personal/test/rot', '--yes'))

    # ---- recipients change -> rekey
    $idB = [IO.Path]::Combine($T, 'idB.txt')
    $pubB = Sec-NewIdentityFile $idB
    $r = RunCli @('recipients', 'add', 'dev-b', $pubB)
    Assert ($r.ExitCode -eq 0) 'recipients add'
    $r = RunCli @('check')
    Assert ($r.ExitCode -eq 1 -and (HasLine $r.Text '^ERROR rekey-needed store/personal/test/kv1\.kv\.age$')) 'check: recipients changed -> rekey ERROR'
    $cipherKv = [IO.Path]::Combine($repo, 'store/personal/test/kv1.kv.age')
    Assert ($null -eq (Sec-AgeDecrypt ([IO.File]::ReadAllBytes($cipherKv)) $idB)) 'dev-b cannot decrypt before rekey'
    $r = RunCli @('rekey')
    Assert ($r.ExitCode -eq 0) 'rekey exit 0'
    $r = RunCli @('check')
    Assert (-not (HasLine $r.Text '^ERROR ')) 'check: no ERROR after rekey'
    $ctx = Sec-OpenRepo $repo -Strict
    $lock = Sec-LockRead $repo
    $allOk = $true
    foreach ($e in $ctx.Catalog.Entries) {
        $ex = Sec-KeysFor $ctx $e.StorePath
        $bytes = [IO.File]::ReadAllBytes([IO.Path]::Combine($repo, $e.StorePath))
        if ($lock[$e.StorePath].RHash -cne $ex.Hash -or $lock[$e.StorePath].CHash -cne (Sec-Sha256Hex $bytes)) { $allOk = $false }
        $viaB = Sec-AgeDecrypt $bytes $idB
        $viaA = Sec-AgeDecrypt $bytes $env:SECRET_IDENTITY
        if ($null -eq $viaB -or -not (BytesEq $viaA $viaB)) { $allOk = $false }
    }
    Assert $allOk 'lock consistent and new recipient decrypts every entry'
    Assert ((RunCli @('rekey')).Stderr.Contains('rekeyed 0')) 'rekey idempotent'

    # ---- policy change -> rekey
    [IO.File]::WriteAllBytes([IO.Path]::Combine($repo, 'policy.toml'), (B "[[rule]]`npath = ""store/**""`nrecipients = [""@all""]`n`n[[rule]]`npath = ""store/personal/test/kv1.kv.age""`nrecipients = [""dev-a"", ""@recovery"", ""ghost""]`n"))
    $r = RunCli @('check')
    Assert ($r.ExitCode -eq 1 -and (HasLine $r.Text '^ERROR rekey-needed store/personal/test/kv1\.kv\.age$') -and -not (HasLine $r.Text '^ERROR rekey-needed store/personal/test/key')) 'check: policy changed -> rekey ERROR only for affected'
    Assert (HasLine $r.Text '^WARN policy-ref ghost') 'check: policy unknown name WARN'
    $r = RunCli @('rekey')
    Assert ($r.ExitCode -eq 0) 'rekey after policy change'
    $r = RunCli @('check')
    Assert (-not (HasLine $r.Text '^ERROR ')) 'check clean after policy rekey'
    Assert ($null -eq (Sec-AgeDecrypt ([IO.File]::ReadAllBytes($cipherKv)) $idB)) 'dev-b excluded by policy after rekey'

    # ---- recovery drill
    $r = RunCli @('recovery', 'drill', '--identity', $recFile)
    Assert ($r.ExitCode -eq 0 -and $r.Text.Trim() -ceq 'match true') 'recovery drill match true'
    $r = RunCli @('recovery', 'drill', '--identity', $idB, 'personal/test/kv1')
    Assert ($r.ExitCode -eq 1 -and $r.Text.Trim() -ceq 'match false') 'recovery drill wrong identity match false'
    [IO.File]::WriteAllBytes([IO.Path]::Combine($env:SECRET_DESKTOP, 'secret-recovery-identity-20260917.txt'), (B 'placeholder'))
    Assert ((RunCli @('recovery', 'confirm')).ExitCode -eq 1) 'recovery confirm refuses while desktop file exists'
    Assert (HasLine (RunCli @('check')).Text '^WARN recovery-desktop ') 'check: desktop recovery file WARN'
    [IO.File]::Delete([IO.Path]::Combine($env:SECRET_DESKTOP, 'secret-recovery-identity-20260917.txt'))
    Assert ((RunCli @('recovery', 'confirm')).ExitCode -eq 0) 'recovery confirm'
    Assert (-not (HasLine (RunCli @('check')).Text '^WARN recovery-backup')) 'check: recovery backup WARN gone'

    # ---- pre-commit hook
    Assert ((RunCli @('hooks', 'install')).ExitCode -eq 0) 'hooks install'
    [void](RunCli @('add', 'personal/test/hookc', '--type', 'kv', '--title', 'h', '--stdin', '--no-commit') (B "A=abcd1234`n"))
    Assert ((Sec-Git $repo @('add', '-A') $null).Code -eq 0) 'git add all'
    $c = Sec-Git $repo @('commit', '-q', '-m', 'selftest valid') $null
    Assert ($c.Code -eq 0) 'pre-commit accepts valid repo'
    $fake = [IO.Path]::Combine($repo, 'store/personal/test/fake.kv.age')
    [IO.File]::WriteAllBytes($fake, (B "not an age file`n"))
    [void](Sec-Git $repo @('add', '--', 'store/personal/test/fake.kv.age') $null)
    $c = Sec-Git $repo @('commit', '-q', '-m', 'fake') $null
    Assert ($c.Code -ne 0 -and $c.Err.Contains('fake.kv.age')) 'pre-commit rejects fake .age'
    $r = RunCli @('check')
    Assert ((HasLine $r.Text '^ERROR ciphertext-header store/personal/test/fake\.kv\.age$')) 'check: bad ciphertext header ERROR'
    [void](Sec-Git $repo @('reset', '-q') $null); [IO.File]::Delete($fake)
    $notes = [IO.Path]::Combine($repo, 'notes.txt'); [IO.File]::WriteAllBytes($notes, (B 'x'))
    [void](Sec-Git $repo @('add', '--', 'notes.txt') $null)
    $c = Sec-Git $repo @('commit', '-q', '-m', 'notes') $null
    Assert ($c.Code -ne 0 -and $c.Err.Contains('notes.txt')) 'pre-commit rejects non-whitelisted file'
    [void](Sec-Git $repo @('reset', '-q') $null); [IO.File]::Delete($notes)
    $badPath = [IO.Path]::Combine($repo, 'store/personal/Upper'); [void][IO.Directory]::CreateDirectory($badPath)
    [IO.File]::Copy($cipherKv, [IO.Path]::Combine($badPath, 'x.kv.age'))
    [void](Sec-Git $repo @('add', '--', 'store/personal/Upper/x.kv.age') $null)
    $c = Sec-Git $repo @('commit', '-q', '-m', 'badpath') $null
    Assert ($c.Code -ne 0) 'pre-commit rejects .age at invalid path'
    [void](Sec-Git $repo @('reset', '-q') $null); [IO.Directory]::Delete($badPath, $true)

    # ---- M2: --push rejected (remote moved on) -> tell the human, never rebase behind their back
    $bare = [IO.Path]::Combine($T, 'remote.git')
    Assert ((Sec-Exec (Sec-FindExe 'git') @('init', '--bare', '-q', $bare) $null).ExitCode -eq 0) 'bare remote created'
    [void](Sec-Git $repo @('remote', 'add', 'origin', $bare) $null)
    $branch = (Sec-Git $repo @('rev-parse', '--abbrev-ref', 'HEAD') $null).Out.Trim()
    Assert ((Sec-Git $repo @('push', '-u', 'origin', $branch) $null).Code -eq 0) 'first push'
    $clone2 = [IO.Path]::Combine($T, 'clone2')
    [void](Sec-Exec (Sec-FindExe 'git') @('clone', '-q', $bare, $clone2) $null)
    [IO.File]::WriteAllBytes([IO.Path]::Combine($clone2, 'README.md'), (B "other writer`n"))
    [void](Sec-Git $clone2 @('config', 'user.email', 'other@example.invalid') $null)
    [void](Sec-Git $clone2 @('config', 'user.name', 'other') $null)
    [void](Sec-Git $clone2 @('add', '-A') $null)
    [void](Sec-Git $clone2 @('commit', '-q', '-m', 'remote moves on') $null)
    Assert ((Sec-Git $clone2 @('push', '-q') $null).Code -eq 0) 'remote advanced'
    # L1: knowing the remote moved on, a write warns (and check reports behind)
    [void](Sec-Git $repo @('fetch', '-q') $null)
    $r = RunCli @('add', 'personal/test/behind', '--type', 'kv', '--title', 'b', '--stdin') (B "A=abcd1234`n")
    Assert ($r.ExitCode -eq 0 -and $r.Stderr.Contains('behind') -and $r.Stderr.Contains('pull --rebase')) 'write warns when the clone is behind upstream'
    Assert (HasLine (RunCli @('check')).Text '^WARN git behind upstream by 1$') 'check reports behind upstream'
    [void](RunCli @('rm', 'personal/test/behind', '--yes'))
    $r = RunCli @('add', 'personal/test/pushme', '--type', 'kv', '--title', 'p', '--stdin', '--push') (B "A=abcd1234`n")
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('pull --rebase') -and $r.Stderr.Contains('secret check') -and -not $r.Stderr.Contains('rebasing')) 'push rejection tells the human what to run, does not rebase'
    Assert ($null -ne (Sec-FindEntry (Sec-OpenRepo $repo -Strict) 'personal/test/pushme')) 'the local commit is kept when push fails'
    [void](RunCli @('rm', 'personal/test/pushme', '--yes'))
    [void](Sec-Git $repo @('remote', 'remove', 'origin') $null)

    # L2: a local commit that was never pushed at all (nothing behind, purely ahead) -> check warns with
    # the count and a copy-pasteable push command; the write path itself never auto-pushes.
    $bare2 = [IO.Path]::Combine($T, 'remote2.git')
    Assert ((Sec-Exec (Sec-FindExe 'git') @('init', '--bare', '-q', $bare2) $null).ExitCode -eq 0) 'bare remote (ahead scenario) created'
    [void](Sec-Git $repo @('remote', 'add', 'origin', $bare2) $null)
    Assert ((Sec-Git $repo @('push', '-u', 'origin', $branch) $null).Code -eq 0) 'push establishes a clean upstream for the ahead scenario'
    Assert (-not (HasLine (RunCli @('check')).Text '^WARN git ahead of upstream') -and -not (HasLine (RunCli @('check')).Text '^WARN git behind upstream')) 'check: no drift right after a matching push'
    $r = RunCli @('add', 'personal/test/ahead', '--type', 'kv', '--title', 'a', '--stdin') (B "A=abcd1234`n")
    Assert ($r.ExitCode -eq 0) 'add without --push leaves the commit local-only'
    $wantAhead = '^WARN git ahead of upstream by 1 -- not pushed, run: git -C ' + [regex]::Escape($repo) + ' push$'
    Assert (HasLine (RunCli @('check')).Text $wantAhead) 'check: unpushed commit is WARN with count and push hint'
    [void](RunCli @('rm', 'personal/test/ahead', '--yes'))
    [void](Sec-Git $repo @('push', '-q') $null)
    [void](Sec-Git $repo @('remote', 'remove', 'origin') $null)

    # ---- tampered ciphertext -> check ERROR
    [IO.File]::WriteAllBytes($cipherKv, (B 'garbage'))
    $r = RunCli @('check')
    Assert ($r.ExitCode -eq 1 -and (HasLine $r.Text '^ERROR ciphertext-header store/personal/test/kv1\.kv\.age$') -and (HasLine $r.Text '^ERROR lock-hash store/personal/test/kv1\.kv\.age$')) 'check: tampered ciphertext ERROR'
    Assert ((RunCli @('rekey', '--all')).ExitCode -eq 1) 'rekey refuses ciphertext changed outside CLI'
    $env:EDITOR = $edAppend
    $r = RunCli @('edit', 'personal/test/kv1')
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('outside the CLI')) 'edit refuses ciphertext changed outside CLI'
    $env:EDITOR = $saved['EDITOR']
    $r = RunCli @('add', 'personal/test/kv1', '--type', 'kv', '--title', 'x', '--replace', '--stdin') (B "A=1`n")
    Assert ($r.ExitCode -eq 1 -and $r.Stderr.Contains('outside the CLI')) 'add --replace refuses ciphertext changed outside CLI'

    # ---- global leak scan
    $all = $script:allOutput.ToString()
    Assert (-not $all.Contains($v1) -and -not $all.Contains($v2) -and -not $all.Contains($zhVal)) 'no test value in any CLI output (excluding get/show)'
} finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    try {
        # retry: git / the virus scanner can still hold a handle for a moment after the last child exits
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            try {
                foreach ($f in [IO.Directory]::GetFiles($T, '*', [IO.SearchOption]::AllDirectories)) { [IO.File]::SetAttributes($f, [IO.FileAttributes]::Normal) }
                [IO.Directory]::Delete($T, $true)
                break
            } catch {
                if ($attempt -eq 4) { throw }
                Start-Sleep -Milliseconds 700
            }
        }
    } catch { [Console]::Out.WriteLine("note: could not fully remove $T") }
}

[Console]::Out.WriteLine(('selftest: ' + $script:pass + ' passed, ' + $script:fail + ' failed'))
if ($script:fail -gt 0) { exit 1 }
exit 0
