# test-guard-secret-run.ps1 -- self test for ../hooks/guard-secret-run.ps1, in the style of
# cli/test/selftest.ps1: feed the hook stdin JSON exactly like Claude Code would, assert the
# stdout decision. Never touches a real data repo, identity, or value. Exit 0 = all pass.
#
#   pwsh -NoProfile -File claude-plugin/test/test-guard-secret-run.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File claude-plugin/test/test-guard-secret-run.ps1

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$hookPath = [IO.Path]::Combine((Split-Path -Parent $here), 'hooks', 'guard-secret-run.ps1')
$hostExe = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

$script:pass = 0
$script:fail = 0

function Invoke-Hook {
    # Writes/reads stdio as raw UTF-8 bytes over BaseStream rather than the StandardInputEncoding /
    # StandardOutputEncoding ProcessStartInfo properties: those are .NET-Core-only and throw on
    # Windows PowerShell 5.1 (.NET Framework) -- same reason cli/SecretLib.ps1's Sec-Exec avoids them.
    param([string]$ToolName, [hashtable]$ToolInput)
    $payload = @{ hook_event_name = 'PreToolUse'; tool_name = $ToolName; tool_input = $ToolInput } | ConvertTo-Json -Depth 6 -Compress
    $noBom = New-Object System.Text.UTF8Encoding($false)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $hostExe
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $hookPath + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $outMs = New-Object System.IO.MemoryStream
    $errMs = New-Object System.IO.MemoryStream
    $t1 = $p.StandardOutput.BaseStream.CopyToAsync($outMs)
    $t2 = $p.StandardError.BaseStream.CopyToAsync($errMs)
    $bytes = $noBom.GetBytes($payload)
    try { $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length); $p.StandardInput.BaseStream.Flush() }
    catch { } finally { try { $p.StandardInput.Close() } catch { } }
    $t1.Wait(); $t2.Wait(); $p.WaitForExit()
    return @{
        ExitCode = $p.ExitCode
        Stdout   = $noBom.GetString($outMs.ToArray())
        Stderr   = $noBom.GetString($errMs.ToArray())
    }
}

function Get-Decision([string]$Stdout) {
    if (-not $Stdout) { return $null }
    try { $j = $Stdout | ConvertFrom-Json } catch { return $null }
    return $j.hookSpecificOutput.permissionDecision
}

function Assert-Deny([string]$Name, [string]$ToolName, [hashtable]$ToolInput) {
    $r = Invoke-Hook $ToolName $ToolInput
    $decision = Get-Decision $r.Stdout
    if ($decision -eq 'deny') { $script:pass++ }
    else {
        $script:fail++
        [Console]::Out.WriteLine("FAIL (expected deny)  $Name")
        [Console]::Out.WriteLine('  exit=' + $r.ExitCode + ' stdout=' + $r.Stdout + ' stderr=' + $r.Stderr)
    }
}

function Assert-Allow([string]$Name, [string]$ToolName, [hashtable]$ToolInput) {
    $r = Invoke-Hook $ToolName $ToolInput
    $decision = Get-Decision $r.Stdout
    if ($decision -ne 'deny') { $script:pass++ }
    else {
        $script:fail++
        [Console]::Out.WriteLine("FAIL (expected allow)  $Name")
        [Console]::Out.WriteLine('  exit=' + $r.ExitCode + ' stdout=' + $r.Stdout + ' stderr=' + $r.Stderr)
    }
}

[Console]::Out.WriteLine('host: ' + $hostExe + ' ' + $PSVersionTable.PSVersion.ToString())
[Console]::Out.WriteLine('hook: ' + $hookPath)

# ---- 1. secret get / show / edit: deny ----
Assert-Deny 'secret get <path>#<FIELD>' 'Bash' @{ command = 'secret get example/demo/api#API_KEY' }
Assert-Deny 'secret show <path>'        'Bash' @{ command = 'secret show example/demo/api' }
Assert-Deny 'secret edit <path>'        'Bash' @{ command = 'secret edit example/demo/api' }
Assert-Deny 'secret.ps1 get via shim'   'Bash' @{ command = './secret.ps1 get example/demo/api#API_KEY' }
Assert-Deny 'secret get --out file'     'Bash' @{ command = 'secret get example/demo/api --out ./out.txt' }

# ---- 2. secret run whose child re-prints the value: deny; normal use: allow ----
Assert-Deny 'secret run -- echo $NAME' 'Bash' @{ command = 'secret run -e API_KEY=example/demo/api#API_KEY -- bash -c "echo $API_KEY"' }
Assert-Deny 'secret run -- curl -H "... $NAME"' 'Bash' @{ command = 'secret run -e API_KEY=example/demo/api#API_KEY -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com' }
Assert-Deny 'secret run -- printenv (child is a bare print command)' 'Bash' @{ command = 'secret run -e API_KEY=example/demo/api#API_KEY -- printenv' }
Assert-Allow 'secret run -- normal script, value only in child env' 'Bash' @{ command = 'secret run -e API_KEY=example/demo/api#API_KEY -- python notify.py' }
Assert-Allow 'secret run --no-mask is not itself denied by this rule set' 'Bash' @{ command = 'secret run -e API_KEY=example/demo/api#API_KEY --no-mask -- python notify.py' }

# ---- 3. decrypting outside the CLI: deny ----
Assert-Deny 'age -d on a ciphertext' 'Bash' @{ command = 'age -d -i ~/.config/secrets/identity.txt store/example/demo/api.kv.age' }
Assert-Deny 'age --decrypt long form' 'Bash' @{ command = 'age --decrypt -i identity.txt store/example/demo/api.kv.age > out.txt' }
Assert-Deny 'dot-source SecretLib and call Sec-ReadField' 'Bash' @{ command = '. ./SecretLib.ps1; Sec-ReadField example/demo/api API_KEY' }
Assert-Deny 'call Sec-GetEntryBytes directly' 'Bash' @{ command = 'pwsh -c "Sec-GetEntryBytes $repo $id example/demo/api"' }

# ---- 4. reading key material by path: deny (Read/Grep/Glob + Bash cat/type) ----
Assert-Deny 'Read the default identity file' 'Read' @{ file_path = '/home/user/.config/secrets/identity.txt' }
Assert-Deny 'Read the identity file, Windows separators' 'Read' @{ file_path = 'C:\Users\demo\.config\secrets\identity.txt' }
Assert-Deny 'Read a Desktop recovery identity file' 'Read' @{ file_path = 'C:\Users\demo\Desktop\secret-recovery-identity-20260101.txt' }
Assert-Deny 'Read recovery/recovery-identity.age' 'Read' @{ file_path = 'C:\secrets\recovery\recovery-identity.age' }
Assert-Deny 'Grep over the identity file' 'Grep' @{ path = '/home/user/.config/secrets/identity.txt'; pattern = 'age1' }
Assert-Deny 'cat the identity file from Bash' 'Bash' @{ command = 'cat ~/.config/secrets/identity.txt' }
Assert-Allow 'Read an unrelated project file' 'Read' @{ file_path = 'C:\Workspace\secret-run\README.md' }
Assert-Allow 'Grep with "secret" in the search pattern, not the path' 'Grep' @{ path = 'C:\Workspace\secret-run\docs'; pattern = 'secret:[a-z/-]+#[A-Z_]+' }

# ---- 5. reading a credential-shaped env var directly: deny ----
Assert-Deny 'printenv a KEY-shaped var' 'Bash' @{ command = 'printenv API_KEY' }
Assert-Deny 'echo $...TOKEN' 'Bash' @{ command = 'echo $GITHUB_TOKEN' }
Assert-Deny 'bare printenv (dump everything)' 'Bash' @{ command = 'printenv' }
Assert-Deny 'Get-ChildItem env:' 'Bash' @{ command = 'Get-ChildItem env:' }

# ---- 6. normal, value-free secret CLI usage: allow ----
Assert-Allow 'secret list'                 'Bash' @{ command = 'secret list example' }
Assert-Allow 'secret info'                 'Bash' @{ command = 'secret info example/demo/api' }
Assert-Allow 'secret resolve'              'Bash' @{ command = 'secret resolve notes:ops/bot.md#Credentials' }
Assert-Allow 'secret check'                'Bash' @{ command = 'secret check' }
Assert-Allow 'secret add --stdin'          'Bash' @{ command = 'secret add example/demo/api --type kv --title Demo --stdin' }
Assert-Allow 'secret recipients list'      'Bash' @{ command = 'secret recipients list' }
Assert-Allow 'git commit with secret: pointer in the message' 'Bash' @{ command = 'git commit -m "secret: add example/demo/api (kv)"' }
Assert-Allow 'unrelated command' 'Bash' @{ command = 'npm test' }

# ---- 7. malformed / empty input: fail open, no crash ----
$r = Invoke-Hook 'Bash' @{ command = $null }
if ($r.ExitCode -eq 0) { $script:pass++ } else { $script:fail++; [Console]::Out.WriteLine('FAIL  empty command should exit 0') }

[Console]::Out.WriteLine("pass=$script:pass fail=$script:fail")
if ($script:fail -gt 0) { exit 1 }
exit 0
