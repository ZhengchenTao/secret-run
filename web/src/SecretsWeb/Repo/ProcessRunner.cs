using System.Collections;
using System.Diagnostics;
using System.Text;

namespace SecretsWeb.Repo;

public sealed class ProcessResult(int exitCode, byte[] stdout, string stderr, bool truncated)
{
    public int ExitCode { get; } = exitCode;
    public byte[] Stdout { get; } = stdout;
    public string Stderr { get; } = stderr;
    public bool Truncated { get; } = truncated;
}

/// <summary>
/// Starts a child process: bytes fed on stdin, stdout read up to a cap (the process is killed beyond it, so memory can't
/// grow unbounded), stderr kept but truncated. No shell; arguments go through ArgumentList, so there is no injection.
/// **The child environment is rebuilt from an allowlist**: the parent holds things like the OIDC client secret and the
/// alert webhook token, none of which git / age need — inheriting them would only add a leak path (crash dumps of the
/// child, third-party telemetry).
/// </summary>
public static class ProcessRunner
{
    private const int StderrMax = 4096;
    public const int MaxConcurrency = 4;

    /// <summary>Global concurrency cap for git / age child processes, so the anonymous surface or a burst of clicks can't overload the host.</summary>
    private static readonly SemaphoreSlim Gate = new(MaxConcurrency, MaxConcurrency);

    /// <summary>Variable names that may be inherited (everything else is dropped). The Windows ones are needed for process creation and by git itself.</summary>
    public static readonly string[] InheritedNames =
    [
        "PATH", "PATHEXT", "HOME", "TZ", "LANG", "LC_ALL", "LC_CTYPE",
        "TMPDIR", "TMP", "TEMP",
        "SystemRoot", "SystemDrive", "windir", "ComSpec", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    ];

    /// <summary>
    /// Fixed variables (override inherited values).
    /// `GIT_CONFIG_GLOBAL` points at `/app/gitconfig` baked into the image (written by the Dockerfile, contains only
    /// `safe.directory`): the bare repo `/repo` is owned by the git server's uid while the container runs as 1654, so git
    /// refuses with `detected dubious ownership`.
    /// **`safe.directory` is only read from protected scopes (system / global); values passed via `-c` or `GIT_CONFIG_*`
    /// are ignored** (verified: `git -c safe.directory=*` has no effect on clone), so a global config file is the only way;
    /// `GIT_CONFIG_NOSYSTEM=1` still blocks `/etc/gitconfig`. On a dev machine the file doesn't exist = empty config,
    /// which doesn't affect the tests.
    /// </summary>
    public static readonly (string Key, string Value)[] ForcedVars =
    [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/app/gitconfig"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("LC_ALL", "C"),
    ];

    /// <summary>Rebuild the child environment from the allowlist: clear it, then add back allowed names and the fixed variables.</summary>
    public static void ApplyEnvironment(IDictionary<string, string?> target, IDictionary source,
        IEnumerable<KeyValuePair<string, string>>? extra = null)
    {
        target.Clear();
        var cmp = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var allowed = new HashSet<string>(InheritedNames, cmp);
        foreach (DictionaryEntry kv in source)
        {
            var name = (string)kv.Key;
            if (allowed.Contains(name) && kv.Value is string v) target[name] = v;
        }
        foreach (var (k, v) in ForcedVars) target[k] = v;
        // Explicitly added by the caller (e.g. GIT_SSH_COMMAND for push) — only values fixed in code get here, never the parent environment
        foreach (var kv in extra ?? []) target[kv.Key] = kv.Value;
    }

    public static async Task<ProcessResult> RunAsync(
        string fileName, IEnumerable<string> args, byte[]? stdin, int maxStdout, TimeSpan timeout,
        CancellationToken ct = default, IEnumerable<KeyValuePair<string, string>>? extraEnv = null,
        string? workingDirectory = null)
    {
        if (!await Gate.WaitAsync(timeout, ct)) throw new TimeoutException("Child process concurrency limit reached");
        try { return await RunCoreAsync(fileName, args, stdin, maxStdout, timeout, ct, extraEnv, workingDirectory); }
        finally { Gate.Release(); }
    }

    private static async Task<ProcessResult> RunCoreAsync(
        string fileName, IEnumerable<string> args, byte[]? stdin, int maxStdout, TimeSpan timeout,
        CancellationToken ct, IEnumerable<KeyValuePair<string, string>>? extraEnv, string? workingDirectory)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (workingDirectory is not null) psi.WorkingDirectory = workingDirectory;
        ApplyEnvironment(psi.Environment, Environment.GetEnvironmentVariables(), extraEnv);

        using var proc = new Process { StartInfo = psi };
        proc.Start();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        var writeTask = Task.Run(async () =>
        {
            try
            {
                if (stdin is not null) await proc.StandardInput.BaseStream.WriteAsync(stdin, cts.Token);
            }
            catch (IOException) { /* the child exited early and closed its end */ }
            finally
            {
                try { proc.StandardInput.Close(); } catch (IOException) { }
            }
        }, CancellationToken.None);

        var stderrTask = Task.Run(async () =>
        {
            var buf = new char[1024];
            var sb = new StringBuilder();
            int n;
            while ((n = await proc.StandardError.ReadAsync(buf, CancellationToken.None)) > 0)
                if (sb.Length < StderrMax) sb.Append(buf, 0, Math.Min(n, StderrMax - sb.Length));
            return sb.ToString();
        }, CancellationToken.None);

        var buffer = new byte[checked(maxStdout + 1)];
        var total = 0;
        var truncated = false;
        try
        {
            var stream = proc.StandardOutput.BaseStream;
            while (true)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), cts.Token);
                if (n == 0) break;
                total += n;
                if (total > maxStdout)
                {
                    truncated = true;
                    Kill(proc);
                    break;
                }
            }
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            Kill(proc);
            Array.Clear(buffer);
            throw new TimeoutException($"{Path.GetFileName(fileName)} timed out");
        }

        await writeTask;
        var stderr = await stderrTask;

        byte[] output;
        if (truncated)
        {
            output = [];
        }
        else
        {
            output = buffer.AsSpan(0, total).ToArray();
        }
        Array.Clear(buffer); // best effort: wipe a buffer that may hold plaintext

        return new ProcessResult(truncated ? -1 : proc.ExitCode, output, stderr, truncated);
    }

    private static void Kill(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
    }
}
