using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SecretsWeb.Tests;

/// <summary>
/// Builds a test bare repo in a temp directory: age-keygen creates a test identity, the age CLI encrypts a few random test
/// values, catalog / recipients / policy / lock are written, committed, then clone --bare.
/// Every value is randomly generated for this run and has nothing to do with any real secret.
/// </summary>
public sealed class TestRepoFixture : IDisposable
{
    public string Root { get; }
    public string BareDir { get; }
    public string IdentityPath { get; }
    public string AuditPath { get; }

    /// <summary>Favorites list (web UI only, a server-side file, not in the data repo).</summary>
    public string FavoritesPath { get; }
    public string Head { get; }

    public string ApiKey { get; } = "test-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(12));
    public string ApiUser { get; } = "user-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6));
    public string DocMarker { get; } = "doc-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
    public string FileText { get; } = "file-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)) + "\n";

    public static readonly string[] EntryPaths =
    [
        "personal/test/api", "personal/test/notes", "work/test/config", "personal/test/blob", "personal/test/broken", "personal/test/badmeta",
    ];

    /// <summary>Entry paths actually in this repo (write tests want a "clean" repo, so the entry with invalid metadata can be left out).</summary>
    public IReadOnlyList<string> Paths { get; }

    public TestRepoFixture(bool includeInvalidEntry = true)
    {
        Paths = includeInvalidEntry ? EntryPaths : EntryPaths[..^1];
        Root = Path.Combine(Path.GetTempPath(), "secrets-web-test-" + Guid.NewGuid().ToString("N"));
        var work = Path.Combine(Root, "work");
        BareDir = Path.Combine(Root, "secrets.git");
        IdentityPath = Path.Combine(Root, "identity.txt");
        AuditPath = Path.Combine(Root, "data", "audit.log");
        FavoritesPath = Path.Combine(Root, "data", "favorites.json");
        Directory.CreateDirectory(work);

        Run("age-keygen", ["-o", IdentityPath], null, Root);
        var pub = Encoding.ASCII.GetString(Run("age-keygen", ["-y", IdentityPath], null, Root)).Trim();

        Write(work, "recipients.toml",
            $"# test recipients\n[[recipient]]\nname = \"web\"\ntype = \"service\"\nkey = \"{pub}\"\nstatus = \"active\"\nadded = \"2026-09-17\"\n");
        Write(work, "policy.toml", "[[rule]]\npath = \"store/**\"\nrecipients = [\"@all\"]\n");
        Write(work, "catalog.toml", """
            [[meta]]
            format = "1"

            [[entry]]
            path = "personal/test/api"
            type = "kv"
            title = "Test API credentials"
            description = "kv for integration tests"
            fields = ["API_USER", "API_KEY"]
            tags = ["testtag"]
            updated = "2026-09-17"

            [[entry]]
            path = "personal/test/notes"
            type = "doc"
            title = "Test document"
            updated = "2026-09-17"

            [[entry]]
            path = "work/test/config"
            type = "file"
            title = "Test text file"
            target = "{workspace}/x/config.txt"
            updated = "2026-09-17"

            [[entry]]
            path = "personal/test/blob"
            type = "file"
            title = "Test binary file"
            updated = "2026-09-17"

            [[entry]]
            path = "personal/test/broken"
            type = "kv"
            title = "Tampered entry"
            fields = ["X"]
            updated = "2026-09-17"

            [[BADMETA]]
            """.Replace("\r\n", "\n").Replace("[[BADMETA]]", includeInvalidEntry
                ? "[[entry]]\npath = \"personal/test/badmeta\"\ntype = \"doc\"\ntitle = \"\"\naliases = [\"vault:\"]\nupdated = \"2026-02-30\""
                : "") + "\n");

        var store = new Dictionary<string, byte[]>
        {
            ["store/personal/test/api.kv.age"] = Encrypt(pub, Encoding.UTF8.GetBytes($"# test\nAPI_USER={ApiUser}\nAPI_KEY={ApiKey}\n")),
            ["store/personal/test/notes.doc.age"] = Encrypt(pub, Encoding.UTF8.GetBytes(
                $"# Title\n\n{DocMarker}\n\n<script>alert(1)</script>\n\n[bad](javascript:alert(1)) [good](https://example.com) [ent](java&#x73;cript:alert(5)) [ref][r]\n\n![leak-alt](https://evil.example/leak.png) ![local](/app.css)\n\n[r]: javascript:alert(6)\n")),
            ["store/work/test/config.file.age"] = Encrypt(pub, Encoding.UTF8.GetBytes(FileText)),
            ["store/personal/test/blob.file.age"] = Encrypt(pub, [0x00, 0xFF, 0x10, 0x00, 0x42]),
        };
        var broken = Encrypt(pub, "X=1\n"u8.ToArray());
        broken[0] = (byte)'x'; // tamper with the ciphertext header
        store["store/personal/test/broken.kv.age"] = broken;
        if (includeInvalidEntry)
            store["store/personal/test/badmeta.doc.age"] = Encrypt(pub, Encoding.UTF8.GetBytes(DocMarker + "-badmeta"));

        foreach (var (p, bytes) in store)
        {
            var full = Path.Combine(work, p.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllBytes(full, bytes);
        }
        var hash = SecretsWeb.Format.Policy.RecipientSetHash([pub]);
        var lockLines = store.Keys.Order(StringComparer.Ordinal)
            .Select(p => $"{hash}  {Convert.ToHexStringLower(SHA256.HashData(store[p]))}  {p}");
        Write(work, "store/.recipients.lock", "# secret recipients lock v1\n" + string.Join("\n", lockLines) + "\n");
        Write(work, ".gitattributes", "*.age binary\n");

        Git(work, "init", "-q", "-b", "main");
        Git(work, "add", "-A");
        Git(work, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "test data");
        Git(Root, "clone", "-q", "--bare", work, BareDir);
        Head = Encoding.ASCII.GetString(Run("git", ["--git-dir", BareDir, "rev-parse", "HEAD"], null, Root)).Trim();
    }

    private byte[] Encrypt(string pub, byte[] plain) => Run("age", ["-r", pub], plain, Root);

    /// <summary>Run a git command directly and return stdout (for test assertions).</summary>
    public string GitOutput(params string[] args) => Encoding.UTF8.GetString(Run("git", args, null, Root));

    public static void ForceDelete(string dir)
    {
        foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            File.SetAttributes(f, FileAttributes.Normal);
        Directory.Delete(dir, true);
    }

    private static void Write(string dir, string rel, string content)
    {
        var full = Path.Combine(dir, rel.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, new UTF8Encoding(false).GetBytes(content));
    }

    private static void Git(string cwd, params string[] args) =>
        Run("git", ["-c", "core.autocrlf=false", .. args], null, cwd);

    private static byte[] Run(string file, string[] args, byte[]? stdin, string cwd)
    {
        var psi = new ProcessStartInfo(file)
        {
            WorkingDirectory = cwd,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var errTask = p.StandardError.ReadToEndAsync();
        if (stdin is not null) p.StandardInput.BaseStream.Write(stdin);
        p.StandardInput.Close();
        using var ms = new MemoryStream();
        p.StandardOutput.BaseStream.CopyTo(ms);
        p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException($"{file} {args.FirstOrDefault()} failed: {errTask.Result}");
        return ms.ToArray();
    }

    public void Dispose()
    {
        try
        {
            ForceDelete(Root);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
