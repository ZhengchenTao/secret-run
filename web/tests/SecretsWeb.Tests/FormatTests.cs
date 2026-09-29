using System.Text;
using SecretsWeb.Format;

namespace SecretsWeb.Tests;

public class RestrictedTomlTests
{
    [Fact]
    public void Accepts_Full_Subset()
    {
        var text = "\uFEFF# header comment\r\n\r\n[[entry]]\r\npath\t=  \"a/b/c\" # trailing\nlit = 'x#y'\nesc = \"q\\\" b\\\\ n\\n t\\t r\\r u\\u00e9\"\n" +
                   "arr = [\n  \"a\", # c\n  'b',\n]\nempty = []\nflag = true\nno = false\n\n[[entry]]\nk-1_X = \"\"\n";
        var blocks = RestrictedToml.Parse(text);
        Assert.Equal(2, blocks.Count);
        var b = blocks[0];
        Assert.Equal("a/b/c", b.GetString("path"));
        Assert.Equal("x#y", b.GetString("lit"));
        Assert.Equal("q\" b\\ n\n t\t r\r u\u00e9", b.GetString("esc"));
        Assert.Equal(["a", "b"], b.GetStringArray("arr"));
        Assert.Empty(b.GetStringArray("empty")!);
        Assert.Equal(new TomlValue.Bool(true), b.Values["flag"]);
        Assert.Equal("", blocks[1].GetString("k-1_X"));
    }

    [Fact]
    public void Normalizes_To_Nfc()
    {
        var blocks = RestrictedToml.Parse("[[x]]\nv = \"e\u0301\"\n");
        Assert.Equal("\u00e9", blocks[0].GetString("v"));
    }

    [Theory]
    [InlineData("[table]\nk = \"v\"\n", "table")]
    [InlineData("k = \"v\"\n", "before header")]
    [InlineData("[[x]]\na.b = \"v\"\n", "dotted key")]
    [InlineData("[[x]]\n\"k\" = \"v\"\n", "quoted key")]
    [InlineData("[[x]]\nk = 1\n", "integer")]
    [InlineData("[[x]]\nk = 1.5\n", "float")]
    [InlineData("[[x]]\nk = 2026-09-17\n", "date")]
    [InlineData("[[x]]\nk = { a = \"b\" }\n", "inline table")]
    [InlineData("[[x]]\nk = [1, 2]\n", "int array")]
    [InlineData("[[x]]\nk = [[\"a\"]]\n", "nested array")]
    [InlineData("[[x]]\nk = \"\"\"multi\"\"\"\n", "multiline basic")]
    [InlineData("[[x]]\nk = '''multi'''\n", "multiline literal")]
    [InlineData("[[x]]\nk = \"a\\x\"\n", "bad escape")]
    [InlineData("[[x]]\nk = \"\\uD800\"\n", "surrogate escape")]
    [InlineData("[[x]]\nk = \"\\U0001F600\"\n", "long unicode escape")]
    [InlineData("[[x]]\nk = \"a\tb\"\n", "raw tab")]
    [InlineData("[[x]]\nk = 'a\u0001b'\n", "control char")]
    [InlineData("[[x]]\nk = \"a\u007Fb\"\n", "DEL")]
    [InlineData("[[x]]\nk = \"v\"\nk = \"w\"\n", "duplicate key")]
    [InlineData("[[x]]\nk = \"v\" j = \"w\"\n", "two pairs one line")]
    [InlineData("[[x]]\nk = \"unterminated\n", "unterminated")]
    [InlineData("[[x]]\nk = [\"a\" \"b\"]\n", "missing comma")]
    [InlineData("[[x]]\nk = True\n", "capital bool")]
    [InlineData("[[ x ]]\n", "spaced header")]
    [InlineData("[[x]]\rk = \"v\"\n", "bare CR")]
    [InlineData("[[x]]\nk = \"v\"\n[[x.y]]\n", "dotted header")]
    public void Rejects_Outside_Subset(string text, string why)
    {
        Assert.NotNull(why);
        Assert.Throws<SecretFormatException>(() => RestrictedToml.Parse(text));
    }

    [Fact]
    public void Error_Message_Does_Not_Echo_Values()
    {
        var ex = Assert.Throws<SecretFormatException>(() => RestrictedToml.Parse("[[x]]\nk = \"SUPERSECRET\\q\"\n"));
        Assert.DoesNotContain("SUPERSECRET", ex.Message);
    }
}

public class PolicyTests
{
    [Theory]
    [InlineData("store/**", "store/personal/ssh/a.file.age", true)]
    [InlineData("store/personal/*", "store/personal/ssh/a.file.age", false)]
    [InlineData("store/**/a.file.age", "store/personal/ssh/a.file.age", true)]
    [InlineData("store/**/x.kv.age", "store/x.kv.age", false)]
    [InlineData("store/?ersonal/**", "store/personal/ssh/a.file.age", true)]
    [InlineData("store/p.rsonal/**", "store/personal/ssh/a.file.age", false)]
    public void Glob_Matches_Format_Examples(string pattern, string path, bool expected) =>
        Assert.Equal(expected, Policy.GlobMatch(pattern, path));

    [Fact]
    public void Recipient_Hash_Dedups_Sorts_Ordinal_Joins_With_LF()
    {
        const string a = "age1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const string b = "age1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var expected = Convert.ToHexStringLower(
            System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(b + "\n" + a)));
        Assert.Equal(expected, Policy.RecipientSetHash([a, b, a]));
        Assert.Equal(expected, Policy.RecipientSetHash([b, a]));
        // empty set = SHA-256 of the empty string
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Policy.RecipientSetHash([]));
        // a single key: no trailing newline
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(a))),
            Policy.RecipientSetHash([a]));
    }
}

public class KvParserTests
{
    private static IReadOnlyList<KeyValuePair<string, string>> P(string s) => KvParser.Parse(Encoding.UTF8.GetBytes(s));

    [Fact]
    public void Parses_Strictly_Without_Trimming_Or_Unquoting()
    {
        var kv = P("# comment\nAPP_ID=abc\n\nQUOTED=\"x\" \r\nEQ=a=b\nEMPTY=\nSP= lead\n");
        Assert.Equal(
            [new("APP_ID", "abc"), new("QUOTED", "\"x\" "), new("EQ", "a=b"), new("EMPTY", ""), new("SP", " lead")],
            kv);
    }

    [Fact]
    public void Tolerates_Bom_And_Missing_Final_Newline()
    {
        var kv = KvParser.Parse([0xEF, 0xBB, 0xBF, .. "A=1"u8.ToArray()]);
        Assert.Equal([new("A", "1")], kv);
    }

    [Theory]
    [InlineData("app_id=x\n")]
    [InlineData(" A=x\n")]
    [InlineData("export A=x\n")]
    [InlineData("NOEQUALS\n")]
    [InlineData("=x\n")]
    [InlineData("A=1\nA=2\n")]
    [InlineData("A=x\r\r\n")]
    [InlineData("A=x\0y\n")]
    [InlineData("1A=x\n")]
    [InlineData("A-B=x\n")]
    public void Rejects_Invalid_Lines(string s) =>
        Assert.Throws<SecretFormatException>(() => P(s));

    [Fact]
    public void Rejects_Invalid_Utf8() =>
        Assert.Throws<SecretFormatException>(() => KvParser.Parse([(byte)'A', (byte)'=', 0xC3, 0x28]));

    [Fact]
    public void Error_Does_Not_Echo_Line()
    {
        var ex = Assert.Throws<SecretFormatException>(() => P("lower=TOPSECRETVALUE\n"));
        Assert.DoesNotContain("TOPSECRETVALUE", ex.Message);
    }
}

public class StoreRulesTests
{
    [Theory]
    [InlineData("store/personal/ssh/my-pem.file.age", true)]
    [InlineData("store/work/chat/assistant-app.kv.age", true)]
    [InlineData("store/personal/a/b.doc.age", true)]
    [InlineData("store/work/ssh/a.kv.age", true)]
    [InlineData("store/team-2/ssh/a.kv.age", true)]
    [InlineData("store/Work/ssh/a.kv.age", false)]
    [InlineData("store/-work/ssh/a.kv.age", false)]
    [InlineData("store/con/ssh/a.kv.age", false)]
    [InlineData("store/ssh/a.kv.age", false)]
    [InlineData("store/personal/SSH/a.kv.age", false)]
    [InlineData("store/personal/-ssh/a.kv.age", false)]
    [InlineData("store/personal/ssh/a.txt.age", false)]
    [InlineData("store/personal/ssh/a.kv", false)]
    [InlineData("store/personal/ssh/x/a.kv.age", false)]
    [InlineData("store/personal/con/a.kv.age", false)]
    [InlineData("store/personal/ssh/lpt9.kv.age", false)]
    [InlineData("store/personal/ssh/com10.kv.age", true)]
    [InlineData("recovery/recovery-identity.age", false)]
    [InlineData("store/personal/ssh/a.kv.age\n", false)]
    public void Store_Path_Regex(string path, bool ok) => Assert.Equal(ok, StoreRules.IsValidStorePath(path));

    [Fact]
    public void Age_Header()
    {
        Assert.True(StoreRules.HasAgeHeader("age-encryption.org/v1\n-> X25519 abc"u8));
        Assert.False(StoreRules.HasAgeHeader("age-encryption.org/v1\r\n"u8));
        Assert.False(StoreRules.HasAgeHeader("-----BEGIN AGE ENCRYPTED FILE-----\n"u8));
        Assert.False(StoreRules.HasAgeHeader("age-encryption.org/v1"u8));
        Assert.False(StoreRules.HasAgeHeader([]));
    }

    /// <summary>Domains are generic: any valid segment, with the same rules (and reserved-name exclusion) as group and name.</summary>
    [Theory]
    [InlineData("work/app/key", true)]
    [InlineData("personal/ssh/id", true)]
    [InlineData("team/db/prod", true)]
    [InlineData("a1/b/c", true)]
    [InlineData("Work/app/key", false)]
    [InlineData("-work/app/key", false)]
    [InlineData("work_x/app/key", false)]
    [InlineData("nul/app/key", false)]
    [InlineData("work/app", false)]
    [InlineData("work/app/key/extra", false)]
    [InlineData("", false)]
    public void Logical_Path_Accepts_Any_Valid_Domain(string path, bool ok) =>
        Assert.Equal(ok, StoreRules.IsValidLogicalPath(path));
}

/// <summary>Alias sources are generic: <c>&lt;source&gt;:&lt;path&gt;[#anchor]</c> with source matching ^[a-z][a-z0-9-]*$.</summary>
public class AliasTests
{
    [Theory]
    [InlineData("notes:infra/db.md#Prod")]
    [InlineData("wiki:x")]
    [InlineData("vault:old/x.md#A")]
    [InlineData("my-config-repo2:path/to/file")]
    [InlineData("ssh:id_ed25519.pem")]
    [InlineData(" [[notes:a\\b.md#Anchor]] ")]
    public void Generic_Sources_Are_Accepted(string alias) => Assert.Null(Aliases.Check(alias));

    [Theory]
    [InlineData("noprefix")]
    [InlineData(":path")]
    [InlineData("Notes:path")]
    [InlineData("9notes:path")]
    [InlineData("-notes:path")]
    [InlineData("no_tes:path")]
    [InlineData("notes:")]
    [InlineData("notes:   ")]
    [InlineData("notes:#anchor")]
    [InlineData("notes:.md")]
    public void Bad_Sources_Or_Empty_Paths_Are_Rejected(string alias) => Assert.NotNull(Aliases.Check(alias));

    [Fact]
    public void Normalization_Is_Unchanged()
    {
        Assert.Equal("notes:a/b#X", Aliases.Normalize(" [[notes:a\\b.md#X]] "));
        Assert.Equal("wiki:x", Aliases.Normalize("wiki:x.md"));
    }
}

public class CatalogTests
{
    private const string Key = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";

    private static readonly Recipients Rcpt = Recipients.Parse(
        $"[[recipient]]\nname = \"laptop\"\ntype = \"device\"\nkey = \"{Key}\"\nstatus = \"active\"\nadded = \"2026-09-17\"\n");

    private const string Meta = "[[meta]]\nformat = \"1\"\n\n";

    private static string Entry(string body) => Meta + "[[entry]]\n" + body;

    private const string Kv = "path = \"personal/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"A\"]\nupdated = \"2026-09-17\"\n";

    [Fact]
    public void Parses_Valid_Catalog_And_Ignores_Unknown()
    {
        var c = Catalog.Parse(Meta + "[[entry]]\n" + Kv + "future = \"x\"\n\n[[unknown]]\nz = true\n\n" +
            "[[entry]]\npath = \"work/x/b\"\ntype = \"file\"\ntitle = \"F\"\ntarget = \"~/.ssh/b.pem\"\nacl = \"private\"\n" +
            "machines = [\"laptop\"]\naliases = [\"ssh:b.pem\"]\nupdated = \"2026-09-17\"\n", Rcpt);
        Assert.Equal("1", c.Format);
        Assert.Equal(2, c.Entries.Count);
        Assert.Equal("store/personal/app/a.kv.age", c.Find("personal/app/a")!.StorePath);
    }

    [Theory]
    [InlineData("[[entry]]\n")]
    [InlineData("[[meta]]\nformat = \"2\"\n")]
    [InlineData("[[meta]]\nformat = true\n")]
    [InlineData("[[meta]]\n")]
    [InlineData("")]
    [InlineData("[[meta]]\nformat = \"1\"\n[[entry]]\npath = 1\n")] // TOML syntax error = whole-file failure
    public void Rejects_Bad_Meta_Or_Toml_Globally(string text) =>
        Assert.Throws<SecretFormatException>(() => Catalog.Parse(text, Rcpt));

    [Fact]
    public void Extra_Meta_Is_Only_A_Warning()
    {
        var c = Catalog.Parse("[[meta]]\nformat = \"1\"\n[[meta]]\nformat = \"1\"\n\n[[entry]]\n" + Kv, Rcpt);
        Assert.Single(c.Warnings);
        Assert.True(c.Entries.Single().IsValid);
    }

    [Theory]
    [InlineData("~/.ssh/id.pem", true)]
    [InlineData("{workspace}/x/config.txt", true)]
    [InlineData("~/foo", false)]
    [InlineData("~/", false)]
    [InlineData("~/.ssh/", false)]
    [InlineData("/etc/x", false)]
    [InlineData("C:/x", false)]
    [InlineData("~/.ssh/a/../b", false)]
    [InlineData("~/.ssh/./b", false)]
    [InlineData("~/.ssh/a//b", false)]
    [InlineData("~/.ssh/x.", false)]
    [InlineData("~/.ssh/x /y", false)]
    [InlineData("~/.ssh/con", false)]
    [InlineData("{workspace}/LPT1.txt", false)]
    [InlineData("{workspace}/a{b}", false)]
    [InlineData("{workspace}/a\\b", false)]
    [InlineData("{workspace}/a:b", false)]
    [InlineData("{workspace}/a\tb", false)]
    [InlineData("x/{workspace}/a", false)]
    public void Target_Syntax_Matches_Cli(string target, bool ok) =>
        Assert.Equal(ok, TargetSyntax.Check(target) is null);

    [Theory]
    [InlineData("path = \"personal/app\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"A\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"Work/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"A\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/aux/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"A\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"blob\"\ntitle = \"T\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"a\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"A\", \"A\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = [\"A\\n\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\\n\"\ntype = \"doc\"\ntitle = \"T\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\nupdated = \"2026-09-17\\n\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\nfields = [\"A\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\ntarget = \"~/.ssh/x\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"file\"\ntitle = \"T\"\ntarget = \"~/../x\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"file\"\ntitle = \"T\"\ntarget = \"C:/x\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"file\"\ntitle = \"T\"\nmachines = [\"nobody\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\nupdated = \"2026-9-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\ntags = \"x\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\naliases = [\"No_Where:x\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"  \"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"kv\"\ntitle = \"T\"\nfields = []\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\nupdated = \"2026-02-30\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\naliases = [\"vault:\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\naliases = [\"vault:#anchor\"]\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"file\"\ntitle = \"T\"\ntarget = \"~/foo\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"file\"\ntitle = \"T\"\nacl = \"public\"\nupdated = \"2026-09-17\"\n")]
    [InlineData("path = \"personal/app/a\"\ntype = \"doc\"\ntitle = true\nupdated = \"2026-09-17\"\n")]
    public void Bad_Entry_Only_Invalidates_That_Entry(string body)
    {
        var c = Catalog.Parse(Entry(body) + "\n[[entry]]\n" + Kv.Replace("personal/app/a", "personal/app/ok"), Rcpt);
        Assert.Equal(2, c.Entries.Count);
        Assert.False(c.Entries[0].IsValid);
        Assert.NotEmpty(c.Entries[0].Errors);
        Assert.True(c.Entries[1].IsValid);
        Assert.Equal(1, c.InvalidCount);
    }

    [Fact]
    public void Duplicate_Path_And_Normalized_Alias_Invalidate_Later_Entry()
    {
        var c1 = Catalog.Parse(Entry(Kv) + "\n[[entry]]\n" + Kv, Rcpt);
        Assert.True(c1.Entries[0].IsValid);
        Assert.False(c1.Entries[1].IsValid);
        Assert.Same(c1.Entries[0], c1.Find("personal/app/a"));

        var a1 = "path = \"personal/app/a\"\ntype = \"doc\"\ntitle = \"T\"\naliases = [\"notes:Secrets/x.md#A\"]\nupdated = \"2026-09-17\"\n";
        var a2 = "path = \"personal/app/b\"\ntype = \"doc\"\ntitle = \"T\"\naliases = [\" [[notes:Secrets\\\\x#A]] \"]\nupdated = \"2026-09-17\"\n";
        var c2 = Catalog.Parse(Entry(a1) + "\n[[entry]]\n" + a2, Rcpt);
        Assert.True(c2.Entries[0].IsValid);
        Assert.False(c2.Entries[1].IsValid);
    }

    [Theory]
    [InlineData("AGE1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS3290GQ")]
    [InlineData("age1bqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290")]
    [InlineData("age1short")]
    public void Recipients_Ignore_Bad_Keys(string key)
    {
        var r = Recipients.Parse(
            $"[[recipient]]\nname = \"x\"\ntype = \"device\"\nkey = \"{key}\"\nstatus = \"active\"\nadded = \"2026-09-17\"\n");
        Assert.Empty(r.Items);
        Assert.Single(r.Errors);
    }
}
