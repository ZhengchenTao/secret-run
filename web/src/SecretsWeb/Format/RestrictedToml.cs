using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace SecretsWeb.Format;

/// <summary>Format contract violation (FORMAT.md). Messages only carry line numbers / key names / rules, never values.</summary>
public sealed class SecretFormatException(string message) : Exception(message);

/// <summary>A restricted-TOML value: string / string array / boolean.</summary>
public abstract record TomlValue
{
    public sealed record Str(string Value) : TomlValue;
    public sealed record StrArray(IReadOnlyList<string> Values) : TomlValue;
    public sealed record Bool(bool Value) : TomlValue;
}

/// <summary>One <c>[[name]]</c> block. Keys keep their order of appearance; duplicate keys are rejected while parsing.</summary>
public sealed record TomlBlock(string Name, int Line, IReadOnlyDictionary<string, TomlValue> Values)
{
    public bool Has(string key) => Values.ContainsKey(key);

    public string? GetString(string key)
    {
        if (!Values.TryGetValue(key, out var v)) return null;
        return v is TomlValue.Str s ? s.Value
            : throw new SecretFormatException($"[[{Name}]] starting at line {Line}: key {key} must be a string");
    }

    public IReadOnlyList<string>? GetStringArray(string key)
    {
        if (!Values.TryGetValue(key, out var v)) return null;
        return v is TomlValue.StrArray a ? a.Values
            : throw new SecretFormatException($"[[{Name}]] starting at line {Line}: key {key} must be a string array");
    }
}

/// <summary>
/// Hand-written parser for the FORMAT restricted TOML: only the subset is accepted, anything outside it is an error (no general
/// TOML library, so integers, inline tables, dotted keys and the like can't slip in).
/// Readers tolerate a leading BOM and CRLF; every string is NFC-normalized.
/// </summary>
public static class RestrictedToml
{
    private static readonly Regex BareKey = new("^[A-Za-z0-9_-]+\\z", RegexOptions.CultureInvariant);

    public static IReadOnlyList<TomlBlock> Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > 0 && text[0] == '\uFEFF') text = text[1..];
        return new Parser(text).ParseDocument();
    }

    /// <summary>Strict UTF-8 decoding (invalid byte sequences are an error).</summary>
    public static string DecodeUtf8Strict(byte[] bytes, string what)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            throw new SecretFormatException($"{what} is not valid UTF-8");
        }
    }

    private sealed class Parser(string s)
    {
        private int _pos;
        private int _line = 1;

        private bool Eof => _pos >= s.Length;
        private char Cur => s[_pos];

        private SecretFormatException Err(string msg) => new($"TOML line {_line}: {msg}");

        public List<TomlBlock> ParseDocument()
        {
            var blocks = new List<TomlBlock>();
            string? name = null;
            int blockLine = 0;
            Dictionary<string, TomlValue>? current = null;

            while (!Eof)
            {
                SkipInlineWs();
                if (Eof) break;
                var c = Cur;
                if (c == '\n' || c == '\r') { ConsumeNewline(); continue; }
                if (c == '#') { SkipComment(); ConsumeLineEnd(); continue; }

                if (c == '[')
                {
                    if (current is not null) blocks.Add(new TomlBlock(name!, blockLine, current));
                    blockLine = _line;
                    name = ParseHeader();
                    current = new Dictionary<string, TomlValue>(StringComparer.Ordinal);
                    ConsumeLineEnd();
                    continue;
                }

                if (current is null) throw Err("only comments and blank lines are allowed before the first [[name]] table array");
                var key = ParseKey();
                SkipInlineWs();
                if (Eof || Cur != '=') throw Err("a key must be followed by =");
                _pos++;
                SkipInlineWs();
                var value = ParseValue();
                if (!current.TryAdd(key, value)) throw Err($"key {key} is duplicated within the block");
                ConsumeLineEnd();
            }

            if (current is not null) blocks.Add(new TomlBlock(name!, blockLine, current));
            return blocks;
        }

        private string ParseHeader()
        {
            if (!(s.AsSpan(_pos).StartsWith("[["))) throw Err("only table arrays [[name]] are allowed, not [table]");
            _pos += 2;
            var start = _pos;
            while (!Eof && Cur != ']' && Cur != '\n' && Cur != '\r') _pos++;
            var name = s[start.._pos];
            if (!BareKey.IsMatch(name)) throw Err("a table array name must be a bare key (no spaces, dots or quotes)");
            if (!s.AsSpan(_pos).StartsWith("]]")) throw Err("a table array header must end with ]]");
            _pos += 2;
            return name;
        }

        private string ParseKey()
        {
            var start = _pos;
            while (!Eof && (char.IsAsciiLetterOrDigit(Cur) || Cur == '_' || Cur == '-')) _pos++;
            var key = s[start.._pos];
            if (key.Length == 0 || !BareKey.IsMatch(key)) throw Err("keys must be bare keys [A-Za-z0-9_-]+ (no quoted or dotted keys)");
            return key;
        }

        private TomlValue ParseValue()
        {
            if (Eof) throw Err("missing value");
            switch (Cur)
            {
                case '"': return new TomlValue.Str(ParseBasicString());
                case '\'': return new TomlValue.Str(ParseLiteralString());
                case '[': return ParseArray();
                default:
                    if (s.AsSpan(_pos).StartsWith("true") && IsValueEnd(_pos + 4)) { _pos += 4; return new TomlValue.Bool(true); }
                    if (s.AsSpan(_pos).StartsWith("false") && IsValueEnd(_pos + 5)) { _pos += 5; return new TomlValue.Bool(false); }
                    throw Err("a value must be a string, a string array or a boolean (no integers, floats, dates or inline tables)");
            }
        }

        private bool IsValueEnd(int p) =>
            p >= s.Length || s[p] is ' ' or '\t' or '\r' or '\n' or '#' or ',' or ']';

        private TomlValue ParseArray()
        {
            _pos++; // [
            var items = new List<string>();
            while (true)
            {
                SkipArrayWs();
                if (Eof) throw Err("unterminated array");
                if (Cur == ']') { _pos++; break; }
                if (Cur == '"') items.Add(ParseBasicString());
                else if (Cur == '\'') items.Add(ParseLiteralString());
                else throw Err("array elements must be strings");
                SkipArrayWs();
                if (Eof) throw Err("unterminated array");
                if (Cur == ',') { _pos++; continue; }
                if (Cur == ']') { _pos++; break; }
                throw Err("array elements must be separated by commas");
            }
            return new TomlValue.StrArray(items);
        }

        private void SkipArrayWs()
        {
            while (!Eof)
            {
                var c = Cur;
                if (c is ' ' or '\t') _pos++;
                else if (c is '\n' or '\r') ConsumeNewline();
                else if (c == '#') SkipComment();
                else break;
            }
        }

        private string ParseBasicString()
        {
            if (s.AsSpan(_pos).StartsWith("\"\"\"")) throw Err("multi-line strings are not supported");
            _pos++;
            var sb = new StringBuilder();
            while (true)
            {
                if (Eof) throw Err("unterminated string");
                var c = Cur;
                if (c == '"') { _pos++; break; }
                if (IsControl(c)) throw Err("control characters are not allowed in strings (tabs included; write \\t)");
                if (c == '\\')
                {
                    if (_pos + 1 >= s.Length) throw Err("unterminated string");
                    var e = s[_pos + 1];
                    _pos += 2;
                    switch (e)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case 'n': sb.Append('\n'); break;
                        case 't': sb.Append('\t'); break;
                        case 'r': sb.Append('\r'); break;
                        case 'u':
                            if (_pos + 4 > s.Length) throw Err("\\u must be followed by 4 hex digits");
                            var hex = s.Substring(_pos, 4);
                            if (!hex.All(char.IsAsciiHexDigit) ||
                                !int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var cp))
                                throw Err("\\u must be followed by 4 hex digits");
                            if (cp is >= 0xD800 and <= 0xDFFF) throw Err("\\u must not be in the surrogate range D800-DFFF");
                            sb.Append((char)cp);
                            _pos += 4;
                            break;
                        default:
                            throw Err("unsupported escape sequence");
                    }
                    continue;
                }
                if (char.IsHighSurrogate(c))
                {
                    if (_pos + 1 >= s.Length || !char.IsLowSurrogate(s[_pos + 1])) throw Err("invalid UTF-16 surrogate pair");
                    sb.Append(c).Append(s[_pos + 1]);
                    _pos += 2;
                    continue;
                }
                if (char.IsLowSurrogate(c)) throw Err("invalid UTF-16 surrogate pair");
                sb.Append(c);
                _pos++;
            }
            return Nfc(sb.ToString());
        }

        private string ParseLiteralString()
        {
            if (s.AsSpan(_pos).StartsWith("'''")) throw Err("multi-line literal strings are not supported");
            _pos++;
            var start = _pos;
            while (true)
            {
                if (Eof) throw Err("unterminated string");
                var c = Cur;
                if (c == '\'') break;
                if (IsControl(c)) throw Err("control characters are not allowed in strings");
                _pos++;
            }
            var v = s[start.._pos];
            _pos++;
            return Nfc(v);
        }

        private string Nfc(string v)
        {
            try { return v.Normalize(NormalizationForm.FormC); }
            catch (ArgumentException) { throw Err("string contains invalid Unicode"); }
        }

        private static bool IsControl(char c) => c <= '' || c == '';

        private void SkipInlineWs()
        {
            while (!Eof && Cur is ' ' or '\t') _pos++;
        }

        private void SkipComment()
        {
            // # to end of line; comments don't allow control characters other than tab either (TOML 1.0)
            while (!Eof && Cur != '\n' && Cur != '\r')
            {
                if (Cur != '\t' && IsControl(Cur)) throw Err("control characters are not allowed in comments");
                _pos++;
            }
        }

        /// <summary>After a value / header: optional whitespace, optional comment, then a newline or end of file.</summary>
        private void ConsumeLineEnd()
        {
            SkipInlineWs();
            if (Eof) return;
            if (Cur == '#') SkipComment();
            if (Eof) return;
            if (Cur is '\n' or '\r') { ConsumeNewline(); return; }
            throw Err("only one key/value pair or header per line (unexpected trailing content)");
        }

        private void ConsumeNewline()
        {
            if (Cur == '\r')
            {
                if (_pos + 1 < s.Length && s[_pos + 1] == '\n') _pos += 2;
                else throw Err("a lone \\r is not a valid newline");
            }
            else _pos++;
            _line++;
        }
    }
}
