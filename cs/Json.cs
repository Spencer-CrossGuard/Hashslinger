using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Hashslinger
{
    /// <summary>Minimal JSON reader/writer so the tool has no dependencies beyond the base framework.
    /// Objects parse to Dictionary&lt;string,object&gt;, arrays to List&lt;object&gt;, numbers to double.</summary>
    public static class Json
    {
        public static object Parse(string s)
        {
            int i = 0;
            object v = ParseValue(s, ref i, 0);
            SkipWs(s, ref i);
            if (i != s.Length) throw new FormatException("Trailing content after JSON value");
            return v;
        }

        static void SkipWs(string s, ref int i)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        }

        static bool Match(string s, int i, string word)
        {
            return string.CompareOrdinal(s, i, word, 0, word.Length) == 0;
        }

        static object ParseValue(string s, ref int i, int depth)
        {
            if (depth > 64) throw new FormatException("JSON nested too deeply");
            SkipWs(s, ref i);
            if (i >= s.Length) throw new FormatException("Unexpected end of JSON");
            char c = s[i];
            if (c == '{') return ParseObject(s, ref i, depth);
            if (c == '[') return ParseArray(s, ref i, depth);
            if (c == '"') return ParseString(s, ref i);
            if (Match(s, i, "true")) { i += 4; return true; }
            if (Match(s, i, "false")) { i += 5; return false; }
            if (Match(s, i, "null")) { i += 4; return null; }
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            double d;
            if (i == start || !double.TryParse(s.Substring(start, i - start), NumberStyles.Float,
                CultureInfo.InvariantCulture, out d))
                throw new FormatException("Bad JSON value at position " + start);
            return d;
        }

        static Dictionary<string, object> ParseObject(string s, ref int i, int depth)
        {
            Dictionary<string, object> o = new Dictionary<string, object>();
            i++; // {
            SkipWs(s, ref i);
            if (i < s.Length && s[i] == '}') { i++; return o; }
            while (true)
            {
                SkipWs(s, ref i);
                if (i >= s.Length || s[i] != '"') throw new FormatException("Expected string key");
                string key = ParseString(s, ref i);
                SkipWs(s, ref i);
                if (i >= s.Length || s[i] != ':') throw new FormatException("Expected ':'");
                i++;
                o[key] = ParseValue(s, ref i, depth + 1);
                SkipWs(s, ref i);
                if (i < s.Length && s[i] == ',') { i++; continue; }
                if (i < s.Length && s[i] == '}') { i++; return o; }
                throw new FormatException("Expected ',' or '}'");
            }
        }

        static List<object> ParseArray(string s, ref int i, int depth)
        {
            List<object> a = new List<object>();
            i++; // [
            SkipWs(s, ref i);
            if (i < s.Length && s[i] == ']') { i++; return a; }
            while (true)
            {
                a.Add(ParseValue(s, ref i, depth + 1));
                SkipWs(s, ref i);
                if (i < s.Length && s[i] == ',') { i++; continue; }
                if (i < s.Length && s[i] == ']') { i++; return a; }
                throw new FormatException("Expected ',' or ']'");
            }
        }

        static string ParseString(string s, ref int i)
        {
            StringBuilder sb = new StringBuilder();
            i++; // opening quote
            while (true)
            {
                if (i >= s.Length) throw new FormatException("Unterminated string");
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) throw new FormatException("Bad escape");
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw new FormatException("Bad \\u escape");
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: throw new FormatException("Bad escape \\" + e);
                }
            }
        }

        public static string Write(object v)
        {
            StringBuilder sb = new StringBuilder();
            WriteValue(sb, v);
            return sb.ToString();
        }

        static void WriteValue(StringBuilder sb, object v)
        {
            if (v == null) { sb.Append("null"); return; }
            string str = v as string;
            if (str != null) { WriteString(sb, str); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is int || v is long) { sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return; }
            IDictionary<string, object> d = v as IDictionary<string, object>;
            if (d != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (KeyValuePair<string, object> kv in d)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, kv.Key);
                    sb.Append(':');
                    WriteValue(sb, kv.Value);
                }
                sb.Append('}');
                return;
            }
            System.Collections.IEnumerable list = v as System.Collections.IEnumerable;
            if (list != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object o in list)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteValue(sb, o);
                }
                sb.Append(']');
                return;
            }
            throw new ArgumentException("Unsupported JSON type " + v.GetType().Name);
        }

        static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u" + ((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        // ---- typed accessors for config-style dictionaries
        public static string Str(IDictionary<string, object> d, string key, string dflt)
        {
            object v;
            if (d.TryGetValue(key, out v) && v != null) return Convert.ToString(v, CultureInfo.InvariantCulture);
            return dflt;
        }

        public static List<string> StrList(IDictionary<string, object> d, string key)
        {
            List<string> r = new List<string>();
            object v;
            if (d.TryGetValue(key, out v))
            {
                List<object> l = v as List<object>;
                if (l != null) foreach (object o in l) r.Add(Convert.ToString(o, CultureInfo.InvariantCulture));
            }
            return r;
        }
    }
}
