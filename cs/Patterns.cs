using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Hashslinger
{
    /// <summary>Common-pattern check: keyboard walks and base words with leetspeak, seasons, years.
    /// Candidates are hashed in memory and matched against account hashes (not the store).</summary>
    public static class Patterns
    {
        static readonly string[] Seasons = { "spring", "summer", "autumn", "fall", "winter" };

        // ---------------------------------------------------------------- keyboard "waterfalls" (1qaz2wsx, zaq12wsx, 1q2w3e4r)
        // A waterfall runs down (or up) one column of keys, then the next column over: 1qaz, 2wsx, 3edc ...
        // Generated here for a US keyboard: every start column, both directions, columns taken down, up or zig-zag, full
        // columns or just the top two / three or bottom two / three keys, then plain, fully shifted (!QAZ@WSX) and
        // alternating (1qaz@WSX, !QAZ2wsx). Plus straight row runs and numeric-pad shapes.
        static readonly string[] KeyRows = { "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm" };
        const string ShiftFrom = "1234567890";
        const string ShiftTo = "!@#$%^&*()";

        static string ShiftKeys(string s)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char ch in s)
            {
                int i = ShiftFrom.IndexOf(ch);
                sb.Append(i >= 0 ? ShiftTo[i] : char.ToUpperInvariant(ch));
            }
            return sb.ToString();
        }

        static string Reverse(string s)
        {
            char[] a = s.ToCharArray();
            Array.Reverse(a);
            return new string(a);
        }

        static bool Cell(int r, int c) { return r >= 0 && r < KeyRows.Length && c >= 0 && c < KeyRows[r].Length; }

        // One strip of keys. kind 0: a column read top to bottom (1qaz). kind 1: a diagonal climbing to the right (zse4),
        // kind 2: a diagonal climbing to the left, both read from the bottom row up. Null when the strip runs off the board.
        static string Strip(int kind, int c)
        {
            StringBuilder sb = new StringBuilder();
            if (kind == 0)
            {
                foreach (string row in KeyRows) if (c < row.Length) sb.Append(row[c]);
                return sb.ToString();
            }
            int dx = kind == 1 ? 1 : -1;
            for (int i = 0; i < 4; i++)
            {
                int r = 3 - i, cc = c + dx * i;
                if (!Cell(r, cc)) return null;
                sb.Append(KeyRows[r][cc]);
            }
            return sb.ToString();
        }

        // which part of a strip to use: 0 whole, 1 top two, 2 top three, 3 bottom three, 4 bottom two, 5 the middle two
        static string ColumnPart(string col, int part)
        {
            int n = col.Length;
            switch (part)
            {
                case 1: return col.Substring(0, Math.Min(2, n));
                case 2: return col.Substring(0, Math.Min(3, n));
                case 3: return col.Substring(Math.Max(0, n - 3));
                case 4: return col.Substring(Math.Max(0, n - 2));
                case 5: return n <= 2 ? col : col.Substring(1, 2);
                default: return col;
            }
        }

        public static List<string> Waterfalls() { return Waterfalls(false); }

        /// <summary>core = true gives the classic set (US columns, 2 to 6 of them in a row, plus row runs and a few number-pad
        /// shapes). That set also gets the longer list of endings (years, !!, 12345 ...). core = false adds everything else:
        /// chains of up to 10 columns, every-other-column hops, middle slices, diagonal strips and every number-pad shape.</summary>
        public static List<string> Waterfalls(bool core)
        {
            HashSet<string> set = new HashSet<string>();
            int maxN = core ? 6 : 10, kinds = core ? 1 : 3, steps = core ? 1 : 2, parts = core ? 5 : 6;
            for (int kind = 0; kind < kinds; kind++)
                for (int dir = -1; dir <= 1; dir += 2)
                    for (int step = 1; step <= steps; step++)
                        for (int start = 0; start < 10; start++)
                            for (int n = 2; n <= maxN; n++)
                            {
                                int last = start + dir * step * (n - 1);
                                if (last < 0 || last > 9) continue;
                                for (int part = 0; part < parts; part++)
                                    for (int mode = 0; mode < 4; mode++)
                                    {
                                        List<string> pieces = new List<string>();
                                        bool ok = true;
                                        int total = 0;
                                        for (int k = 0; k < n; k++)
                                        {
                                            string strip = Strip(kind, start + dir * step * k);
                                            if (strip == null) { ok = false; break; }
                                            string down = ColumnPart(strip, part);
                                            bool up = mode == 1 || (mode == 2 && k % 2 == 1) || (mode == 3 && k % 2 == 0);
                                            pieces.Add(up ? Reverse(down) : down);
                                            total += down.Length;
                                        }
                                        if (!ok || total > 32) continue;
                                        AddShiftVariants(set, pieces);
                                    }
                            }
            // straight runs along a row, forward and backward, 4 to 10 keys
            foreach (string row in KeyRows)
                for (int len = 4; len <= row.Length && len <= 10; len++)
                    for (int s = 0; s + len <= row.Length; s++)
                    {
                        string run = row.Substring(s, len);
                        set.Add(run); set.Add(Reverse(run));
                        set.Add(ShiftKeys(run)); set.Add(ShiftKeys(Reverse(run)));
                    }
            foreach (string pad in new[] { "147258369", "369258147", "159753", "357159", "789456123", "123654789", "741852963", "963852741", "1470258", "147852", "258369", "159357", "7894561230" })
                set.Add(pad);
            if (!core)
            {
                foreach (string line in new[] { "0123456789", "9876543210", "1234567890", "0987654321" }) set.Add(line);
                AddPadChains(set, new[] { "789", "456", "123" });   // number pad rows, 2 or 3 in any order, each either way round
                AddPadChains(set, new[] { "741", "852", "963" });   // number pad columns
                AddPadChains(set, new[] { "159", "357" });          // the two diagonals
            }
            return new List<string>(set);
        }

        static void AddPadChains(HashSet<string> set, string[] lines)
        {
            int n = lines.Length;
            for (int a = 0; a < n; a++)
                for (int b = 0; b < n; b++)
                {
                    if (a == b) continue;
                    for (int oa = 0; oa < 2; oa++)
                        for (int ob = 0; ob < 2; ob++)
                        {
                            string x = oa == 0 ? lines[a] : Reverse(lines[a]);
                            string y = ob == 0 ? lines[b] : Reverse(lines[b]);
                            set.Add(x + y);
                            for (int c = 0; c < n; c++)
                            {
                                if (c == a || c == b) continue;
                                set.Add(x + y + lines[c]); set.Add(x + y + Reverse(lines[c]));
                            }
                        }
                }
        }

        static void AddShiftVariants(HashSet<string> set, List<string> parts)
        {
            for (int style = 0; style < 4; style++)
            {
                StringBuilder sb = new StringBuilder();
                for (int k = 0; k < parts.Count; k++)
                {
                    bool shifted = style == 1 || (style == 2 && k % 2 == 1) || (style == 3 && k % 2 == 0);
                    sb.Append(shifted ? ShiftKeys(parts[k]) : parts[k]);
                }
                set.Add(sb.ToString());
            }
        }

        static string Capitalize(string w)
        {
            return w.Length == 0 ? w : char.ToUpperInvariant(w[0]) + w.Substring(1).ToLowerInvariant();
        }

        static IEnumerable<string> CaseVariants(string w)
        {
            HashSet<string> s = new HashSet<string>();
            s.Add(w.ToLowerInvariant());
            s.Add(Capitalize(w));
            s.Add(w.ToUpperInvariant());
            return s;
        }

        static List<string> LeetVariants(string w, Dictionary<char, string[]> leet, int cap)
        {
            List<string> cur = new List<string>();
            cur.Add("");
            foreach (char ch in w)
            {
                List<string> opts = new List<string>();
                opts.Add(ch.ToString());
                string[] subs;
                if (leet.TryGetValue(char.ToLowerInvariant(ch), out subs)) opts.AddRange(subs);
                List<string> next = new List<string>();
                foreach (string prefix in cur)
                {
                    foreach (string o in opts)
                    {
                        next.Add(prefix + o);
                        if (next.Count >= cap) break;
                    }
                    if (next.Count >= cap) break;
                }
                cur = next;
            }
            return cur;
        }

        static Dictionary<char, string[]> ParseLeet(Dictionary<string, object> rules)
        {
            Dictionary<char, string[]> m = new Dictionary<char, string[]>();
            object o;
            if (rules.TryGetValue("leet", out o))
            {
                Dictionary<string, object> d = o as Dictionary<string, object>;
                if (d != null)
                    foreach (KeyValuePair<string, object> kv in d)
                        m[kv.Key[0]] = Json.StrList(d, kv.Key).ToArray();
                return m;
            }
            m['a'] = new[] { "@", "4" }; m['e'] = new[] { "3" }; m['i'] = new[] { "1", "!" };
            m['o'] = new[] { "0" }; m['s'] = new[] { "$", "5" }; m['t'] = new[] { "7" };
            return m;
        }

        public static Dictionary<Hash128, string> Build(string rulesPath, DateTime today)
        {
            Dictionary<string, object> rules = (Dictionary<string, object>)Json.Parse(File.ReadAllText(rulesPath, Encoding.UTF8));
            Dictionary<char, string[]> leet = ParseLeet(rules);
            int cap = (int)Convert.ToDouble(Json.Str(rules, "max_leet_variants", "64"), System.Globalization.CultureInfo.InvariantCulture);
            int back = (int)Convert.ToDouble(Json.Str(rules, "years_back", "4"), System.Globalization.CultureInfo.InvariantCulture);
            bool seasons = Json.Str(rules, "include_seasons", "True").ToLowerInvariant() == "true";
            List<string> suffixes = Json.StrList(rules, "suffixes");
            if (suffixes.Count == 0) suffixes.Add("");
            for (int y = today.Year - back; y <= today.Year + 1; y++)
            {
                string ys = y.ToString(System.Globalization.CultureInfo.InvariantCulture);
                suffixes.Add(ys);
                suffixes.Add(ys.Substring(2));
                suffixes.Add(ys + "!");
            }

            Dictionary<Hash128, string> map = new Dictionary<Hash128, string>();
            if (Json.Str(rules, "keyboard_waterfalls", "True").ToLowerInvariant() == "true")
            {
                string[] plainEnds = { "", "1", "!", "123", "12", "@", "#", "$", "." };
                // longer endings, only for the classic set so the candidate count stays reasonable
                List<string> moreEnds = new List<string> { "!!", "1!", "1234", "12345", "!@#", "123!", "0", "2", "11", "01", "@1", "1@", "#1" };
                for (int y = today.Year - back; y <= today.Year + 1; y++)
                {
                    string ys = y.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    moreEnds.Add(ys); moreEnds.Add(ys.Substring(2)); moreEnds.Add(ys + "!"); moreEnds.Add(ys.Substring(2) + "!");
                }
                foreach (string wf in Waterfalls(false))
                    AddWaterfall(map, wf, plainEnds);
                foreach (string wf in Waterfalls(true))
                    AddWaterfall(map, wf, moreEnds.ToArray());
            }
            foreach (string walk in Json.StrList(rules, "keyboard_walks"))
                foreach (string v in CaseVariants(walk))
                    foreach (string s in new[] { "", "1", "!", "123" })
                        AddCandidate(map, v + s, "keyboard walk");

            List<string> words = Json.StrList(rules, "base_words");
            if (seasons) words.AddRange(Seasons);
            foreach (string w in words)
                foreach (string cv in CaseVariants(w))
                    foreach (string lv in LeetVariants(cv, leet, cap))
                        foreach (string s in suffixes)
                            AddCandidate(map, lv + s, "dictionary base word");
            return map;
        }

        // the walk exactly as generated first (1qaz@WSX and !QAZ2wsx are mixed case on purpose), then the lower, Capitalized
        // and UPPER forms, each with every ending
        static void AddWaterfall(Dictionary<Hash128, string> map, string wf, string[] ends)
        {
            List<string> forms = new List<string>(CaseVariants(wf));
            if (!forms.Contains(wf)) forms.Add(wf);
            foreach (string v in forms)
                foreach (string e in ends)
                    AddCandidate(map, v + e, "keyboard waterfall");
        }

        static void AddCandidate(Dictionary<Hash128, string> map, string cand, string why)
        {
            Hash128 h = Ntlm.Hash(cand);
            if (!map.ContainsKey(h)) map[h] = why;
        }
    }
}
