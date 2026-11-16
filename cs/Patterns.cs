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

        static void AddCandidate(Dictionary<Hash128, string> map, string cand, string why)
        {
            Hash128 h = Ntlm.Hash(cand);
            if (!map.ContainsKey(h)) map[h] = why;
        }
    }
}
