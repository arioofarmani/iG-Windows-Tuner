// JournalEngine.cs
// Change journal verifier (3.6, DECISIONS T3/T4): walks the hash chain of one segment's text,
// parses each entry and updates the baseline and last-state indexes. Managed code only: no
// P/Invoke, processes, registry, network or file access (the caller reads the file and passes the
// text). PowerShell alone missed the "10,000 entries in under 1 s" budget in a loaded process.
// C# 5 (Windows PowerShell 5.1 Add-Type).

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace IgwtJournal
{
    // Chain state carried from segment to segment. Reason codes: chain, invalid, seq, torn.
    public sealed class ChainState
    {
        public string Hash = "";
        public long Seq;
        public bool HasTorn;
        public string TornHash = "";
        public int TornLine;
        public string Status = "";
        public string Reason = "";
        public int BadLine;
        public long FoundSeq;
        public int SegmentLines;
        public bool TornPending;
        public string PendingHash = "";
        public bool NeedsBreak;
    }

    // Canonical JSON for comparing values (ConvertTo-IgwtCanonicalJson): object keys sorted
    // ordinally, every number in invariant decimal form without trailing zeros, dates in UTC
    // round-trip form, anything else as its string. The same value captured live (hashtables,
    // PSCustomObject) and read back from the journal (dictionaries) gives the same text.
    public static class Canonical
    {
        public static string ToJson(object value)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, value, 0);
            return sb.ToString();
        }

        static void Write(StringBuilder sb, object v, int depth)
        {
            if (depth > 40) { sb.Append("null"); return; }
            System.Management.Automation.PSObject pso = v as System.Management.Automation.PSObject;
            if (pso != null && !(pso.BaseObject is System.Management.Automation.PSCustomObject)) { v = pso.BaseObject; pso = null; }
            if (v == null) { sb.Append("null"); return; }
            if (v is string) { Str(sb, (string)v); return; }
            if (v is char) { Str(sb, v.ToString()); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is DateTime) { Str(sb, ((DateTime)v).ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)); return; }
            if (v is byte || v is sbyte || v is short || v is ushort || v is int || v is uint || v is long || v is ulong || v is decimal)
            {
                sb.Append(Convert.ToDecimal(v, CultureInfo.InvariantCulture).ToString("G29", CultureInfo.InvariantCulture)); return;
            }
            if (v is double || v is float)
            {
                double d = Convert.ToDouble(v, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d) || Math.Abs(d) > 7.9e27) { Str(sb, d.ToString("R", CultureInfo.InvariantCulture)); return; }
                sb.Append(((decimal)d).ToString("G29", CultureInfo.InvariantCulture)); return;
            }
            if (pso != null)
            {
                SortedDictionary<string, object> props = new SortedDictionary<string, object>(StringComparer.Ordinal);
                foreach (System.Management.Automation.PSPropertyInfo p in pso.Properties) { props[p.Name] = p.Value; }
                Obj(sb, props, depth); return;
            }
            System.Collections.IDictionary dict = v as System.Collections.IDictionary;
            if (dict != null)
            {
                SortedDictionary<string, object> keys = new SortedDictionary<string, object>(StringComparer.Ordinal);
                foreach (System.Collections.DictionaryEntry de in dict) { keys[Convert.ToString(de.Key, CultureInfo.InvariantCulture)] = de.Value; }
                Obj(sb, keys, depth); return;
            }
            System.Collections.IEnumerable list = v as System.Collections.IEnumerable;
            if (list != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object x in list) { if (!first) { sb.Append(','); } first = false; Write(sb, x, depth + 1); }
                sb.Append(']'); return;
            }
            Str(sb, Convert.ToString(v, CultureInfo.InvariantCulture));
        }

        static void Obj(StringBuilder sb, SortedDictionary<string, object> map, int depth)
        {
            sb.Append('{');
            bool first = true;
            foreach (KeyValuePair<string, object> kv in map) { if (!first) { sb.Append(','); } first = false; Str(sb, kv.Key); sb.Append(':'); Write(sb, kv.Value, depth + 1); }
            sb.Append('}');
        }

        static void Str(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                if (c == '"') { sb.Append("\\\""); }
                else if (c == '\\') { sb.Append("\\\\"); }
                else if (c < (char)0x20 || c == (char)0x2028 || c == (char)0x2029) { sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); }
                else { sb.Append(c); }
            }
            sb.Append('"');
        }
    }

    public static class Verifier
    {
        static readonly string[] LastKinds = new string[] { "committed", "reverted", "retired", "adopted", "rolledBack" };

        public static string HashLine(string line)
        {
            using (SHA256 sha = SHA256.Create()) { return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(line))); }
        }

        static string Hex(byte[] b)
        {
            StringBuilder sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) { sb.Append(x.ToString("x2", CultureInfo.InvariantCulture)); }
            return sb.ToString();
        }

        static Dictionary<string, object> Parse(JavaScriptSerializer ser, string line)
        {
            try { return ser.DeserializeObject(line) as Dictionary<string, object>; }
            catch (ArgumentException) { return null; }
            catch (InvalidOperationException) { return null; }
        }

        static string Str(Dictionary<string, object> e, string name)
        {
            object v;
            if (e.TryGetValue(name, out v) && v != null) { return Convert.ToString(v, CultureInfo.InvariantCulture); }
            return "";
        }

        static void Fail(ChainState st, string reason, int line)
        {
            st.Status = "Broken"; st.Reason = reason; st.BadLine = line;
        }

        // Verifies one segment. entries may be null (verify and index only). Returns false on a break.
        public static bool VerifySegment(string text, bool isLastSegment, ChainState st, List<object> entries,
            Dictionary<string, object> baselines, Dictionary<string, object> last)
        {
            JavaScriptSerializer ser = new JavaScriptSerializer();
            ser.MaxJsonLength = int.MaxValue;
            bool endsWithBreak = text.Length == 0 || text[text.Length - 1] == '\n';
            string[] lines = text.Split('\n');
            int count = lines.Length;
            if (endsWithBreak) { count--; }
            int segLines = 0;
            using (SHA256 sha = SHA256.Create())
            {
                for (int i = 0; i < count; i++)
                {
                    string line = lines[i].TrimEnd('\r');
                    int lineNo = i + 1;
                    bool isLast = isLastSegment && i == count - 1;
                    string prefix = "{\"prev\":\"" + st.Hash + "\"";
                    if (!line.StartsWith(prefix, StringComparison.Ordinal))
                    {
                        // A torn write: an unterminated last line, or a malformed line that the next line's chainNote names.
                        string lh = Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(line)));
                        if (isLast && !endsWithBreak) { st.TornPending = true; st.PendingHash = lh; continue; }
                        if (!st.HasTorn && Parse(ser, line) == null) { st.HasTorn = true; st.TornHash = lh; st.TornLine = lineNo; continue; }
                        Fail(st, "chain", lineNo); return false;
                    }
                    Dictionary<string, object> e = Parse(ser, line);
                    if (e == null) { Fail(st, "invalid", lineNo); return false; }
                    string kind = Str(e, "kind");
                    if (st.HasTorn)
                    {
                        if (kind != "chainNote" || Str(e, "torn") != st.TornHash) { Fail(st, "torn", st.TornLine); return false; }
                        st.HasTorn = false;
                    }
                    long expect = st.Seq + 1;
                    long seq;
                    if (!long.TryParse(Str(e, "seq"), NumberStyles.Integer, CultureInfo.InvariantCulture, out seq) || seq != expect)
                    {
                        st.FoundSeq = seq; Fail(st, "seq", lineNo); return false;
                    }
                    st.Seq = expect;
                    st.Hash = Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(line)));
                    segLines++;
                    object t;
                    Dictionary<string, object> target = (e.TryGetValue("target", out t) ? t as Dictionary<string, object> : null);
                    if (target != null)
                    {
                        string key = Str(target, "key");
                        if (key.Length > 0)
                        {
                            if (kind == "baseline" && !baselines.ContainsKey(key)) { baselines[key] = e; }
                            if (Array.IndexOf(LastKinds, kind) >= 0) { last[key] = e; }
                        }
                    }
                    if (entries != null) { entries.Add(e); }
                }
            }
            st.SegmentLines = segLines;
            if (isLastSegment) { st.NeedsBreak = !endsWithBreak && !st.TornPending; }
            return true;
        }
    }
}
