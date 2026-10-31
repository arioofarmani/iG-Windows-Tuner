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
