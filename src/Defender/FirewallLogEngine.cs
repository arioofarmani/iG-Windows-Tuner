// FirewallLogEngine.cs
// Parser, live tail, query and aggregates for the Windows Firewall log (pfirewall.log), loaded
// with Add-Type -Path by Initialize-IgwtFirewallLogEngine (src\Defender\FirewallLog.ps1).
// Managed code only: no P/Invoke, no unsafe code, no process, registry or network access, and it
// never writes a file. It exists because PowerShell alone parsed a 32 MB log in 29 s and filtered
// 300,000 rows in 3 to 8 s, far over the 3.5 budgets (DECISIONS F11).
// C# 5 only (the compiler of Windows PowerShell 5.1): no string interpolation, no ?. operator.
// Every field value comes from the network and is untrusted: it is kept as plain text.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;

namespace IgwtFirewallLog
{
    public sealed class Entry
    {
        public long Id { get; set; }
        public DateTime? Time { get; set; }
        public string TimeText { get; set; }
        public string TimeUtcText { get; set; }
        public string Action { get; set; }
        public string Protocol { get; set; }
        public string Source { get; set; }
        public string Destination { get; set; }
        public string SourcePort { get; set; }
        public string DestinationPort { get; set; }
        public string Size { get; set; }
        public string TcpFlags { get; set; }
        public string Info { get; set; }
        // The raw "path" field as written in the log (SEND, RECEIVE, ...; DECISIONS F10).
        public string Direction { get; set; }
        public string ProcessId { get; set; }
        public string Process { get; set; }
        public string Rule { get; set; }
        public string Note { get; set; }
        public string File { get; set; }
        public long Line { get; set; }
        public int SourcePortNumber { get; set; }
        public int DestinationPortNumber { get; set; }
        public long SizeNumber { get; set; }
        public int Pid { get; set; }
        internal byte[] SourceBytes;
        internal byte[] DestinationBytes;
        internal bool BytesParsed;
    }

    public sealed class ParseResult
    {
        public string[] Fields { get; set; }
        public List<Entry> Entries { get; set; }
        public Dictionary<string, int> Skipped { get; set; }
        public long EndOffset { get; set; }
        public long Length { get; set; }
        public bool TimeIsUtc { get; set; }
        public bool Cancelled { get; set; }
    }

    public sealed class CancelFlag
    {
        private volatile bool cancelled;
        public bool Cancelled { get { return cancelled; } }
        public void Cancel() { cancelled = true; }
    }

    public static class Parser
    {
        private static readonly char[] Separators = new char[] { ' ', '\t' };
        // Real log lines are a few hundred bytes; anything longer is not parsed and not kept in memory.
        public const int MaxLineBytes = 65536;
        private static long nextId;

        public static FileStream OpenShared(string path)
        {
            // The firewall service keeps writing (and may rotate) the file: share read, write and delete.
            return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
        }

        // Parses complete lines from 'offset'. A last line without a line break is not consumed:
        // EndOffset stays at its start, so a live tail reads it again once it is complete. When
        // 'final' is true such a line is counted as Partial. 'fields' continues an earlier read
        // (null: the #Fields header in this text decides).
        public static ParseResult Parse(Stream stream, long offset, string[] fields, bool timeIsUtc, string file, bool final, CancelFlag cancel)
        {
            return ParseCore(stream, offset, fields, timeIsUtc, file, final, cancel, false);
        }

        // The header of a log: the #Fields and #Time Format lines at its start (first 64 KB).
        public static ParseResult ReadHeader(Stream stream)
        {
            ParseResult h = new ParseResult();
            stream.Seek(0, SeekOrigin.Begin);
            byte[] buf = new byte[65536];
            int n = stream.Read(buf, 0, buf.Length);
            string text = Encoding.UTF8.GetString(buf, 0, n);
            foreach (string raw in text.Split('\n'))
            {
                string line = raw.TrimEnd('\r');
                if (line.Length == 0) { continue; }
                if (line[0] != '#') { break; }
                if (line.StartsWith("#Fields:", StringComparison.Ordinal)) { h.Fields = line.Substring(8).Split(Separators, StringSplitOptions.RemoveEmptyEntries); }
                else if (line.StartsWith("#Time Format:", StringComparison.OrdinalIgnoreCase)) { h.TimeIsUtc = line.Substring(13).Trim().Equals("UTC", StringComparison.OrdinalIgnoreCase); }
            }
            return h;
        }

        // The newest entries only: the last 'bytes' of the file, starting at the next full line,
        // so the first rows show at once while the whole file is read.
        public static ParseResult ParseTail(Stream stream, long bytes, string file)
        {
            ParseResult h = ReadHeader(stream);
            long start = Math.Max(0L, stream.Length - Math.Max(4096L, bytes));
            return ParseCore(stream, start, h.Fields, h.TimeIsUtc, file, true, null, start > 0);
        }

        private static ParseResult ParseCore(Stream stream, long offset, string[] fields, bool timeIsUtc, string file, bool final, CancelFlag cancel, bool skipToLine)
        {
            ParseResult r = new ParseResult();
            r.Skipped = new Dictionary<string, int>();
            r.Skipped["Empty"] = 0; r.Skipped["NoHeader"] = 0; r.Skipped["FieldCount"] = 0; r.Skipped["Partial"] = 0; r.Skipped["TooLong"] = 0;
            bool overlong = false; long dropped = 0;
            r.Fields = fields;
            r.TimeIsUtc = timeIsUtc;
            long length = stream.Length;
            r.Length = length;
            int capacity = (int)Math.Min(4000000L, Math.Max(1024L, (length - offset) / 100L));
            r.Entries = new List<Entry>(capacity);
            stream.Seek(offset, SeekOrigin.Begin);
            Dictionary<string, int> ix = Index(fields);
            byte[] buf = new byte[1 << 20];
            byte[] carry = new byte[0];
            int carryLen = 0;
            long consumed = offset;
            long lineNo = 0;
            int read;
            Dictionary<string, string> pool = new Dictionary<string, string>(StringComparer.Ordinal);
            while ((read = stream.Read(buf, 0, buf.Length)) > 0)
            {
                if (cancel != null && cancel.Cancelled) { r.Cancelled = true; break; }
                int start = 0;
                if (skipToLine)
                {
                    // Started inside a line: drop the bytes up to the next line break.
                    int nl = Array.IndexOf(buf, (byte)10, 0, read);
                    if (nl < 0) { consumed += read; continue; }
                    consumed += nl + 1; start = nl + 1; skipToLine = false;
                }
                for (int i = start; i < read; i++)
                {
                    if (buf[i] != 10) { continue; }
                    string line;
                    if (overlong || carryLen + (i - start) > MaxLineBytes)
                    {
                        // A line longer than any real log line (or a damaged, zero-filled region): skipped and counted.
                        consumed += dropped + carryLen + (i - start) + 1;
                        dropped = 0; carryLen = 0; overlong = false;
                        lineNo++;
                        r.Skipped["TooLong"]++;
                        start = i + 1;
                        continue;
                    }
                    if (carryLen > 0)
                    {
                        byte[] joined = new byte[carryLen + (i - start)];
                        Buffer.BlockCopy(carry, 0, joined, 0, carryLen);
                        Buffer.BlockCopy(buf, start, joined, carryLen, i - start);
                        line = Encoding.UTF8.GetString(joined);
                        consumed += joined.Length + 1;
                        carryLen = 0;
                    }
                    else
                    {
                        line = Encoding.UTF8.GetString(buf, start, i - start);
                        consumed += (i - start) + 1;
                    }
                    lineNo++;
                    HandleLine(line.TrimEnd('\r'), r, ref fields, ref ix, file, lineNo, pool);
                    start = i + 1;
                }
                int rest = read - start;
                if (rest > 0 && (overlong || carryLen + rest > MaxLineBytes))
                {
                    // Keep no more than one line's worth in memory: count the bytes, drop them.
                    dropped += carryLen + rest; carryLen = 0; overlong = true;
                }
                else if (rest > 0)
                {
                    if (carry.Length < carryLen + rest) { byte[] bigger = new byte[Math.Max(carry.Length * 2, carryLen + rest)]; Buffer.BlockCopy(carry, 0, bigger, 0, carryLen); carry = bigger; }
                    Buffer.BlockCopy(buf, start, carry, carryLen, rest);
                    carryLen += rest;
                }
            }
            if (overlong && final) { r.Skipped["TooLong"]++; }
            else if (carryLen > 0)
            {
                string tail = Encoding.UTF8.GetString(carry, 0, carryLen);
                if (tail.Trim().Length > 0 && final) { r.Skipped["Partial"]++; }
            }
            r.EndOffset = consumed;
            r.Fields = fields;
            return r;
        }

        private static Dictionary<string, int> Index(string[] fields)
        {
            Dictionary<string, int> ix = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (fields == null) { return ix; }
            for (int i = 0; i < fields.Length; i++) { ix[fields[i]] = i; }
            return ix;
        }

        // Values repeat a lot (actions, addresses, ports, flags): one string per distinct value
        // saves memory and lets a search test each distinct value once.
        private static string Get(string[] p, Dictionary<string, int> ix, string name, Dictionary<string, string> pool)
        {
            int i;
            if (!ix.TryGetValue(name, out i) || i >= p.Length) { return string.Empty; }
            string v = p[i];
            if (v == "-") { return string.Empty; }
            string pooled;
            if (pool.TryGetValue(v, out pooled)) { return pooled; }
            if (pool.Count < 500000) { pool[v] = v; }
            return v;
        }

        private static void HandleLine(string line, ParseResult r, ref string[] fields, ref Dictionary<string, int> ix, string file, long lineNo, Dictionary<string, string> pool)
        {
            if (line.Trim().Length == 0) { r.Skipped["Empty"]++; return; }
            if (line[0] == '#')
            {
                if (line.StartsWith("#Fields:", StringComparison.Ordinal))
                {
                    fields = line.Substring(8).Split(Separators, StringSplitOptions.RemoveEmptyEntries);
                    ix = Index(fields);
                }
                else if (line.StartsWith("#Time Format:", StringComparison.OrdinalIgnoreCase))
                {
                    // Seen values: Local. UTC is handled in case Windows writes it (UNVERIFIED, DECISIONS F11).
                    r.TimeIsUtc = line.Substring(13).Trim().Equals("UTC", StringComparison.OrdinalIgnoreCase);
                }
                return;
            }
            if (fields == null) { r.Skipped["NoHeader"]++; return; }
            string[] p = line.Split(Separators, StringSplitOptions.RemoveEmptyEntries);
            if (p.Length != fields.Length) { r.Skipped["FieldCount"]++; return; }
            Entry e = new Entry();
            e.Id = System.Threading.Interlocked.Increment(ref nextId);
            e.File = file; e.Line = lineNo;
            string d = Get(p, ix, "date", pool), t = Get(p, ix, "time", pool);
            DateTime dt;
            if (d.Length > 0 && t.Length > 0 && DateTime.TryParseExact(d + " " + t, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
            {
                bool utc = r.TimeIsUtc;
                DateTime local = utc ? DateTime.SpecifyKind(dt, DateTimeKind.Utc).ToLocalTime() : DateTime.SpecifyKind(dt, DateTimeKind.Local);
                e.Time = local;
                e.TimeText = local.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
                e.TimeUtcText = local.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
            }
            else { e.TimeText = string.Empty; e.TimeUtcText = string.Empty; }
            e.Action = Get(p, ix, "action", pool);
            e.Protocol = Get(p, ix, "protocol", pool);
            e.Source = Get(p, ix, "src-ip", pool);
            e.Destination = Get(p, ix, "dst-ip", pool);
            e.SourcePort = Get(p, ix, "src-port", pool);
            e.DestinationPort = Get(p, ix, "dst-port", pool);
            e.Size = Get(p, ix, "size", pool);
            e.TcpFlags = Get(p, ix, "tcpflags", pool);
            e.Info = Get(p, ix, "info", pool);
            e.Direction = Get(p, ix, "path", pool);
            e.ProcessId = Get(p, ix, "pid", pool);
            e.Process = string.Empty; e.Rule = string.Empty; e.Note = string.Empty;
            int n; long l;
            e.SourcePortNumber = int.TryParse(e.SourcePort, NumberStyles.None, CultureInfo.InvariantCulture, out n) ? n : -1;
            e.DestinationPortNumber = int.TryParse(e.DestinationPort, NumberStyles.None, CultureInfo.InvariantCulture, out n) ? n : -1;
            e.Pid = int.TryParse(e.ProcessId, NumberStyles.None, CultureInfo.InvariantCulture, out n) ? n : -1;
            e.SizeNumber = long.TryParse(e.Size, NumberStyles.None, CultureInfo.InvariantCulture, out l) ? l : -1;
            r.Entries.Add(e);
        }
    }

    // Follows a log: reads only the bytes appended since the last read, and starts over when the
    // file was rotated (it is shorter than the last offset, or a different file).
    public sealed class Tail
    {
        public string Path { get; private set; }
        public long Offset { get; private set; }
        public string[] Fields { get; private set; }
        public bool TimeIsUtc { get; private set; }
        public int Rotations { get; private set; }
        private DateTime created;

        public Tail(string path, long offset, string[] fields, bool timeIsUtc)
        {
            Path = path; Offset = offset; Fields = fields; TimeIsUtc = timeIsUtc;
            try { created = System.IO.File.GetCreationTimeUtc(path); } catch (IOException) { created = DateTime.MinValue; } catch (UnauthorizedAccessException) { created = DateTime.MinValue; }
        }

        public ParseResult Poll()
        {
            using (FileStream fs = Parser.OpenShared(Path))
            {
                DateTime c = DateTime.MinValue;
                try { c = System.IO.File.GetCreationTimeUtc(Path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
                bool rotated = fs.Length < Offset || (created != DateTime.MinValue && c != DateTime.MinValue && c != created);
                if (rotated) { Offset = 0; Fields = null; Rotations++; created = c; }
                ParseResult r = Parser.Parse(fs, Offset, Fields, TimeIsUtc, Path, false, null);
                Offset = r.EndOffset; Fields = r.Fields; TimeIsUtc = r.TimeIsUtc;
                return r;
            }
        }
    }

    public sealed class Query
    {
        public string Search { get; set; }
        public string[] Actions { get; set; }
        public string[] Directions { get; set; }
        public string[] Protocols { get; set; }
        public int[] Ports { get; set; }
        // Exact address or CIDR (a.b.c.d/n, IPv6 too); matches source or destination.
        public string Address { get; set; }
        public string Process { get; set; }
        public DateTime? From { get; set; }
        public DateTime? To { get; set; }
        public bool NotesOnly { get; set; }
        public Dictionary<string, string[]> Columns { get; set; }
        public string[] SortKeys { get; set; }
        public bool[] SortDescending { get; set; }
    }

    public sealed class Count
    {
        public string Value { get; set; }
        public long Hits { get; set; }
        public long Bytes { get; set; }
    }

    public sealed class Bucket
    {
        public DateTime Start { get; set; }
        public long Dropped { get; set; }
        public long Allowed { get; set; }
    }

    public static class Engine
    {
        public static string Get(Entry e, string key)
        {
            switch (key)
            {
                case "Time": case "TimeText": return e.TimeText;
                case "TimeUtc": case "TimeUtcText": return e.TimeUtcText;
                case "File": return e.File;
                case "Line": return e.Line.ToString(CultureInfo.InvariantCulture);
                case "Action": return e.Action;
                case "Protocol": return e.Protocol;
                case "Source": return e.Source;
                case "Destination": return e.Destination;
                case "SourcePort": return e.SourcePort;
                case "DestinationPort": return e.DestinationPort;
                case "Size": return e.Size;
                case "TcpFlags": return e.TcpFlags;
                case "Info": return e.Info;
                case "Direction": return e.Direction;
                case "ProcessId": return e.ProcessId;
                case "Process": return e.Process;
                case "Rule": return e.Rule;
                case "Note": return e.Note;
                case "Remote": return e.Direction == "SEND" ? e.Destination : e.Source;
                case "Port": return e.Protocol + "/" + e.DestinationPort;
                default: return string.Empty;
            }
        }

        // The fields a search looks in (by number: a string switch per value was the slow part).
        private const int SearchFieldCount = 14;
        private static string SearchField(Entry e, int k)
        {
            switch (k)
            {
                case 0: return e.Action;
                case 1: return e.Protocol;
                case 2: return e.Source;
                case 3: return e.Destination;
                case 4: return e.DestinationPort;
                case 5: return e.SourcePort;
                case 6: return e.Direction;
                case 7: return e.ProcessId;
                case 8: return e.Process;
                case 9: return e.Rule;
                case 10: return e.Info;
                case 11: return e.TcpFlags;
                case 12: return e.Note;
                default: return e.TimeText;
            }
        }

        private static long NumericKey(Entry e, string key)
        {
            switch (key)
            {
                case "Time": case "TimeText": return e.Time.HasValue ? e.Time.Value.Ticks : long.MinValue;
                case "SourcePort": return e.SourcePortNumber;
                case "DestinationPort": return e.DestinationPortNumber;
                case "Size": return e.SizeNumber;
                case "ProcessId": return e.Pid;
                default: return long.MinValue;
            }
        }

        private static bool IsNumeric(string key)
        {
            return key == "Time" || key == "TimeText" || key == "SourcePort" || key == "DestinationPort" || key == "Size" || key == "ProcessId";
        }

        private static HashSet<string> Set(string[] values)
        {
            if (values == null || values.Length == 0) { return null; }
            return new HashSet<string>(values, StringComparer.OrdinalIgnoreCase);
        }

        public static bool TryParseNetwork(string text, out byte[] network, out int prefix)
        {
            network = null; prefix = -1;
            if (string.IsNullOrEmpty(text)) { return false; }
            string a = text.Trim(); int slash = a.IndexOf('/');
            string addr = slash >= 0 ? a.Substring(0, slash) : a;
            IPAddress ip;
            if (!IPAddress.TryParse(addr, out ip)) { return false; }
            network = ip.GetAddressBytes();
            prefix = network.Length * 8;
            if (slash >= 0)
            {
                int p;
                if (!int.TryParse(a.Substring(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out p) || p < 0 || p > network.Length * 8) { return false; }
                prefix = p;
            }
            return true;
        }

        public static bool InNetwork(byte[] address, byte[] network, int prefix)
        {
            if (address == null || network == null || address.Length != network.Length) { return false; }
            int full = prefix / 8, bits = prefix % 8;
            for (int i = 0; i < full; i++) { if (address[i] != network[i]) { return false; } }
            if (bits == 0) { return true; }
            int mask = (0xFF << (8 - bits)) & 0xFF;
            return (address[full] & mask) == (network[full] & mask);
        }

        private static void EnsureBytes(Entry e)
        {
            if (e.BytesParsed) { return; }
            IPAddress ip;
            e.SourceBytes = IPAddress.TryParse(e.Source, out ip) ? ip.GetAddressBytes() : null;
            e.DestinationBytes = IPAddress.TryParse(e.Destination, out ip) ? ip.GetAddressBytes() : null;
            e.BytesParsed = true;
        }

        // Filters and sorts. Search: every word must appear in one of the text fields (case-insensitive).
        public static Entry[] Run(IList<Entry> all, Query q)
        {
            if (q == null) { q = new Query(); }
            HashSet<string> actions = Set(q.Actions), dirs = Set(q.Directions), protos = Set(q.Protocols);
            HashSet<int> ports = (q.Ports == null || q.Ports.Length == 0) ? null : new HashSet<int>(q.Ports);
            string[] words = string.IsNullOrEmpty(q.Search) ? new string[0] : q.Search.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            byte[] net = null; int prefix = -1; bool hasNet = false;
            if (!string.IsNullOrEmpty(q.Address))
            {
                hasNet = true;
                if (!TryParseNetwork(q.Address, out net, out prefix)) { return new Entry[0]; }
            }
            List<KeyValuePair<string, HashSet<string>>> cols = new List<KeyValuePair<string, HashSet<string>>>();
            if (q.Columns != null) { foreach (KeyValuePair<string, string[]> kv in q.Columns) { HashSet<string> s = Set(kv.Value); if (s != null) { cols.Add(new KeyValuePair<string, HashSet<string>>(kv.Key, s)); } } }
            string proc = string.IsNullOrEmpty(q.Process) ? null : q.Process;
            List<Entry> hits = new List<Entry>(all.Count);
            // Per word: whether a distinct value contains it (values are pooled, so each is tested once).
            Dictionary<string, bool>[] memo = new Dictionary<string, bool>[words.Length];
            for (int w = 0; w < words.Length; w++) { memo[w] = new Dictionary<string, bool>(StringComparer.Ordinal); }
            for (int i = 0; i < all.Count; i++)
            {
                Entry e = all[i];
                if (actions != null && !actions.Contains(e.Action)) { continue; }
                if (dirs != null && !dirs.Contains(e.Direction)) { continue; }
                if (protos != null && !protos.Contains(e.Protocol)) { continue; }
                if (ports != null && !ports.Contains(e.DestinationPortNumber) && !ports.Contains(e.SourcePortNumber)) { continue; }
                if (q.From.HasValue && (!e.Time.HasValue || e.Time.Value < q.From.Value)) { continue; }
                if (q.To.HasValue && (!e.Time.HasValue || e.Time.Value > q.To.Value)) { continue; }
                if (q.NotesOnly && string.IsNullOrEmpty(e.Note)) { continue; }
                if (proc != null && e.Process.IndexOf(proc, StringComparison.OrdinalIgnoreCase) < 0 && e.ProcessId != proc) { continue; }
                if (hasNet) { EnsureBytes(e); if (!InNetwork(e.SourceBytes, net, prefix) && !InNetwork(e.DestinationBytes, net, prefix)) { continue; } }
                bool ok = true;
                for (int c = 0; c < cols.Count && ok; c++) { ok = cols[c].Value.Contains(Get(e, cols[c].Key)); }
                if (!ok) { continue; }
                for (int w = 0; w < words.Length && ok; w++)
                {
                    bool found = false;
                    for (int k = 0; k < SearchFieldCount; k++)
                    {
                        string v = SearchField(e, k);
                        if (v == null || v.Length == 0) { continue; }
                        bool has;
                        if (!memo[w].TryGetValue(v, out has)) { has = v.IndexOf(words[w], StringComparison.OrdinalIgnoreCase) >= 0; memo[w][v] = has; }
                        if (has) { found = true; break; }
                    }
                    ok = found;
                }
                if (ok) { hits.Add(e); }
            }
            Entry[] result = hits.ToArray();
            Sort(result, q.SortKeys, q.SortDescending);
            return result;
        }

        // Replaces the values by their dense rank (0 = smallest, equal values share a rank); returns the largest rank.
        private static long DenseRank(long[] values)
        {
            long[] sorted = (long[])values.Clone();
            Array.Sort(sorted);
            int m = 0;
            for (int i = 1; i < sorted.Length; i++) { if (sorted[i] != sorted[m]) { sorted[++m] = sorted[i]; } }
            for (int i = 0; i < values.Length; i++) { values[i] = Array.BinarySearch(sorted, 0, m + 1, values[i]); }
            return m;
        }

        public static void Sort(Entry[] rows, string[] keys, bool[] descending)
        {
            if (keys == null || keys.Length == 0 || rows.Length < 2) { return; }
            int n = rows.Length, levels = keys.Length;
            long[][] num = new long[levels][];
            long[] max = new long[levels];
            for (int l = 0; l < levels; l++)
            {
                if (IsNumeric(keys[l])) { num[l] = new long[n]; for (int i = 0; i < n; i++) { num[l][i] = NumericKey(rows[i], keys[l]); } max[l] = DenseRank(num[l]); }
                else
                {
                    // Text keys sort by rank: each distinct value is compared once, rows compare integers.
                    // The ranks are dense already (0 .. distinct - 1), so no second ranking pass is needed.
                    Dictionary<string, long> rank = new Dictionary<string, long>(StringComparer.Ordinal);
                    for (int i = 0; i < n; i++) { rank[Get(rows[i], keys[l]) ?? string.Empty] = 0; }
                    string[] distinct = new string[rank.Count];
                    rank.Keys.CopyTo(distinct, 0);
                    Array.Sort(distinct, StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < distinct.Length; i++) { rank[distinct[i]] = i; }
                    num[l] = new long[n];
                    for (int i = 0; i < n; i++) { num[l][i] = rank[Get(rows[i], keys[l]) ?? string.Empty]; }
                    max[l] = Math.Max(0, distinct.Length - 1);
                }
            }
            int[] order = new int[n];
            for (int i = 0; i < n; i++) { order[i] = i; }
            // Fast path: every level as a dense rank, packed with the row position into one 64-bit key
            // (descending levels inverted), then a primitive sort without a comparison delegate.
            double room = n;
            for (int l = 0; l < levels; l++) { room *= (max[l] + 1); }
            if (room < 9.0e18)
            {
                long[] composite = new long[n];
                for (int i = 0; i < n; i++)
                {
                    long k = 0;
                    for (int l = 0; l < levels; l++)
                    {
                        long r = num[l][i];
                        if (descending != null && l < descending.Length && descending[l]) { r = max[l] - r; }
                        k = k * (max[l] + 1) + r;
                    }
                    composite[i] = k * n + i;
                }
                Array.Sort(composite, order);
                Entry[] packed = (Entry[])rows.Clone();
                for (int i = 0; i < n; i++) { rows[i] = packed[order[i]]; }
                return;
            }
            Array.Sort(order, delegate(int a, int b)
            {
                for (int l = 0; l < levels; l++)
                {
                    int c = num[l][a].CompareTo(num[l][b]);
                    if (c != 0) { return (descending != null && l < descending.Length && descending[l]) ? -c : c; }
                }
                return a.CompareTo(b);
            });
            Entry[] copy = (Entry[])rows.Clone();
            for (int i = 0; i < n; i++) { rows[i] = copy[order[i]]; }
        }

        // The most frequent values of a key (optionally only one action), with the bytes they carried.
        public static Count[] Top(IList<Entry> rows, string key, string action, int top)
        {
            Dictionary<string, Count> map = new Dictionary<string, Count>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < rows.Count; i++)
            {
                Entry e = rows[i];
                if (!string.IsNullOrEmpty(action) && !string.Equals(e.Action, action, StringComparison.OrdinalIgnoreCase)) { continue; }
                string v = Get(e, key);
                if (string.IsNullOrEmpty(v) || v == "/") { continue; }
                Count c;
                if (!map.TryGetValue(v, out c)) { c = new Count(); c.Value = v; map[v] = c; }
                c.Hits++;
                if (e.SizeNumber > 0) { c.Bytes += e.SizeNumber; }
            }
            List<Count> list = new List<Count>(map.Values);
            list.Sort(delegate(Count a, Count b) { int x = b.Hits.CompareTo(a.Hits); return x != 0 ? x : string.CompareOrdinal(a.Value, b.Value); });
            if (top > 0 && list.Count > top) { list.RemoveRange(top, list.Count - top); }
            return list.ToArray();
        }

        // Events over time in buckets of 'minutes' minutes (dropped and allowed per bucket).
        public static Bucket[] Histogram(IList<Entry> rows, int minutes)
        {
            if (minutes < 1) { minutes = 60; }
            long size = TimeSpan.FromMinutes(minutes).Ticks;
            SortedDictionary<long, Bucket> map = new SortedDictionary<long, Bucket>();
            for (int i = 0; i < rows.Count; i++)
            {
                Entry e = rows[i];
                if (!e.Time.HasValue) { continue; }
                long k = e.Time.Value.Ticks / size * size;
                Bucket b;
                if (!map.TryGetValue(k, out b)) { b = new Bucket(); b.Start = new DateTime(k, DateTimeKind.Local); map[k] = b; }
                if (string.Equals(e.Action, "DROP", StringComparison.OrdinalIgnoreCase)) { b.Dropped++; } else if (string.Equals(e.Action, "ALLOW", StringComparison.OrdinalIgnoreCase)) { b.Allowed++; }
            }
            Bucket[] result = new Bucket[map.Count];
            map.Values.CopyTo(result, 0);
            return result;
        }

        // Fills Process from a pid -> name map (best effort: process ids are reused after a process
        // ends, so a name is the process that has the id now). Ids not in the map get 'missing'
        // with the id in {0}.
        public static int SetProcessNames(IList<Entry> rows, IDictionary<int, string> names, string missing)
        {
            int hits = 0;
            for (int i = 0; i < rows.Count; i++)
            {
                Entry e = rows[i];
                if (e.Pid < 0) { continue; }
                string n;
                if (names != null && names.TryGetValue(e.Pid, out n)) { e.Process = n; hits++; }
                else if (!string.IsNullOrEmpty(missing)) { e.Process = string.Format(CultureInfo.InvariantCulture, missing, e.Pid); }
            }
            return hits;
        }

        // A CSV cell: quoted, and a value starting with = + - @, a tab or a carriage return gets a
        // leading apostrophe so a spreadsheet does not run it as a formula (same rule as
        // Protect-IgwtCsvValue in src\Core\Export.ps1).
        public static string CsvCell(string v)
        {
            if (v == null) { v = string.Empty; }
            if (v.Length > 0 && (v[0] == '=' || v[0] == '+' || v[0] == '-' || v[0] == '@' || v[0] == '\t' || v[0] == '\r')) { v = "'" + v; }
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        }

        // CSV lines (header first) of the rows; the caller writes them to the file the user chose.
        public static string[] CsvLines(IList<Entry> rows, string[] keys, string[] headers)
        {
            string[] lines = new string[rows.Count + 1];
            StringBuilder sb = new StringBuilder(256);
            for (int k = 0; k < keys.Length; k++) { if (k > 0) { sb.Append(','); } sb.Append(CsvCell(headers != null && k < headers.Length ? headers[k] : keys[k])); }
            lines[0] = sb.ToString();
            for (int i = 0; i < rows.Count; i++)
            {
                sb.Length = 0;
                for (int k = 0; k < keys.Length; k++) { if (k > 0) { sb.Append(','); } sb.Append(CsvCell(Get(rows[i], keys[k]))); }
                lines[i + 1] = sb.ToString();
            }
            return lines;
        }

        // A JSON string literal (quotes, backslashes and control characters escaped).
        public static string JsonString(string v)
        {
            if (v == null) { return "null"; }
            StringBuilder sb = new StringBuilder(v.Length + 2);
            sb.Append('"');
            foreach (char ch in v)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        // (char)0x2028 and 0x2029 are line and paragraph separators; written as numbers
                        // because the C# compiler turns a \u escape into the character before parsing.
                        if (ch < 0x20 || ch == (char)0x2028 || ch == (char)0x2029) { sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture)); }
                        else { sb.Append(ch); }
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        // One JSON object per row ({"header": "value", ...}).
        public static string JsonObject(Entry e, string[] keys, string[] headers)
        {
            StringBuilder sb = new StringBuilder(256);
            sb.Append('{');
            for (int k = 0; k < keys.Length; k++)
            {
                if (k > 0) { sb.Append(','); }
                sb.Append(JsonString(headers != null && k < headers.Length ? headers[k] : keys[k])).Append(':').Append(JsonString(Get(e, keys[k])));
            }
            sb.Append('}');
            return sb.ToString();
        }

        // A JSON array of the rows, one object per line; the caller writes the lines to the file the user chose.
        public static string[] JsonArrayLines(IList<Entry> rows, string[] keys, string[] headers)
        {
            string[] lines = new string[rows.Count + 2];
            lines[0] = "[";
            for (int i = 0; i < rows.Count; i++) { lines[i + 1] = JsonObject(rows[i], keys, headers) + (i < rows.Count - 1 ? "," : string.Empty); }
            lines[rows.Count + 1] = "]";
            return lines;
        }

        // A stable key for a log entry (notes survive a new read of the same file).
        public static string NoteKey(Entry e)
        {
            return string.Join("|", new string[] { e.File ?? string.Empty, e.TimeText, e.Action, e.Protocol, e.Source, e.SourcePort, e.Destination, e.DestinationPort, e.Size, e.Direction, e.ProcessId });
        }

        // Puts the saved notes on the entries they belong to; returns how many were found.
        public static int ApplyNotes(IList<Entry> rows, IDictionary<string, string> notes)
        {
            int hits = 0;
            if (notes == null || notes.Count == 0) { return 0; }
            for (int i = 0; i < rows.Count; i++)
            {
                string n;
                if (notes.TryGetValue(NoteKey(rows[i]), out n)) { rows[i].Note = n; hits++; }
            }
            return hits;
        }

        // The distinct process ids in the rows.
        public static int[] ProcessIds(IList<Entry> rows)
        {
            HashSet<int> ids = new HashSet<int>();
            for (int i = 0; i < rows.Count; i++) { if (rows[i].Pid >= 0) { ids.Add(rows[i].Pid); } }
            int[] result = new int[ids.Count];
            ids.CopyTo(result);
            return result;
        }

        // Counts by action and the first and last time.
        public static Summary Summarize(IList<Entry> rows)
        {
            Summary s = new Summary();
            for (int i = 0; i < rows.Count; i++)
            {
                Entry e = rows[i];
                s.Entries++;
                if (string.Equals(e.Action, "DROP", StringComparison.OrdinalIgnoreCase)) { s.Dropped++; }
                else if (string.Equals(e.Action, "ALLOW", StringComparison.OrdinalIgnoreCase)) { s.Allowed++; }
                if (e.Time.HasValue)
                {
                    if (!s.From.HasValue || e.Time.Value < s.From.Value) { s.From = e.Time; }
                    if (!s.To.HasValue || e.Time.Value > s.To.Value) { s.To = e.Time; }
                }
            }
            return s;
        }
    }

    public sealed class Summary
    {
        public long Entries { get; set; }
        public long Dropped { get; set; }
        public long Allowed { get; set; }
        public DateTime? From { get; set; }
        public DateTime? To { get; set; }
    }

    // One row of the normalized forensic export (SCHEMA.md in every export). Values from the
    // network are untrusted text; rule_name and dns_name are best effort and flagged as such.
    public sealed class Row
    {
        public DateTime TimestampUtc { get; set; }
        public string Source { get; set; }
        public string Action { get; set; }
        public string Direction { get; set; }
        public string Protocol { get; set; }
        public string SrcIp { get; set; }
        public string SrcPort { get; set; }
        public string DstIp { get; set; }
        public string DstPort { get; set; }
        public long Bytes { get; set; }
        public string TcpFlags { get; set; }
        public int Pid { get; set; }
        public string ProcessPath { get; set; }
        public string ProcessName { get; set; }
        public string RuleName { get; set; }
        public string DnsName { get; set; }
        public string Notes { get; set; }
    }

    public sealed class Flow
    {
        public string ProcessName { get; set; }
        public string ProcessPath { get; set; }
        public string RemoteIp { get; set; }
        public string Port { get; set; }
        public string Protocol { get; set; }
        public DateTime FirstSeenUtc { get; set; }
        public DateTime LastSeenUtc { get; set; }
        public long Events { get; set; }
        public long Allowed { get; set; }
        public long Blocked { get; set; }
        public long Bytes { get; set; }
    }

    // Consistent keyed pseudonyms for one export: HMAC-SHA256 with a random key that is never
    // written anywhere, so the same value gets the same pseudonym within the export (correlations
    // survive) but cannot be looked up or linked across exports.
    public sealed class Redactor
    {
        private readonly System.Security.Cryptography.HMACSHA256 hmac;
        private readonly Dictionary<string, string> cache = new Dictionary<string, string>(StringComparer.Ordinal);
        public bool Enabled { get; private set; }
        public string UserName { get; set; }
        public string ComputerName { get; set; }
        public int Count { get { return cache.Count; } }

        public Redactor(bool enabled)
        {
            Enabled = enabled;
            byte[] key = new byte[32];
            using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create()) { rng.GetBytes(key); }
            hmac = new System.Security.Cryptography.HMACSHA256(key);
        }

        public string Pseudonym(string kind, string value)
        {
            if (string.IsNullOrEmpty(value)) { return value; }
            string k = kind + "|" + value.ToLowerInvariant();
            string p;
            if (cache.TryGetValue(k, out p)) { return p; }
            byte[] h = hmac.ComputeHash(Encoding.UTF8.GetBytes(k));
            StringBuilder sb = new StringBuilder(kind.Length + 13);
            sb.Append(kind).Append('-');
            for (int i = 0; i < 6; i++) { sb.Append(h[i].ToString("x2", CultureInfo.InvariantCulture)); }
            p = sb.ToString();
            cache[k] = p;
            return p;
        }

        // Internal addresses: RFC 1918, loopback, link-local, carrier-grade NAT, IPv6 unique local and link-local.
        public static bool IsInternal(string ip)
        {
            IPAddress a;
            if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip.Trim(), out a)) { return false; }
            if (a.IsIPv4MappedToIPv6) { a = a.MapToIPv4(); }
            byte[] b = a.GetAddressBytes();
            if (b.Length == 4)
            {
                return b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
            }
            if (IPAddress.IsLoopback(a) || a.IsIPv6LinkLocal || a.IsIPv6SiteLocal) { return true; }
            return (b[0] & 0xFE) == 0xFC;
        }

        // One address, or a list separated by semicolons (DNS answers): each internal address is pseudonymized.
        public string Ip(string ip)
        {
            if (!Enabled || string.IsNullOrEmpty(ip)) { return ip; }
            if (ip.IndexOf(';') >= 0)
            {
                string[] parts = ip.Split(';');
                for (int i = 0; i < parts.Length; i++) { parts[i] = Ip(parts[i]); }
                return string.Join(";", parts);
            }
            return IsInternal(ip) ? Pseudonym("ip", ip.Trim()) : ip;
        }

        // Free text (rule names, notes, messages): user folders and names, the computer name, and every
        // internal IPv4 or IPv6 address in it.
        public string Text(string text)
        {
            if (!Enabled || string.IsNullOrEmpty(text)) { return text; }
            string t = Path(text);
            StringBuilder sb = new StringBuilder(t.Length);
            int i = 0;
            while (i < t.Length)
            {
                int j = i;
                while (j < t.Length && (char.IsLetterOrDigit(t[j]) || t[j] == '.' || t[j] == ':')) { j++; }
                if (j > i)
                {
                    string tok = t.Substring(i, j - i).TrimEnd('.', ':');
                    string rest = t.Substring(i + tok.Length, j - i - tok.Length);
                    sb.Append((tok.IndexOf('.') >= 0 || tok.IndexOf(':') >= 0) && IsInternal(tok) ? Pseudonym("ip", tok) : tok).Append(rest);
                    i = j;
                }
                else { sb.Append(t[i]); i++; }
            }
            return sb.ToString();
        }

        // A user profile folder in a path (C:\Users\<name>\...) and the user name anywhere in it.
        public string Path(string path)
        {
            if (!Enabled || string.IsNullOrEmpty(path)) { return path; }
            string p = path;
            int i = p.IndexOf("\\Users\\", StringComparison.OrdinalIgnoreCase);
            if (i >= 0)
            {
                int start = i + 7, end = p.IndexOf('\\', start);
                if (end < 0) { end = p.Length; }
                string name = p.Substring(start, end - start);
                if (!name.Equals("Public", StringComparison.OrdinalIgnoreCase) && !name.Equals("Default", StringComparison.OrdinalIgnoreCase)) { p = p.Substring(0, start) + Pseudonym("user", name) + p.Substring(end); }
            }
            if (!string.IsNullOrEmpty(UserName)) { p = ReplaceIgnoreCase(p, UserName, Pseudonym("user", UserName)); }
            if (!string.IsNullOrEmpty(ComputerName)) { p = ReplaceIgnoreCase(p, ComputerName, Pseudonym("host", ComputerName)); }
            return p;
        }

        // Host names: the computer name, single-label names and local suffixes are pseudonymized;
        // public DNS names stay (they are what an analysis needs).
        public string Host(string name)
        {
            if (!Enabled || string.IsNullOrEmpty(name)) { return name; }
            string n = name.TrimEnd('.');
            // Reverse-lookup names carry the address itself (10.1.168.192.in-addr.arpa).
            if (n.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase)) { return Pseudonym("host", n); }
            bool local = n.IndexOf('.') < 0 || n.EndsWith(".local", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".lan", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".home.arpa", StringComparison.OrdinalIgnoreCase) || n.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                || (!string.IsNullOrEmpty(ComputerName) && n.StartsWith(ComputerName + ".", StringComparison.OrdinalIgnoreCase));
            return local ? Pseudonym("host", n) : name;
        }

        private static string ReplaceIgnoreCase(string s, string find, string with)
        {
            if (find.Length < 3) { return s; }
            int i = s.IndexOf(find, StringComparison.OrdinalIgnoreCase);
            while (i >= 0) { s = s.Substring(0, i) + with + s.Substring(i + find.Length); i = s.IndexOf(find, i + with.Length, StringComparison.OrdinalIgnoreCase); }
            return s;
        }
    }

    public static class Export
    {
        public static readonly string[] Columns = new string[] { "timestamp_utc", "source", "action", "direction", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "bytes", "tcp_flags", "pid", "process_path", "process_name", "rule_name", "rule_name_best_effort", "dns_name", "dns_name_best_effort", "notes" };

        // A firewall log entry as a normalized row (no process path or rule in the firewall log).
        public static Row FromEntry(Entry e)
        {
            Row r = new Row();
            r.TimestampUtc = e.Time.HasValue ? e.Time.Value.ToUniversalTime() : DateTime.MinValue;
            r.Source = "fwlog"; r.Action = e.Action == "DROP" ? "drop" : (e.Action == "ALLOW" ? "allow" : e.Action.ToLowerInvariant());
            r.Direction = e.Direction == "SEND" ? "outbound" : (e.Direction == "RECEIVE" ? "inbound" : e.Direction.ToLowerInvariant());
            r.Protocol = e.Protocol; r.SrcIp = e.Source; r.SrcPort = e.SourcePort; r.DstIp = e.Destination; r.DstPort = e.DestinationPort;
            r.Bytes = e.SizeNumber; r.TcpFlags = e.TcpFlags; r.Pid = e.Pid; r.ProcessPath = string.Empty;
            r.ProcessName = (e.Process != null && !e.Process.StartsWith("pid ", StringComparison.Ordinal)) ? e.Process : string.Empty;
            r.RuleName = string.Empty; r.DnsName = string.Empty; r.Notes = e.Note ?? string.Empty;
            return r;
        }

        public static List<Row> FromEntries(IList<Entry> rows)
        {
            List<Row> list = new List<Row>(rows.Count);
            for (int i = 0; i < rows.Count; i++) { list.Add(FromEntry(rows[i])); }
            return list;
        }

        // Best-effort DNS names: for each row the most recent DNS answer (before the row, within
        // 'window') that resolved its remote address, preferring an answer to the same process.
        public static int CorrelateDns(IList<Row> rows, IList<Row> dns, TimeSpan window)
        {
            Dictionary<string, List<Row>> byIp = new Dictionary<string, List<Row>>(StringComparer.OrdinalIgnoreCase);
            foreach (Row d in dns)
            {
                if (string.IsNullOrEmpty(d.DstIp)) { continue; }
                foreach (string ip in d.DstIp.Split(new char[] { ';', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    List<Row> l;
                    if (!byIp.TryGetValue(ip, out l)) { l = new List<Row>(); byIp[ip] = l; }
                    l.Add(d);
                }
            }
            int hits = 0;
            foreach (Row r in rows)
            {
                if (r.Source == "dns") { continue; }
                string remote = r.Direction == "inbound" ? r.SrcIp : r.DstIp;
                List<Row> cands;
                if (string.IsNullOrEmpty(remote) || !byIp.TryGetValue(remote, out cands)) { continue; }
                Row best = null; bool bestSamePid = false;
                foreach (Row d in cands)
                {
                    if (d.TimestampUtc > r.TimestampUtc || r.TimestampUtc - d.TimestampUtc > window) { continue; }
                    bool same = d.Pid >= 0 && d.Pid == r.Pid;
                    if (best == null || (same && !bestSamePid) || (same == bestSamePid && d.TimestampUtc > best.TimestampUtc)) { best = d; bestSamePid = same; }
                }
                if (best != null) { r.DnsName = best.DnsName; hits++; }
            }
            return hits;
        }

        // Stable sort by time (rows with the same time keep their order).
        public static void SortByTime(List<Row> rows)
        {
            Row[] a = rows.ToArray();
            long[] keys = new long[a.Length];
            int[] order = new int[a.Length];
            for (int i = 0; i < a.Length; i++) { keys[i] = a[i].TimestampUtc.Ticks; order[i] = i; }
            Array.Sort(order, delegate(int x, int y) { int c = keys[x].CompareTo(keys[y]); return c != 0 ? c : x.CompareTo(y); });
            rows.Clear();
            for (int i = 0; i < order.Length; i++) { rows.Add(a[order[i]]); }
        }

        public static Flow[] Flows(IList<Row> rows)
        {
            Dictionary<string, Flow> map = new Dictionary<string, Flow>(StringComparer.OrdinalIgnoreCase);
            foreach (Row r in rows)
            {
                if (r.Source == "dns") { continue; }
                bool inbound = r.Direction == "inbound";
                string remote = inbound ? r.SrcIp : r.DstIp;
                string port = r.DstPort;
                string proc = !string.IsNullOrEmpty(r.ProcessPath) ? r.ProcessPath : (!string.IsNullOrEmpty(r.ProcessName) ? r.ProcessName : (r.Pid >= 0 ? "pid " + r.Pid.ToString(CultureInfo.InvariantCulture) : string.Empty));
                string key = proc + "|" + remote + "|" + port + "|" + r.Protocol;
                Flow f;
                if (!map.TryGetValue(key, out f))
                {
                    f = new Flow(); f.ProcessPath = r.ProcessPath; f.ProcessName = !string.IsNullOrEmpty(r.ProcessName) ? r.ProcessName : proc; f.RemoteIp = remote; f.Port = port; f.Protocol = r.Protocol;
                    f.FirstSeenUtc = r.TimestampUtc; f.LastSeenUtc = r.TimestampUtc; map[key] = f;
                }
                f.Events++;
                if (r.Action == "allow") { f.Allowed++; } else if (r.Action == "drop" || r.Action == "block") { f.Blocked++; }
                if (r.Bytes > 0) { f.Bytes += r.Bytes; }
                if (r.TimestampUtc < f.FirstSeenUtc) { f.FirstSeenUtc = r.TimestampUtc; }
                if (r.TimestampUtc > f.LastSeenUtc) { f.LastSeenUtc = r.TimestampUtc; }
            }
            List<Flow> list = new List<Flow>(map.Values);
            list.Sort(delegate(Flow a, Flow b) { return b.Events.CompareTo(a.Events); });
            return list.ToArray();
        }

        private static string[] Values(Row r, Redactor red)
        {
            bool on = red != null && red.Enabled;
            return new string[] {
                r.TimestampUtc == DateTime.MinValue ? string.Empty : r.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                r.Source, r.Action, r.Direction, r.Protocol,
                on ? red.Ip(r.SrcIp) : r.SrcIp, r.SrcPort, on ? red.Ip(r.DstIp) : r.DstIp, r.DstPort,
                r.Bytes >= 0 ? r.Bytes.ToString(CultureInfo.InvariantCulture) : string.Empty, r.TcpFlags,
                r.Pid >= 0 ? r.Pid.ToString(CultureInfo.InvariantCulture) : string.Empty,
                on ? red.Path(r.ProcessPath) : r.ProcessPath, on ? red.Path(r.ProcessName) : r.ProcessName,
                on ? red.Text(r.RuleName) : r.RuleName, string.IsNullOrEmpty(r.RuleName) ? string.Empty : "true",
                on ? red.Host(r.DnsName) : r.DnsName, string.IsNullOrEmpty(r.DnsName) || r.Source == "dns" ? string.Empty : "true",
                on ? red.Text(r.Notes) : r.Notes
            };
        }

        public static string[] JsonLines(IList<Row> rows, Redactor red)
        {
            string[] lines = new string[rows.Count];
            StringBuilder sb = new StringBuilder(512);
            for (int i = 0; i < rows.Count; i++)
            {
                string[] v = Values(rows[i], red);
                sb.Length = 0; sb.Append('{');
                for (int k = 0; k < Columns.Length; k++)
                {
                    if (k > 0) { sb.Append(','); }
                    sb.Append('"').Append(Columns[k]).Append("\":");
                    bool numeric = Columns[k] == "bytes" || Columns[k] == "pid";
                    bool flag = Columns[k].EndsWith("_best_effort", StringComparison.Ordinal);
                    if (string.IsNullOrEmpty(v[k])) { sb.Append(flag ? "false" : "null"); }
                    else if (numeric || flag) { sb.Append(v[k]); }
                    else { sb.Append(Engine.JsonString(v[k])); }
                }
                sb.Append('}');
                lines[i] = sb.ToString();
            }
            return lines;
        }

        public static string[] CsvLines(IList<Row> rows, Redactor red, bool header)
        {
            string[] lines = new string[rows.Count + (header ? 1 : 0)];
            StringBuilder sb = new StringBuilder(512);
            int o = 0;
            if (header) { for (int k = 0; k < Columns.Length; k++) { if (k > 0) { sb.Append(','); } sb.Append(Engine.CsvCell(Columns[k])); } lines[o++] = sb.ToString(); }
            for (int i = 0; i < rows.Count; i++)
            {
                string[] v = Values(rows[i], red);
                sb.Length = 0;
                for (int k = 0; k < v.Length; k++) { if (k > 0) { sb.Append(','); } sb.Append(Engine.CsvCell(v[k])); }
                lines[o++] = sb.ToString();
            }
            return lines;
        }

        public static string[] FlowLines(IList<Flow> flows, Redactor red, bool json)
        {
            string[] cols = new string[] { "process_name", "process_path", "remote_ip", "port", "protocol", "first_seen_utc", "last_seen_utc", "events", "allowed", "blocked", "bytes" };
            List<string> lines = new List<string>(flows.Count + 1);
            bool on = red != null && red.Enabled;
            StringBuilder sb = new StringBuilder(256);
            if (!json) { lines.Add(string.Join(",", Array.ConvertAll(cols, delegate(string c) { return Engine.CsvCell(c); }))); }
            foreach (Flow f in flows)
            {
                string[] v = new string[] { on ? red.Path(f.ProcessName) : f.ProcessName, on ? red.Path(f.ProcessPath) : f.ProcessPath, on ? red.Ip(f.RemoteIp) : f.RemoteIp, f.Port, f.Protocol,
                    f.FirstSeenUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture), f.LastSeenUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
                    f.Events.ToString(CultureInfo.InvariantCulture), f.Allowed.ToString(CultureInfo.InvariantCulture), f.Blocked.ToString(CultureInfo.InvariantCulture), f.Bytes.ToString(CultureInfo.InvariantCulture) };
                sb.Length = 0;
                if (json)
                {
                    sb.Append('{');
                    for (int k = 0; k < cols.Length; k++) { if (k > 0) { sb.Append(','); } sb.Append('"').Append(cols[k]).Append("\":"); if (k >= 7) { sb.Append(v[k]); } else { sb.Append(Engine.JsonString(v[k])); } }
                    sb.Append('}');
                }
                else { for (int k = 0; k < v.Length; k++) { if (k > 0) { sb.Append(','); } sb.Append(Engine.CsvCell(v[k])); } }
                lines.Add(sb.ToString());
            }
            return lines.ToArray();
        }

        // Where to split lines into files of at most about maxBytes (UTF-8, with line breaks):
        // the index of the first line of every chunk after the first.
        public static int[] ChunkStarts(string[] lines, long maxBytes, int headerLines)
        {
            List<int> starts = new List<int>();
            long size = 0;
            for (int i = headerLines; i < lines.Length; i++)
            {
                long n = Encoding.UTF8.GetByteCount(lines[i]) + 2;
                if (size > 0 && size + n > maxBytes) { starts.Add(i); size = 0; }
                size += n;
            }
            return starts.ToArray();
        }
    }
}
