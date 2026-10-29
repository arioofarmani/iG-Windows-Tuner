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
            r.Skipped["Empty"] = 0; r.Skipped["NoHeader"] = 0; r.Skipped["FieldCount"] = 0; r.Skipped["Partial"] = 0;
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
                if (rest > 0)
                {
                    if (carry.Length < carryLen + rest) { byte[] bigger = new byte[Math.Max(carry.Length * 2, carryLen + rest)]; Buffer.BlockCopy(carry, 0, bigger, 0, carryLen); carry = bigger; }
                    Buffer.BlockCopy(buf, start, carry, carryLen, rest);
                    carryLen += rest;
                }
            }
            if (carryLen > 0)
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

        public static void Sort(Entry[] rows, string[] keys, bool[] descending)
        {
            if (keys == null || keys.Length == 0 || rows.Length < 2) { return; }
            int n = rows.Length, levels = keys.Length;
            long[][] num = new long[levels][];
            for (int l = 0; l < levels; l++)
            {
                if (IsNumeric(keys[l])) { num[l] = new long[n]; for (int i = 0; i < n; i++) { num[l][i] = NumericKey(rows[i], keys[l]); } }
                else
                {
                    // Text keys sort by rank: each distinct value is compared once, rows compare integers.
                    Dictionary<string, long> rank = new Dictionary<string, long>(StringComparer.Ordinal);
                    string[] v = new string[n];
                    for (int i = 0; i < n; i++) { v[i] = Get(rows[i], keys[l]) ?? string.Empty; rank[v[i]] = 0; }
                    string[] distinct = new string[rank.Count];
                    rank.Keys.CopyTo(distinct, 0);
                    Array.Sort(distinct, StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < distinct.Length; i++) { rank[distinct[i]] = i; }
                    num[l] = new long[n];
                    for (int i = 0; i < n; i++) { num[l][i] = rank[v[i]]; }
                }
            }
            int[] order = new int[n];
            for (int i = 0; i < n; i++) { order[i] = i; }
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
}
