using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace AgentGuard.Core.Storage;

public sealed class EventFilter
{
    public string? AgentId { get; set; }
    public string? Action { get; set; }
    public Verdict? Verdict { get; set; }
    public Severity? Severity { get; set; }
    public string? Source { get; set; }
    public string? Query { get; set; }
    public DateTimeOffset? From { get; set; }
    public DateTimeOffset? To { get; set; }
    public long? Before { get; set; }
    public long? After { get; set; }
    public int Limit { get; set; } = 100;
    public bool Ascending { get; set; }
}

public sealed record IntegrityResult(bool Ok, long Checked, long? FirstBadId, DateTimeOffset VerifiedAt);
public sealed record ActivityBucket(DateTimeOffset Ts, long Total, long Blocked, long Asked);
public sealed record AgentActivity(string AgentId, string AgentName, long Total, long Blocked);
public sealed record PolicyVersion(int Version, string Yaml, DateTimeOffset AppliedAt, string AppliedBy, int RuleCount);

/// <summary>
/// SQLite persistence. Events are append-only and hash-chained: each row's hash covers its content and the previous row's hash,
/// so editing or deleting a row breaks the chain from that point on.
/// </summary>
public sealed class EventStore : IDisposable
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly string _connectionString;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private long _lastId;
    private string _lastHash = GenesisHash;

    public string DatabasePath { get; }

    public EventStore(string databasePath)
    {
        DatabasePath = databasePath;
        var dir = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
        }.ToString();
        Initialize();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        using var pragma = c.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;";
        pragma.ExecuteNonQuery();
        return c;
    }

    private void Initialize()
    {
        using var c = Open();
        Exec(c, """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY, ts TEXT NOT NULL, ts_ms INTEGER NOT NULL,
              agent_id TEXT NOT NULL, agent_name TEXT NOT NULL, pid INTEGER,
              action TEXT NOT NULL, target TEXT NOT NULL, details_json TEXT NOT NULL,
              verdict TEXT NOT NULL, rule_id TEXT, severity TEXT NOT NULL, source TEXT NOT NULL,
              enforced INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_ms);
            CREATE INDEX IF NOT EXISTS ix_events_agent ON events(agent_id, ts_ms);
            CREATE INDEX IF NOT EXISTS ix_events_verdict ON events(verdict, ts_ms);
            CREATE TABLE IF NOT EXISTS chain_checkpoints(
              id INTEGER PRIMARY KEY AUTOINCREMENT, last_pruned_id INTEGER NOT NULL, last_pruned_hash TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS agents(
              id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, exe_path TEXT, publisher TEXT, signer_valid INTEGER,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, trust TEXT NOT NULL DEFAULT 'unknown', network_blocked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS agent_processes(
              pid INTEGER NOT NULL, start_time TEXT NOT NULL, agent_id TEXT NOT NULL, parent_pid INTEGER, end_time TEXT,
              command_line TEXT, exe_path TEXT, PRIMARY KEY(pid, start_time));
            CREATE TABLE IF NOT EXISTS mcp_servers(id TEXT PRIMARY KEY, name TEXT NOT NULL, client TEXT NOT NULL, json TEXT NOT NULL, missing INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, event_id INTEGER NOT NULL, status TEXT NOT NULL, requested_at TEXT NOT NULL, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS alerts(
              id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL, ts TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
              title TEXT NOT NULL, agent_id TEXT NOT NULL, agent_name TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, rule_id TEXT);
            CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, id);
            CREATE TABLE IF NOT EXISTS policies(
              version INTEGER PRIMARY KEY AUTOINCREMENT, yaml TEXT NOT NULL, applied_at TEXT NOT NULL, applied_by TEXT NOT NULL, rule_count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS host_contacts(agent_id TEXT NOT NULL, host TEXT NOT NULL, first_seen TEXT NOT NULL, PRIMARY KEY(agent_id, host));
            """);

        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, hash FROM events ORDER BY id DESC LIMIT 1";
        using var r = cmd.ExecuteReader();
        if (r.Read())
        {
            _lastId = r.GetInt64(0);
            _lastHash = r.GetString(1);
        }
        else
        {
            var cp = LatestCheckpoint(c);
            if (cp is not null) { _lastId = cp.Value.Id; _lastHash = cp.Value.Hash; }
        }
    }

    // ---------------------------------------------------------------- events

    /// <summary>Appends an event, assigning its id and chain hashes.</summary>
    public async Task<AgentEvent> AppendAsync(AgentEvent e, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            e.Id = _lastId + 1;
            e.PrevHash = _lastHash;
            var detailsJson = Json.Serialize(e.Details);
            e.Hash = ComputeHash(e, detailsJson);
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = """
                INSERT INTO events(id, ts, ts_ms, agent_id, agent_name, pid, action, target, details_json, verdict, rule_id, severity, source, enforced, prev_hash, hash)
                VALUES($id, $ts, $ms, $agent, $name, $pid, $action, $target, $details, $verdict, $rule, $sev, $source, $enforced, $prev, $hash)
                """;
            cmd.Parameters.AddWithValue("$id", e.Id);
            cmd.Parameters.AddWithValue("$ts", FormatTs(e.Ts));
            cmd.Parameters.AddWithValue("$ms", e.Ts.ToUnixTimeMilliseconds());
            cmd.Parameters.AddWithValue("$agent", e.AgentId);
            cmd.Parameters.AddWithValue("$name", e.AgentName);
            cmd.Parameters.AddWithValue("$pid", (object?)e.Pid ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$action", e.Action);
            cmd.Parameters.AddWithValue("$target", e.Target);
            cmd.Parameters.AddWithValue("$details", detailsJson);
            cmd.Parameters.AddWithValue("$verdict", Lower(e.Verdict));
            cmd.Parameters.AddWithValue("$rule", (object?)e.RuleId ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sev", Lower(e.Severity));
            cmd.Parameters.AddWithValue("$source", e.Source);
            cmd.Parameters.AddWithValue("$enforced", e.Enforced ? 1 : 0);
            cmd.Parameters.AddWithValue("$prev", e.PrevHash);
            cmd.Parameters.AddWithValue("$hash", e.Hash);
            cmd.ExecuteNonQuery();
            _lastId = e.Id;
            _lastHash = e.Hash;
            return e;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public static string ComputeHash(AgentEvent e, string detailsJson)
    {
        var canonical = string.Join('\u001f',
            e.Id.ToString(CultureInfo.InvariantCulture), FormatTs(e.Ts), e.AgentId, e.AgentName,
            e.Pid?.ToString(CultureInfo.InvariantCulture) ?? "", e.Action, e.Target, detailsJson, Lower(e.Verdict),
            e.RuleId ?? "", Lower(e.Severity), e.Source, e.Enforced ? "1" : "0", e.PrevHash);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public AgentEvent? GetEvent(long id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT * FROM events WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadEvent(r) : null;
    }

    public List<AgentEvent> QueryEvents(EventFilter f)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrEmpty(f.AgentId)) { where.Add("agent_id=$agent"); cmd.Parameters.AddWithValue("$agent", f.AgentId); }
        if (!string.IsNullOrEmpty(f.Action))
        {
            if (f.Action.EndsWith('*')) { where.Add("action LIKE $action"); cmd.Parameters.AddWithValue("$action", f.Action.TrimEnd('*') + "%"); }
            else { where.Add("action=$action"); cmd.Parameters.AddWithValue("$action", f.Action); }
        }
        if (f.Verdict is { } v) { where.Add("verdict=$verdict"); cmd.Parameters.AddWithValue("$verdict", Lower(v)); }
        if (f.Severity is { } s) { where.Add("severity=$sev"); cmd.Parameters.AddWithValue("$sev", Lower(s)); }
        if (!string.IsNullOrEmpty(f.Source)) { where.Add("source=$source"); cmd.Parameters.AddWithValue("$source", f.Source); }
        if (!string.IsNullOrEmpty(f.Query))
        {
            where.Add("(target LIKE $q ESCAPE '\\' OR agent_name LIKE $q ESCAPE '\\' OR rule_id LIKE $q ESCAPE '\\' OR details_json LIKE $q ESCAPE '\\')");
            cmd.Parameters.AddWithValue("$q", "%" + f.Query.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%");
        }
        if (f.From is { } from) { where.Add("ts_ms>=$from"); cmd.Parameters.AddWithValue("$from", from.ToUnixTimeMilliseconds()); }
        if (f.To is { } to) { where.Add("ts_ms<=$to"); cmd.Parameters.AddWithValue("$to", to.ToUnixTimeMilliseconds()); }
        if (f.Before is { } before) { where.Add("id<$before"); cmd.Parameters.AddWithValue("$before", before); }
        if (f.After is { } after) { where.Add("id>$after"); cmd.Parameters.AddWithValue("$after", after); }
        cmd.CommandText = "SELECT * FROM events" + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "")
                          + (f.Ascending ? " ORDER BY id ASC" : " ORDER BY id DESC") + " LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", Math.Clamp(f.Limit, 1, 100_000));
        var list = new List<AgentEvent>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadEvent(r));
        return list;
    }

    private static AgentEvent ReadEvent(SqliteDataReader r)
    {
        var detailsJson = r.GetString(r.GetOrdinal("details_json"));
        var details = Json.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(detailsJson) ?? new();
        return new AgentEvent
        {
            Id = r.GetInt64(r.GetOrdinal("id")),
            Ts = ParseTs(r.GetString(r.GetOrdinal("ts"))),
            AgentId = r.GetString(r.GetOrdinal("agent_id")),
            AgentName = r.GetString(r.GetOrdinal("agent_name")),
            Pid = r.IsDBNull(r.GetOrdinal("pid")) ? null : r.GetInt32(r.GetOrdinal("pid")),
            Action = r.GetString(r.GetOrdinal("action")),
            Target = r.GetString(r.GetOrdinal("target")),
            Details = details.ToDictionary(kv => kv.Key, kv => Json.FromElement(kv.Value)),
            Verdict = Enum.Parse<Verdict>(r.GetString(r.GetOrdinal("verdict")), true),
            RuleId = r.IsDBNull(r.GetOrdinal("rule_id")) ? null : r.GetString(r.GetOrdinal("rule_id")),
            Severity = Enum.Parse<Severity>(r.GetString(r.GetOrdinal("severity")), true),
            Source = r.GetString(r.GetOrdinal("source")),
            Enforced = r.GetInt64(r.GetOrdinal("enforced")) != 0,
            PrevHash = r.GetString(r.GetOrdinal("prev_hash")),
            Hash = r.GetString(r.GetOrdinal("hash")),
        };
    }

    /// <summary>Walks the whole chain from the latest checkpoint and recomputes every hash.</summary>
    public IntegrityResult VerifyIntegrity()
    {
        using var c = Open();
        var cp = LatestCheckpoint(c);
        var expectedPrev = cp?.Hash ?? GenesisHash;
        var expectedId = (cp?.Id ?? 0) + 1;
        long checkedCount = 0;

        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, ts, agent_id, agent_name, pid, action, target, details_json, verdict, rule_id, severity, source, enforced, prev_hash, hash FROM events WHERE id>$from ORDER BY id ASC";
        cmd.Parameters.AddWithValue("$from", cp?.Id ?? 0);
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var e = new AgentEvent
            {
                Id = r.GetInt64(0),
                Ts = ParseTs(r.GetString(1)),
                AgentId = r.GetString(2),
                AgentName = r.GetString(3),
                Pid = r.IsDBNull(4) ? null : r.GetInt32(4),
                Action = r.GetString(5),
                Target = r.GetString(6),
                Verdict = Enum.Parse<Verdict>(r.GetString(8), true),
                RuleId = r.IsDBNull(9) ? null : r.GetString(9),
                Severity = Enum.Parse<Severity>(r.GetString(10), true),
                Source = r.GetString(11),
                Enforced = r.GetInt64(12) != 0,
                PrevHash = r.GetString(13),
            };
            var stored = r.GetString(14);
            checkedCount++;
            if (e.Id != expectedId || e.PrevHash != expectedPrev || ComputeHash(e, r.GetString(7)) != stored)
                return new IntegrityResult(false, checkedCount, e.Id, DateTimeOffset.UtcNow);
            expectedPrev = stored;
            expectedId++;
        }
        return new IntegrityResult(true, checkedCount, null, DateTimeOffset.UtcNow);
    }

    /// <summary>Deletes events older than <paramref name="olderThan"/>, recording a checkpoint so the remaining chain still verifies.</summary>
    public async Task<int> PruneAsync(DateTimeOffset olderThan, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            using var c = Open();
            using var find = c.CreateCommand();
            find.CommandText = "SELECT id, hash FROM events WHERE ts_ms<$cut ORDER BY id DESC LIMIT 1";
            find.Parameters.AddWithValue("$cut", olderThan.ToUnixTimeMilliseconds());
            long lastId; string lastHash;
            using (var r = find.ExecuteReader())
            {
                if (!r.Read()) return 0;
                lastId = r.GetInt64(0);
                lastHash = r.GetString(1);
            }
            using var tx = c.BeginTransaction();
            using var cp = c.CreateCommand();
            cp.Transaction = tx;
            cp.CommandText = "INSERT INTO chain_checkpoints(last_pruned_id, last_pruned_hash, created_at) VALUES($id, $hash, $at)";
            cp.Parameters.AddWithValue("$id", lastId);
            cp.Parameters.AddWithValue("$hash", lastHash);
            cp.Parameters.AddWithValue("$at", FormatTs(DateTimeOffset.UtcNow));
            cp.ExecuteNonQuery();
            using var del = c.CreateCommand();
            del.Transaction = tx;
            del.CommandText = "DELETE FROM events WHERE id<=$id";
            del.Parameters.AddWithValue("$id", lastId);
            var n = del.ExecuteNonQuery();
            tx.Commit();
            return n;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static (long Id, string Hash)? LatestCheckpoint(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT last_pruned_id, last_pruned_hash FROM chain_checkpoints ORDER BY id DESC LIMIT 1";
        using var r = cmd.ExecuteReader();
        return r.Read() ? (r.GetInt64(0), r.GetString(1)) : null;
    }

    // ---------------------------------------------------------------- stats

    public (long Events, long Blocked, long Asked) CountsSince(DateTimeOffset since)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*), COALESCE(SUM(verdict='block'),0), COALESCE(SUM(verdict='ask'),0) FROM events WHERE ts_ms>=$since AND source NOT IN ('system','discovery')";
        cmd.Parameters.AddWithValue("$since", since.ToUnixTimeMilliseconds());
        using var r = cmd.ExecuteReader();
        r.Read();
        return (r.GetInt64(0), r.GetInt64(1), r.GetInt64(2));
    }

    public List<ActivityBucket> Activity(DateTimeOffset now, int hours)
    {
        var start = new DateTimeOffset(now.UtcDateTime.Date.AddHours(now.UtcDateTime.Hour), TimeSpan.Zero).AddHours(-(hours - 1));
        var buckets = Enumerable.Range(0, hours).Select(i => start.AddHours(i)).ToDictionary(t => t.ToUnixTimeMilliseconds() / 3_600_000, t => new long[3]);
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT ts_ms/3600000 AS h, COUNT(*), COALESCE(SUM(verdict='block'),0), COALESCE(SUM(verdict='ask'),0)
            FROM events WHERE ts_ms>=$start AND source NOT IN ('system','discovery') GROUP BY h
            """;
        cmd.Parameters.AddWithValue("$start", start.ToUnixTimeMilliseconds());
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            if (buckets.TryGetValue(r.GetInt64(0), out var b)) { b[0] = r.GetInt64(1); b[1] = r.GetInt64(2); b[2] = r.GetInt64(3); }
        }
        return buckets.OrderBy(kv => kv.Key)
            .Select(kv => new ActivityBucket(DateTimeOffset.FromUnixTimeMilliseconds(kv.Key * 3_600_000), kv.Value[0], kv.Value[1], kv.Value[2]))
            .ToList();
    }

    public List<AgentActivity> AgentActivity(DateTimeOffset since, int limit = 1000)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            SELECT agent_id, MAX(agent_name), COUNT(*), COALESCE(SUM(verdict='block'),0)
            FROM events WHERE ts_ms>=$since AND source NOT IN ('system','discovery')
            GROUP BY agent_id ORDER BY COUNT(*) DESC LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$since", since.ToUnixTimeMilliseconds());
        cmd.Parameters.AddWithValue("$limit", limit);
        var list = new List<AgentActivity>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(new AgentActivity(r.GetString(0), r.GetString(1), r.GetInt64(2), r.GetInt64(3)));
        return list;
    }

    // ---------------------------------------------------------------- agents

    public void UpsertAgent(AgentRecord a)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO agents(id, kind, name, exe_path, publisher, signer_valid, first_seen, last_seen, trust, network_blocked)
            VALUES($id, $kind, $name, $exe, $pub, $sig, $first, $last, $trust, $net)
            ON CONFLICT(id) DO UPDATE SET kind=$kind, name=$name, exe_path=COALESCE($exe, exe_path), publisher=COALESCE($pub, publisher),
              signer_valid=COALESCE($sig, signer_valid), last_seen=$last, trust=$trust, network_blocked=$net
            """;
        cmd.Parameters.AddWithValue("$id", a.Id);
        cmd.Parameters.AddWithValue("$kind", a.Kind);
        cmd.Parameters.AddWithValue("$name", a.Name);
        cmd.Parameters.AddWithValue("$exe", (object?)a.ExePath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pub", (object?)a.Publisher ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sig", a.SignerValid is null ? DBNull.Value : a.SignerValid.Value ? 1 : 0);
        cmd.Parameters.AddWithValue("$first", FormatTs(a.FirstSeen));
        cmd.Parameters.AddWithValue("$last", FormatTs(a.LastSeen));
        cmd.Parameters.AddWithValue("$trust", a.Trust);
        cmd.Parameters.AddWithValue("$net", a.NetworkBlocked ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public List<AgentRecord> ListAgents()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, kind, name, exe_path, publisher, signer_valid, first_seen, last_seen, trust, network_blocked FROM agents ORDER BY name";
        var list = new List<AgentRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new AgentRecord
            {
                Id = r.GetString(0), Kind = r.GetString(1), Name = r.GetString(2),
                ExePath = r.IsDBNull(3) ? null : r.GetString(3),
                Publisher = r.IsDBNull(4) ? null : r.GetString(4),
                SignerValid = r.IsDBNull(5) ? null : r.GetInt64(5) != 0,
                FirstSeen = ParseTs(r.GetString(6)), LastSeen = ParseTs(r.GetString(7)),
                Trust = r.GetString(8), NetworkBlocked = r.GetInt64(9) != 0,
            });
        }
        return list;
    }

    public void RecordAgentProcess(int pid, DateTimeOffset start, string agentId, int? parentPid, string? commandLine, string? exePath)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT OR IGNORE INTO agent_processes(pid, start_time, agent_id, parent_pid, command_line, exe_path)
            VALUES($pid, $start, $agent, $ppid, $cmd, $exe)
            """;
        cmd.Parameters.AddWithValue("$pid", pid);
        cmd.Parameters.AddWithValue("$start", FormatTs(start));
        cmd.Parameters.AddWithValue("$agent", agentId);
        cmd.Parameters.AddWithValue("$ppid", (object?)parentPid ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cmd", (object?)commandLine ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$exe", (object?)exePath ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public void EndAgentProcess(int pid, DateTimeOffset start, DateTimeOffset end)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE agent_processes SET end_time=$end WHERE pid=$pid AND start_time=$start";
        cmd.Parameters.AddWithValue("$pid", pid);
        cmd.Parameters.AddWithValue("$start", FormatTs(start));
        cmd.Parameters.AddWithValue("$end", FormatTs(end));
        cmd.ExecuteNonQuery();
    }

    // ---------------------------------------------------------------- MCP servers

    public void UpsertMcpServer(McpServerRecord s)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO mcp_servers(id, name, client, json, missing) VALUES($id, $name, $client, $json, 0)
            ON CONFLICT(id) DO UPDATE SET name=$name, client=$client, json=$json, missing=0
            """;
        cmd.Parameters.AddWithValue("$id", s.Id);
        cmd.Parameters.AddWithValue("$name", s.Name);
        cmd.Parameters.AddWithValue("$client", s.Client);
        cmd.Parameters.AddWithValue("$json", Json.Serialize(s));
        cmd.ExecuteNonQuery();
    }

    public void MarkMcpServersMissing(IReadOnlyCollection<string> presentIds)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        if (presentIds.Count == 0) cmd.CommandText = "UPDATE mcp_servers SET missing=1";
        else
        {
            var names = presentIds.Select((_, i) => "$p" + i).ToList();
            cmd.CommandText = $"UPDATE mcp_servers SET missing=1 WHERE id NOT IN ({string.Join(",", names)})";
            var i = 0;
            foreach (var id in presentIds) cmd.Parameters.AddWithValue("$p" + i++, id);
        }
        cmd.ExecuteNonQuery();
    }

    public List<McpServerRecord> ListMcpServers(bool includeMissing = false)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM mcp_servers" + (includeMissing ? "" : " WHERE missing=0") + " ORDER BY client, name";
        var list = new List<McpServerRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Json.Deserialize<McpServerRecord>(r.GetString(0))!);
        return list;
    }

    public McpServerRecord? GetMcpServer(string id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM mcp_servers WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        var json = cmd.ExecuteScalar() as string;
        return json is null ? null : Json.Deserialize<McpServerRecord>(json);
    }

    // ---------------------------------------------------------------- approvals

    public void SaveApproval(ApprovalRecord a)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO approvals(id, event_id, status, requested_at, json) VALUES($id, $event, $status, $at, $json)
            ON CONFLICT(id) DO UPDATE SET status=$status, json=$json
            """;
        cmd.Parameters.AddWithValue("$id", a.Id);
        cmd.Parameters.AddWithValue("$event", a.EventId);
        cmd.Parameters.AddWithValue("$status", a.Status);
        cmd.Parameters.AddWithValue("$at", FormatTs(a.RequestedAt));
        cmd.Parameters.AddWithValue("$json", Json.Serialize(a));
        cmd.ExecuteNonQuery();
    }

    public List<ApprovalRecord> ListApprovals(string? status, int limit = 200)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM approvals" + (status is null ? "" : " WHERE status=$status") + " ORDER BY requested_at DESC LIMIT $limit";
        if (status is not null) cmd.Parameters.AddWithValue("$status", status);
        cmd.Parameters.AddWithValue("$limit", limit);
        var list = new List<ApprovalRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(Json.Deserialize<ApprovalRecord>(r.GetString(0))!);
        return list;
    }

    public ApprovalRecord? GetApproval(string id)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT json FROM approvals WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        var json = cmd.ExecuteScalar() as string;
        return json is null ? null : Json.Deserialize<ApprovalRecord>(json);
    }

    // ---------------------------------------------------------------- alerts

    public AlertRecord AddAlert(AlertRecord a)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO alerts(event_id, ts, severity, status, title, agent_id, agent_name, action, target, rule_id)
            VALUES($event, $ts, $sev, $status, $title, $agent, $name, $action, $target, $rule);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$event", a.EventId);
        cmd.Parameters.AddWithValue("$ts", FormatTs(a.Ts));
        cmd.Parameters.AddWithValue("$sev", Lower(a.Severity));
        cmd.Parameters.AddWithValue("$status", a.Status);
        cmd.Parameters.AddWithValue("$title", a.Title);
        cmd.Parameters.AddWithValue("$agent", a.AgentId);
        cmd.Parameters.AddWithValue("$name", a.AgentName);
        cmd.Parameters.AddWithValue("$action", a.Action);
        cmd.Parameters.AddWithValue("$target", a.Target);
        cmd.Parameters.AddWithValue("$rule", (object?)a.RuleId ?? DBNull.Value);
        a.Id = (long)cmd.ExecuteScalar()!;
        return a;
    }

    public List<AlertRecord> ListAlerts(string? status, int limit = 500)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT * FROM alerts" + (status is null ? "" : " WHERE status=$status") + " ORDER BY id DESC LIMIT $limit";
        if (status is not null) cmd.Parameters.AddWithValue("$status", status);
        cmd.Parameters.AddWithValue("$limit", limit);
        var list = new List<AlertRecord>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadAlert(r));
        return list;
    }

    public AlertRecord? SetAlertStatus(long id, string status)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "UPDATE alerts SET status=$status WHERE id=$id; SELECT * FROM alerts WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$status", status);
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadAlert(r) : null;
    }

    public long CountAlerts(string status)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM alerts WHERE status=$status";
        cmd.Parameters.AddWithValue("$status", status);
        return (long)cmd.ExecuteScalar()!;
    }

    private static AlertRecord ReadAlert(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(r.GetOrdinal("id")),
        EventId = r.GetInt64(r.GetOrdinal("event_id")),
        Ts = ParseTs(r.GetString(r.GetOrdinal("ts"))),
        Severity = Enum.Parse<Severity>(r.GetString(r.GetOrdinal("severity")), true),
        Status = r.GetString(r.GetOrdinal("status")),
        Title = r.GetString(r.GetOrdinal("title")),
        AgentId = r.GetString(r.GetOrdinal("agent_id")),
        AgentName = r.GetString(r.GetOrdinal("agent_name")),
        Action = r.GetString(r.GetOrdinal("action")),
        Target = r.GetString(r.GetOrdinal("target")),
        RuleId = r.IsDBNull(r.GetOrdinal("rule_id")) ? null : r.GetString(r.GetOrdinal("rule_id")),
    };

    // ---------------------------------------------------------------- policies

    public PolicyVersion SavePolicy(string yaml, string appliedBy, int ruleCount)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        var at = DateTimeOffset.UtcNow;
        cmd.CommandText = "INSERT INTO policies(yaml, applied_at, applied_by, rule_count) VALUES($yaml, $at, $by, $n); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$yaml", yaml);
        cmd.Parameters.AddWithValue("$at", FormatTs(at));
        cmd.Parameters.AddWithValue("$by", appliedBy);
        cmd.Parameters.AddWithValue("$n", ruleCount);
        var version = (int)(long)cmd.ExecuteScalar()!;
        return new PolicyVersion(version, yaml, at, appliedBy, ruleCount);
    }

    public PolicyVersion? GetPolicy(int? version = null)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = version is null
            ? "SELECT version, yaml, applied_at, applied_by, rule_count FROM policies ORDER BY version DESC LIMIT 1"
            : "SELECT version, yaml, applied_at, applied_by, rule_count FROM policies WHERE version=$v";
        if (version is not null) cmd.Parameters.AddWithValue("$v", version);
        using var r = cmd.ExecuteReader();
        return r.Read() ? new PolicyVersion(r.GetInt32(0), r.GetString(1), ParseTs(r.GetString(2)), r.GetString(3), r.GetInt32(4)) : null;
    }

    public List<PolicyVersion> PolicyHistory(int limit = 100)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT version, '', applied_at, applied_by, rule_count FROM policies ORDER BY version DESC LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit);
        var list = new List<PolicyVersion>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(new PolicyVersion(r.GetInt32(0), "", ParseTs(r.GetString(2)), r.GetString(3), r.GetInt32(4)));
        return list;
    }

    // ---------------------------------------------------------------- settings / misc

    public string? GetSetting(string key)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key=$k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void SetSetting(string key, string value)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO settings(key, value) VALUES($k, $v) ON CONFLICT(key) DO UPDATE SET value=$v";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Records a host contact. Returns true when this is the agent's first contact with the host.</summary>
    public bool RecordHostContact(string agentId, string host)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT OR IGNORE INTO host_contacts(agent_id, host, first_seen) VALUES($a, $h, $t)";
        cmd.Parameters.AddWithValue("$a", agentId);
        cmd.Parameters.AddWithValue("$h", host.ToLowerInvariant());
        cmd.Parameters.AddWithValue("$t", FormatTs(DateTimeOffset.UtcNow));
        return cmd.ExecuteNonQuery() > 0;
    }

    public bool HasHostContact(string agentId, string host)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM host_contacts WHERE agent_id=$a AND host=$h";
        cmd.Parameters.AddWithValue("$a", agentId);
        cmd.Parameters.AddWithValue("$h", host.ToLowerInvariant());
        return cmd.ExecuteScalar() is not null;
    }

    private static void Exec(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public static string FormatTs(DateTimeOffset ts) => ts.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    public static DateTimeOffset ParseTs(string s) =>
        DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static string Lower<T>(T e) where T : Enum => e.ToString().ToLowerInvariant();

    public void Dispose()
    {
        _writeLock.Dispose();
        SqliteConnection.ClearAllPools();
    }
}
