using System.Text.Json;
using HostsGuardian.Core.Models;

namespace HostsGuardian.DnsEngine;

/// <summary>Bounded durable management audit, distinct from raw telemetry.</summary>
public sealed class PolicyAuditStore(string path)
{
    public const int MaximumEntries = 1000;
    public bool Available { get; private set; } = true;
    private readonly object _gate = new();
    public PolicyAuditRecord[] Read()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(path)) { Available = true; return []; }
                if (new FileInfo(path).Length > 1048576 || new FileInfo(path).LinkTarget != null) throw new IOException("Invalid audit file");
                var values = File.ReadLines(path).Select(line => JsonSerializer.Deserialize<PolicyAuditRecord>(line) ?? throw new JsonException()).ToArray();
                if (values.Length > MaximumEntries || values.Any(r => r.Operation == null || r.Operation.Length > 80 ||
                    r.ActorEvidence == null || r.ActorEvidence.Length > 160 || r.Outcome == null || r.Outcome.Length > 80 ||
                    r.PolicyHash == null || r.PolicyHash.Length != 64 || r.PolicyHash.Any(c => !Uri.IsHexDigit(c)) ||
                    r.Changes == null || r.Changes.Length > 1024 || r.PreviousRevision < 0 || r.EffectiveRevision < 0)) throw new IOException("Invalid or oversized audit");
                Available = true; return values;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException)
            { Available = false; return []; }
        }
    }
    public void Record(PolicyAuditRecord record)
    {
        lock (_gate)
        {
            var previous = Read(); if (!Available) return; // retain unreadable history
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
                var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
                if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (var stream = new FileStream(temporary, options))
                using (var writer = new StreamWriter(stream))
                    foreach (var entry in previous.TakeLast(MaximumEntries - 1).Append(record)) writer.WriteLine(JsonSerializer.Serialize(entry));
                File.Move(temporary, path, true);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Available = false; }
            finally { try { if (File.Exists(temporary)) File.Delete(temporary); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { } }
        }
    }
}
