using System.Text.Json;
using HostsGuardian.Core.Models;

namespace HostsGuardian.DnsEngine;

public sealed record CommittedPolicy(long Revision, string[] Domains);
public sealed record PolicyLoadResult(string State, CommittedPolicy? Policy, string Fault = "");

/// <summary>Owns one versioned policy file; never generates policy or modifies RuleStore.</summary>
public sealed class PolicyPersistence
{
    public const int MaximumFileBytes = 1024 * 1024;
    private readonly string _path;

    public PolicyPersistence(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Policy file must be configured");
        _path = Path.GetFullPath(path);
    }

    public PolicyLoadResult Load()
    {
        try
        {
            RejectLink();
            using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > MaximumFileBytes) return Invalid();
            using var memory = new MemoryStream();
            var buffer = new byte[4096];
            int count;
            while ((count = stream.Read(buffer)) > 0)
            {
                if (memory.Length + count > MaximumFileBytes) return Invalid();
                memory.Write(buffer, 0, count);
            }
            using var document = JsonDocument.Parse(memory.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return Invalid();
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!names.Add(property.Name)) return Invalid();
            if (!names.SetEquals(new[] { "schemaVersion", "revision", "domains" })) return Invalid();
            if (!root.GetProperty("schemaVersion").TryGetInt32(out var version) || version != 1) return Invalid();
            if (!root.GetProperty("revision").TryGetInt64(out var revision) || revision < 1) return Invalid();
            var values = root.GetProperty("domains");
            if (values.ValueKind != JsonValueKind.Array) return Invalid();
            var domains = new List<string>();
            var unique = new HashSet<string>(StringComparer.Ordinal);
            foreach (var value in values.EnumerateArray())
            {
                if (value.ValueKind != JsonValueKind.String) return Invalid();
                var domain = value.GetString()!;
                if (domain.Length == 0 || DomainName.Normalize(domain) != domain || !unique.Add(domain)) return Invalid();
                domains.Add(domain);
            }
            var sorted = domains.OrderBy(domain => domain, StringComparer.Ordinal).ToArray();
            if (!domains.SequenceEqual(sorted)) return Invalid();
            return new PolicyLoadResult("Restored", new CommittedPolicy(revision, sorted));
        }
        catch (FileNotFoundException) { return Missing(); }
        catch (DirectoryNotFoundException) { return Missing(); }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException or OverflowException)
        { return Invalid(); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        { return new PolicyLoadResult("Unavailable", null, "PolicyReadFailed"); }
    }

    public void Commit(CommittedPolicy policy, bool preserveUntrustedFile)
    {
        if (policy.Revision < 1) throw new ArgumentException("Invalid policy revision");
        var previous = "";
        foreach (var domain in policy.Domains)
        {
            if (domain.Length == 0 || DomainName.Normalize(domain) != domain || StringComparer.Ordinal.Compare(previous, domain) >= 0)
                throw new ArgumentException("Policy must contain sorted unique normalized domains");
            previous = domain;
        }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, revision = policy.Revision, domains = policy.Domains });
        if (bytes.Length > MaximumFileBytes) throw new ArgumentException("Policy exceeds storage limit");
        var directory = Path.GetDirectoryName(_path)!;
        var temporary = Path.Combine(directory, ".policy-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
            else Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            RejectLink();
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            if (preserveUntrustedFile && File.Exists(_path))
            {
                var evidence = _path + ".rejected-" + Guid.NewGuid().ToString("N");
                File.Replace(temporary, _path, evidence);
            }
            else File.Move(temporary, _path, overwrite: true);
            // Rename is the commit point; no fallible maintenance follows it.
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (IOException) { EngineLog.Warning("Persistence", "Uncommitted temporary file retained"); }
            catch (UnauthorizedAccessException) { EngineLog.Warning("Persistence", "Uncommitted temporary file retained"); }
        }
    }

    private void RejectLink()
    {
        var file = new FileInfo(_path);
        if (file.LinkTarget != null || (file.Exists && (file.Attributes & FileAttributes.ReparsePoint) != 0))
            throw new IOException("Policy file must not be a symbolic link");
    }

    private static PolicyLoadResult Invalid() => new("Invalid", null, "PolicyInvalid");
    private static PolicyLoadResult Missing() => new("Missing", new CommittedPolicy(0, Array.Empty<string>()));
}
