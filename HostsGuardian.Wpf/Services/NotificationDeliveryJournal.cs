using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
namespace HostsGuardian.Wpf.Services;

/// <summary>Bounded per-user deduplication hashes only, with no policy, device names or credentials.</summary>
public sealed class NotificationDeliveryJournal
{
    private readonly string _path;
    private Dictionary<string, DateTimeOffset> _entries = new();
    public bool Available { get; private set; } = true;
    public NotificationDeliveryJournal(string path)
    {
        _path = path;
        try
        {
            if (File.Exists(path))
            {
                if (new FileInfo(path).Length > 131072) throw new IOException();
                _entries = JsonSerializer.Deserialize<Dictionary<string, DateTimeOffset>>(File.ReadAllText(path)) ?? throw new IOException();
                if (_entries.Count > 1024 || _entries.Any(p => p.Key.Length != 64 || p.Key.Any(c => !Uri.IsHexDigit(c)))) throw new IOException();
            }
        }
        catch { Available = false; } // Preserve corrupt state; do not flood notifications after a reset.
    }
    public bool Reserve(string key, DateTimeOffset until, DateTimeOffset now)
    {
        if (!Available || until <= now) return false;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        if (_entries.TryGetValue(hash, out var previous) && previous > now) return false;
        foreach (var expired in _entries.Where(p => p.Value <= now).Select(p => p.Key).ToArray()) _entries.Remove(expired);
        if (_entries.Count >= 1024) return false; // Fail quiet, retain suppression of unexpired notifications.
        _entries[hash] = until;
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            File.WriteAllText(temporary, JsonSerializer.Serialize(_entries)); File.Move(temporary, _path, true);
            return true;
        }
        catch { Available = false; return false; }
        finally { try { if (File.Exists(temporary)) File.Delete(temporary); } catch { } }
    }
}
