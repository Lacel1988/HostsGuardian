using System.Text;
namespace HostsGuardian.Core.Services;

/// <summary>Explicit, one-time legacy migration only. Caller must authorize the target file.</summary>
public sealed class LegacyHostsCleanup
{
    private const string StartMarker = "# BEGIN HOSTSGUARDIAN";
    private const string EndMarker = "# END HOSTSGUARDIAN";
    private const string LegacyStart = "# HOSTSGUARDIAN BEGIN";
    private const string LegacyEnd = "# HOSTSGUARDIAN END";
    private readonly string _hostsPath;
    public LegacyHostsCleanup(string hostsPath) => _hostsPath = Path.GetFullPath(hostsPath);
    public bool IsBlockPresent() => ParseSections(ReadOriginal().text).Count > 0;
    public (bool ok, string message) Cleanup()
    {
        try
        {
            if (new FileInfo(_hostsPath).LinkTarget != null) throw new IOException("Linked hosts files require separate review.");
            var source = ReadOriginal();
            var original = source.text;
            var stripped = RemoveGuardianBlocks(original);
            if (stripped == original) return (true, "No HostsGuardian block to remove.");
            var backup = CreateBackup();
            if (!File.ReadAllBytes(_hostsPath).SequenceEqual(source.bytes)) throw new IOException("Hosts file changed during cleanup; mutation refused.");
            var output = source.encoding.GetPreamble().Concat(source.encoding.GetBytes(stripped)).ToArray();
            File.WriteAllBytes(_hostsPath, output);
            if (!File.ReadAllBytes(_hostsPath).SequenceEqual(output)) throw new IOException("Legacy cleanup verification failed.");
            return (true, $"HostsGuardian blocks removed. Backup: {backup}");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private (byte[] bytes, string text, Encoding encoding) ReadOriginal()
    {
        var bytes = File.ReadAllBytes(_hostsPath);
        Encoding encoding = bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE, 0, 0 }) ? new UTF32Encoding(false, true, true) :
            bytes.AsSpan().StartsWith(new byte[] { 0, 0, 0xFE, 0xFF }) ? new UTF32Encoding(true, true, true) :
            bytes.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }) ? new UTF8Encoding(true, true) :
            bytes.AsSpan().StartsWith(new byte[] { 0xFF, 0xFE }) ? new UnicodeEncoding(false, true, true) :
            bytes.AsSpan().StartsWith(new byte[] { 0xFE, 0xFF }) ? new UnicodeEncoding(true, true, true) : Encoding.Latin1;
        // BOM-less files use a reversible byte mapping, preserving UTF-8 and legacy code pages alike.
        var preamble = encoding.GetPreamble().Length;
        return (bytes, encoding.GetString(bytes, preamble, bytes.Length - preamble), encoding);
    }

    public string CreateBackup()
    {
        var backup = _hostsPath + ".backup_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff") + "_" + Guid.NewGuid().ToString("N");
        File.Copy(_hostsPath, backup, overwrite: false);
        return backup;
    }

    private static string RemoveGuardianBlocks(string text)
    {
        foreach (var section in ParseSections(text).AsEnumerable().Reverse())
            text = text.Remove(section.start, section.length);
        return text;
    }

    private static List<(int start, int length)> ParseSections(string text)
    {
        var sections = new List<(int, int)>();
        var start = -1;
        string? expectedEnd = null;
        for (var offset = 0; offset < text.Length;)
        {
            var lineEnd = text.IndexOf('\n', offset);
            var next = lineEnd < 0 ? text.Length : lineEnd + 1;
            var line = text.Substring(offset, next - offset).Trim();
            if (line.Equals(StartMarker, StringComparison.OrdinalIgnoreCase) || line.Equals(LegacyStart, StringComparison.OrdinalIgnoreCase))
            {
                if (start >= 0) throw new InvalidDataException("Nested HostsGuardian markers; hosts file left unchanged.");
                start = offset;
                expectedEnd = line.Equals(StartMarker, StringComparison.OrdinalIgnoreCase) ? EndMarker : LegacyEnd;
            }
            else if (line.Equals(EndMarker, StringComparison.OrdinalIgnoreCase) || line.Equals(LegacyEnd, StringComparison.OrdinalIgnoreCase))
            {
                if (start < 0 || !line.Equals(expectedEnd, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Unmatched HostsGuardian markers; hosts file left unchanged.");
                sections.Add((start, next - start));
                start = -1;
            }
            offset = next;
        }
        if (start >= 0) throw new InvalidDataException("Incomplete HostsGuardian block; hosts file left unchanged.");
        return sections;
    }
}
