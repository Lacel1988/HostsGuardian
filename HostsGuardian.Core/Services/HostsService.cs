using System.Text;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public sealed class HostsService
{
    private const string StartMarker = "# BEGIN HOSTSGUARDIAN";
    private const string EndMarker = "# END HOSTSGUARDIAN";
    private const string LegacyStart = "# HOSTSGUARDIAN BEGIN";
    private const string LegacyEnd = "# HOSTSGUARDIAN END";
    private readonly string _hostsPath;

    // An alternate path allows safe fixture tests without touching the system hosts file.
    public HostsService(string? hostsPath = null) => _hostsPath = hostsPath ?? PathsService.HostsPath;

    public sealed class PreviewInfo
    {
        public bool BlockPresent { get; set; }
        public int DomainCount { get; set; }
        public string PreviewText { get; set; } = "";
    }

    public bool IsBlockPresent() => ParseSections(File.ReadAllText(_hostsPath)).Count > 0;

    public string PreviewResult(AppConfig cfg) => PreviewResult(DomainPolicySelection.ForHosts(cfg.BlockedDomains)).PreviewText;

    public PreviewInfo PreviewResult(IEnumerable<string>? domains)
    {
        var list = ValidateDomains(domains);
        var original = File.ReadAllText(_hostsPath);
        return new PreviewInfo
        {
            BlockPresent = ParseSections(original).Count > 0,
            DomainCount = list.Length,
            PreviewText = Merge(original, list)
        };
    }

    public (bool ok, string message) Apply(AppConfig cfg)
    {
        try { return Apply(DomainPolicySelection.ForHosts(cfg.BlockedDomains)); }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public (bool ok, string message) Apply(IEnumerable<string> domains) => ApplyBlockedDomains(domains);

    public (bool ok, string message) ApplyBlockedDomains(IEnumerable<string> domains)
    {
        try
        {
            var list = ValidateDomains(domains);
            var original = File.ReadAllText(_hostsPath);
            var merged = Merge(original, list); // Validate ownership before any backup/write.
            var backup = CreateBackup();
            File.WriteAllText(_hostsPath, merged, ReadEncoding());
            if (File.ReadAllText(_hostsPath) != merged) throw new IOException("Hosts verification failed.");
            return (true, $"Applied {list.Length} selected hosts domain(s). Backup: {backup}");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public (bool ok, string message) Revert()
    {
        try
        {
            var original = File.ReadAllText(_hostsPath);
            var stripped = RemoveGuardianBlocks(original);
            if (stripped == original) return (true, "No HostsGuardian block to remove.");
            var backup = CreateBackup();
            File.WriteAllText(_hostsPath, stripped, ReadEncoding());
            if (File.ReadAllText(_hostsPath) != stripped) throw new IOException("Hosts revert verification failed.");
            return (true, $"HostsGuardian blocks removed. Backup: {backup}");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private Encoding ReadEncoding()
    {
        var prefix = new byte[4];
        using var stream = File.OpenRead(_hostsPath);
        var count = stream.Read(prefix, 0, prefix.Length);
        if (count >= 4 && prefix.SequenceEqual(new byte[] { 0xFF, 0xFE, 0, 0 })) return Encoding.UTF32;
        if (count >= 4 && prefix.SequenceEqual(new byte[] { 0, 0, 0xFE, 0xFF })) return new UTF32Encoding(true, true);
        if (count >= 3 && prefix[0] == 0xEF && prefix[1] == 0xBB && prefix[2] == 0xBF) return new UTF8Encoding(true);
        if (count >= 2 && prefix[0] == 0xFF && prefix[1] == 0xFE) return Encoding.Unicode;
        if (count >= 2 && prefix[0] == 0xFE && prefix[1] == 0xFF) return Encoding.BigEndianUnicode;
        return new UTF8Encoding(false);
    }

    public string CreateBackup()
    {
        var backup = _hostsPath + ".backup_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff") + "_" + Guid.NewGuid().ToString("N");
        File.Copy(_hostsPath, backup, overwrite: false);
        return backup;
    }

    public IReadOnlyList<string> ReadCurrentBlockedDomains()
    {
        var text = File.ReadAllText(_hostsPath);
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var section in ParseSections(text))
        {
            foreach (var line in text.Substring(section.start, section.length).Split('\n'))
            {
                var parts = line.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2 || parts[0].StartsWith('#')) continue;
                foreach (var item in parts.Skip(1))
                {
                    if (item.StartsWith('#')) break;
                    var domain = NormalizeDomain(item);
                    if (domain.Length > 0) domains.Add(domain);
                }
            }
        }
        return domains.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static string NormalizeDomain(string? raw) => DomainName.Normalize(raw);

    private static string[] ValidateDomains(IEnumerable<string>? input)
    {
        return (input ?? Array.Empty<string>()).Select(raw =>
        {
            var domain = NormalizeDomain(raw);
            if (domain.Length == 0) throw new ArgumentException("Invalid selected hosts domain.");
            return domain;
        }).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string Merge(string original, string[] domains)
    {
        var stripped = RemoveGuardianBlocks(original);
        if (domains.Length == 0) return stripped;
        var newline = original.Contains("\r\n") ? "\r\n" : "\n";
        var lines = new List<string> { StartMarker, "# Managed by HostsGuardian; use Revert Hosts to remove." };
        foreach (var domain in domains)
        {
            // Preserve the existing exact-domain + www-alias hosts behavior. No wildcard hosts entries.
            foreach (var alias in domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase)
                         ? new[] { domain } : new[] { domain, "www." + domain })
            {
                lines.Add("0.0.0.0 " + alias);
                lines.Add("::1 " + alias);
            }
        }
        lines.Add(EndMarker);
        return stripped + (stripped.Length > 0 && !stripped.EndsWith('\n') ? newline : "")
            + string.Join(newline, lines) + newline;
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
