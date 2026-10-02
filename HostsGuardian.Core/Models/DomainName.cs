using System.Globalization;

namespace HostsGuardian.Core.Models;

public static class DomainName
{
    // URL input is accepted, but never broaden a selected www/subdomain to its parent.
    public static string Normalize(string? raw)
    {
        var value = (raw ?? "").Trim();
        if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return "";
            value = uri.IdnHost;
        }
        value = value.TrimEnd('.');
        try { value = new IdnMapping().GetAscii(value).ToLowerInvariant(); }
        catch (ArgumentException) { return ""; }
        if (value.Length == 0 || value.Length > 253) return "";
        var labels = value.Split('.');
        if (labels.Length < 2) return "";
        foreach (var label in labels)
        {
            if (label.Length == 0 || label.Length > 63 || label[0] == '-' || label[^1] == '-') return "";
            if (label.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')) return "";
        }
        return value;
    }
}
