using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;

public static class DevicePolicyIdentity
{
    public static string NormalizeMac(string? value)
    {
        var hex = (value ?? "").Trim().Replace("-", "").Replace(":", "");
        if (hex.Length != 12 || !hex.All(Uri.IsHexDigit) || hex.All(c => c == '0') || hex.All(c => c == 'f' || c == 'F')) return "";
        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2).ToUpperInvariant()));
    }

    public static DevicePolicy? Find(IEnumerable<DevicePolicy> policies, string? mac)
    {
        var normalized = NormalizeMac(mac);
        if (normalized.Length == 0) return null;
        var matches = policies.Where(p => NormalizeMac(p.Mac) == normalized).Take(2).ToArray();
        // Duplicate/legacy identities require review, never choose a policy arbitrarily by IP.
        return matches.Length == 1 ? matches[0] : null;
    }

    public static void Save(List<DevicePolicy> policies, string ip, string mac, string name, bool blocked)
    {
        var normalized = NormalizeMac(mac);
        if (normalized.Length == 0) throw new ArgumentException("A valid observed MAC is required to save device policy safely.");
        var matches = policies.Where(p => NormalizeMac(p.Mac) == normalized).ToArray();
        if (matches.Length > 1) throw new InvalidDataException("Duplicate MAC policies require review.");
        var policy = matches.SingleOrDefault();
        if (policy == null) { policy = new DevicePolicy(); policies.Add(policy); }
        policy.Mac = normalized;
        policy.Ip = ip;
        policy.Name = name;
        policy.IsBlocked = blocked;
        policy.UpdatedAtUtc = DateTime.UtcNow;
    }
}
