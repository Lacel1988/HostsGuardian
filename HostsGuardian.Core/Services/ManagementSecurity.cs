using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
public static class ManagementSecurity
{
    // Exactly 32 random bytes represented by 64 hexadecimal characters.
    public static byte[]? ParseToken(string? token)
    {
        if (token == null || token.Length != 64 || !token.All(Uri.IsHexDigit)) return null;
        return Convert.FromHexString(token);
    }
    public static bool Authorize(string[] headers, byte[] expected)
    {
        if (headers.Length != 1 || !headers[0].StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        var supplied = ParseToken(headers[0][7..]);
        return supplied != null && expected.Length == 32 && CryptographicOperations.FixedTimeEquals(supplied, expected);
    }
    public static Uri Endpoint(DnsEngineConfig cfg)
    {
        var address = cfg.Address;
        if (string.IsNullOrEmpty(address) && Uri.TryCreate(cfg.BaseUrl, UriKind.Absolute, out var old)) address = old.Host;
        if (Uri.CheckHostName(address) == UriHostNameType.Unknown || address.Contains('/') || address.Contains('@')
            || cfg.ManagementPort is < 1 or > 65535) throw new ArgumentException("Invalid connection settings");
        return new UriBuilder("https", address, cfg.ManagementPort).Uri;
    }
    public static bool ValidateCertificate(X509Certificate2? certificate, string enrolled, SslPolicyErrors errors)
    {
        if (certificate == null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
        try
        {
            using var trusted = new X509Certificate2(Convert.FromBase64String(enrolled));
            if (!CryptographicOperations.FixedTimeEquals(certificate.RawData, trusted.RawData)) return false;
            if (DateTime.UtcNow < certificate.NotBefore.ToUniversalTime() || DateTime.UtcNow > certificate.NotAfter.ToUniversalTime()) return false;
            var usage = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (usage == null || !usage.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == "1.3.6.1.5.5.7.3.1")) return false;
            // Explicit leaf enrollment permits only this self-signed identity, with validity/name/EKU checks above.
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(trusted);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Local enrolled certificate has no revocation service.
            return chain.Build(certificate);
        }
        catch { return false; }
    }
}
