using System.Text.RegularExpressions;
namespace HostsGuardian.Core.Services;
public static class SecretRedactor
{
    public static string Clean(string? text) => Regex.Replace(Regex.Replace(text ?? "", @"(?i)Bearer\s+[^\s,;]+", "Bearer [REDACTED]"), @"(?i)[0-9a-f]{64}", "[REDACTED]");
}
