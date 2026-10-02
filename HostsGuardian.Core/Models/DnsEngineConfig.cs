using System.Text.Json.Serialization;
namespace HostsGuardian.Core.Models;
public sealed class DnsEngineConfig
{
    public bool Enabled { get; set; }
    public string Address { get; set; } = "";
    public int ManagementPort { get; set; } = 3000;
    public string TrustedCertificate { get; set; } = ""; // Base64 public DER, explicitly enrolled.
    public string CredentialId { get; set; } = "";
    // Compatibility with existing callers/configuration. Secrets are never serialized.
    public string BaseUrl { get; set; } = "";
    [JsonIgnore] public string ApiToken { get; set; } = "";
    [JsonIgnore] public bool LegacyCredentialPresent { get; set; }
    public DateTime? LastSeenUtc { get; set; }
}
