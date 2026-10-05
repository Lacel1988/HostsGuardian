using System.Text.Json;
using HostsGuardian.Core.Models;
namespace HostsGuardian.Core.Services;
public sealed class ConfigService
{
    private readonly string _path;
    public ConfigService(string? path = null) => _path = path ?? PathsService.ConfigPath;
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    public AppConfig Load()
    {
        try
        {
            if (!File.Exists(_path)) return new AppConfig();
            var text = File.ReadAllText(_path);
            var cfg = JsonSerializer.Deserialize<AppConfig>(text, Options) ?? new AppConfig();
            cfg.BlockedDomains ??= new();
            cfg.DevicePolicies ??= new();
            cfg.DnsEngine ??= new();
            cfg.DeviceDomainPolicy = PolicyCanonicalization.Canonicalize(cfg.DeviceDomainPolicy ?? FullDnsPolicy.Empty);
            cfg.DnsEngine.LegacyCredentialPresent = LegacyToken(text) != null;
            return cfg;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException or IOException or UnauthorizedAccessException)
        { throw new InvalidDataException("Configuration is unreadable or invalid; original file retained", exception); }
    }
    private static string? LegacyToken(string text)
    {
        using var document = JsonDocument.Parse(text);
        if (document.RootElement.TryGetProperty("DnsEngine", out var engine) && engine.TryGetProperty("ApiToken", out var token)
            && token.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(token.GetString())) return token.GetString();
        return null;
    }
    public void Save(AppConfig cfg)
    {
        if (File.Exists(_path) && LegacyToken(File.ReadAllText(_path)) != null)
            throw new InvalidOperationException("Existing plaintext credential requires explicit migration before saving");
        Write(cfg);
    }
    private void Write(AppConfig cfg)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(cfg, Options));
        File.Move(temporary, _path, true);
    }
    public void MigrateCredential(AppConfig cfg, ICredentialStore store, string? explicitlyProvisionedReplacement = null)
    {
        var legacy = LegacyToken(File.ReadAllText(_path)) ?? throw new InvalidOperationException("No legacy credential found");
        var token = explicitlyProvisionedReplacement ?? legacy;
        if (ManagementSecurity.ParseToken(token) == null) throw new InvalidOperationException("Legacy credential format is incompatible; provision and explicitly replace it before migration");
        var id = Guid.NewGuid().ToString("N");
        store.Write(id, token);
        if (store.Read(id) != token) throw new InvalidOperationException("Protected credential verification failed");
        var previous = cfg.DnsEngine.CredentialId;
        cfg.DnsEngine.CredentialId = id;
        try { Write(cfg); cfg.DnsEngine.LegacyCredentialPresent = false; }
        catch { cfg.DnsEngine.CredentialId = previous; throw; } // Original plaintext file remains recoverable.
    }
}
