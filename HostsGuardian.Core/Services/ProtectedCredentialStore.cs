using System.Security.Cryptography;
using System.Text;
using System.Runtime.Versioning;
namespace HostsGuardian.Core.Services;
public interface ICredentialStore
{
    string? Read(string id);
    void Write(string id, string token);
    void Delete(string id);
}
public sealed class ProtectedCredentialStore : ICredentialStore
{
    private readonly string _directory;
    public ProtectedCredentialStore(string? directory = null) => _directory = directory ?? Path.Combine(PathsService.AppFolder, "credentials");
    private string FilePath(string id)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new ArgumentException("Invalid credential reference");
        return Path.Combine(_directory, id + ".bin");
    }
    public string? Read(string id)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(FilePath(id)), null, DataProtectionScope.CurrentUser);
            try { var value = Encoding.UTF8.GetString(bytes); return ManagementSecurity.ParseToken(value) != null ? value : null; }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch { return null; }
    }
    public void Write(string id, string token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows credential storage required");
        if (ManagementSecurity.ParseToken(token) == null) throw new ArgumentException("Credential must be 64 hexadecimal characters");
        var path = FilePath(id);
        Directory.CreateDirectory(_directory);
        var bytes = Encoding.UTF8.GetBytes(token);
        try
        {
            var protectedBytes = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllBytes(temporary, protectedBytes);
            File.Move(temporary, path, true);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public void Delete(string id) => File.Delete(FilePath(id));
}
