using System.IO;
using System.Text;
using System.Security.Cryptography;
namespace DesignPrototype.Engine;
public sealed class ReadOnlyCredential { readonly string _directory; public ReadOnlyCredential(string? directory=null){_directory=directory??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"HostsGuardian","credentials");} string FilePath(string id){if(!Guid.TryParseExact(id,"N",out _))throw new ArgumentException("Invalid credential reference");return Path.Combine(_directory,id+".bin");}
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
}
