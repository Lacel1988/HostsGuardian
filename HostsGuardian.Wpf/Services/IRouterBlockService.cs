using System.Threading.Tasks;

namespace HostsGuardian.Wpf.Services
{
    public interface IRouterBlockService
    {
        Task<string> GetSnapshotAsync();
        Task<(bool ok, string message)> ApplyDomainBlockAsync(string domain);
        Task<(bool ok, string message)> RemoveDomainBlockAsync(string domain);
    }
}
