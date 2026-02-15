using System.Threading.Tasks;

namespace HostsGuardian.Wpf.Services
{
    // Biztonságos placeholder: nincs valódi router belenyúlás, csak irány.
    // Később: vendor API, OpenWrt, MikroTik, vagy saját DNS (Pi-hole jelleg).
    public sealed class RouterBlockService : IRouterBlockService
    {
        public Task<string> GetSnapshotAsync()
        {
            return Task.FromResult("Router blocking: not configured (placeholder).");
        }

        public Task<(bool ok, string message)> ApplyDomainBlockAsync(string domain)
        {
            return Task.FromResult((false, "Router blocking not implemented yet."));
        }

        public Task<(bool ok, string message)> RemoveDomainBlockAsync(string domain)
        {
            return Task.FromResult((false, "Router blocking not implemented yet."));
        }
    }
}
