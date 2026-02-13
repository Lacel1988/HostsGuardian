using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using System;
using System.Linq;

var configSvc = new ConfigService();
var logSvc = new AuditLogService();
var hostsSvc = new HostsService();
var statusSvc = new StatusExportService();

if (!AdminService.IsAdmin())
{
    Console.WriteLine("WARNING: Not running as Administrator. Apply/Revert will fail.");
    Console.WriteLine("Tip: Start terminal/VS as Administrator.");
}

var argsList = args.Select(a => a.Trim()).Where(a => a.Length > 0).ToList();
var cmd = argsList.Count > 0 ? argsList[0].ToLowerInvariant() : "help";

switch (cmd)
{
    case "help":
        PrintHelp();
        break;

    case "list":
        {
            var cfg = configSvc.Load();
            if (cfg.BlockedDomains.Count == 0) Console.WriteLine("(empty)");
            foreach (var d in cfg.BlockedDomains.OrderBy(d => d.Domain))
                Console.WriteLine(d.Domain);
        }
        break;

    case "add":
        {
            if (argsList.Count < 2) { Console.WriteLine("Usage: add example.com"); break; }
            var dom = HostsService.NormalizeDomain(argsList[1]);
            if (string.IsNullOrWhiteSpace(dom) || !dom.Contains('.'))
            {
                Console.WriteLine("Invalid domain.");
                break;
            }

            var cfg = configSvc.Load();
            if (cfg.BlockedDomains.Any(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("Already in list.");
                break;
            }

            cfg.BlockedDomains.Add(new DomainEntry { Domain = dom });
            configSvc.Save(cfg);

            logSvc.Write($"DOMAIN_ADD Added: {dom}", "INFO");
            Console.WriteLine($"Added: {dom}");
        }
        break;

    case "remove":
        {
            if (argsList.Count < 2) { Console.WriteLine("Usage: remove example.com"); break; }
            var dom = HostsService.NormalizeDomain(argsList[1]);

            var cfg = configSvc.Load();
            var item = cfg.BlockedDomains.FirstOrDefault(d => string.Equals(d.Domain, dom, StringComparison.OrdinalIgnoreCase));
            if (item == null) { Console.WriteLine("Not found."); break; }

            cfg.BlockedDomains.Remove(item);
            configSvc.Save(cfg);

            logSvc.Write($"DOMAIN_REMOVE Removed: {dom}", "INFO");
            Console.WriteLine($"Removed: {dom}");
        }
        break;

    case "preview":
        {
            var cfg = configSvc.Load();
            var preview = hostsSvc.PreviewResult(cfg);
            logSvc.Write($"PREVIEW_HOSTS Preview generated. Domains: {cfg.BlockedDomains.Count}", "INFO");
            Console.WriteLine(preview);
        }
        break;

    case "apply":
        {
            var cfg = configSvc.Load();
            hostsSvc.Apply(cfg);

            cfg.LastAppliedBy = AdminService.CurrentUser();
            cfg.LastAppliedAtUtc = DateTime.UtcNow;
            configSvc.Save(cfg);

            logSvc.Write($"APPLY_HOSTS Applied. Domains: {cfg.BlockedDomains.Count}", "INFO");
            Console.WriteLine("Applied.");
        }
        break;

    case "revert":
        {
            hostsSvc.Revert();
            logSvc.Write("REVERT_HOSTS Reverted HostsGuardian block.", "INFO");
            Console.WriteLine("Reverted.");
        }
        break;

    case "status":
        {
            var cfg = configSvc.Load();
            var active = hostsSvc.IsBlockPresent();

            var status = new AppStatus
            {
                HostsBlockActive = active,
                BlockedDomainCount = cfg.BlockedDomains.Count,
                LastAppliedBy = cfg.LastAppliedBy,
                LastAppliedAtUtc = cfg.LastAppliedAtUtc
            };

            var outPath = statusSvc.Export(status);

            Console.WriteLine($"Hosts active: {status.HostsBlockActive}");
            Console.WriteLine($"Blocked domains: {status.BlockedDomainCount}");
            Console.WriteLine($"Last applied by: {status.LastAppliedBy ?? "n/a"}");
            Console.WriteLine($"Last applied at (UTC): {(status.LastAppliedAtUtc.HasValue ? status.LastAppliedAtUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "n/a")}");
            Console.WriteLine($"Status file: {outPath}");
        }
        break;

    case "open-data":
        {
            Console.WriteLine(PathsService.AppFolder);
        }
        break;

    default:
        Console.WriteLine($"Unknown command: {cmd}");
        PrintHelp();
        break;
}

void PrintHelp()
{
    Console.WriteLine("HostsGuardian Console");
    Console.WriteLine("Commands:");
    Console.WriteLine("  list");
    Console.WriteLine("  add <domain>");
    Console.WriteLine("  remove <domain>");
    Console.WriteLine("  preview");
    Console.WriteLine("  apply    (admin required)");
    Console.WriteLine("  revert   (admin required)");
    Console.WriteLine("  status");
    Console.WriteLine("  open-data");
}
