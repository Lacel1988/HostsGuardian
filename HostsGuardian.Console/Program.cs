using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using System;
using System.Linq;

var configSvc = new ConfigService();
var logSvc = new AuditLogService();
var statusSvc = new StatusExportService();

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
            var dom = DomainName.Normalize(argsList[1]);
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
            var dom = DomainName.Normalize(argsList[1]);

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
    case "status":
        foreach (var domain in DomainPolicySelection.ForDns(configSvc.Load().BlockedDomains))
            Console.WriteLine(domain);
        Console.WriteLine("Local DNS selections; Engine synchronization is not verified here.");
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
    Console.WriteLine("  status");
    Console.WriteLine("  open-data");
}
