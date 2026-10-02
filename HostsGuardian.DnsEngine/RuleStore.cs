using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace HostsGuardian.DnsEngine;

public sealed class RuleStore
{
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);
    private readonly HashSet<string> _blocked = new(StringComparer.OrdinalIgnoreCase);

    public string InstanceId { get; }

    public RuleStore(string instanceId)
    {
        InstanceId = instanceId;
    }

    public string[] GetBlockedDomains()
    {
        _lock.EnterReadLock();
        try
        {
            return _blocked.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        finally { _lock.ExitReadLock(); }
    }

    public void SetBlockedDomains(IEnumerable<string> domains)
    {
        var normalized = NormalizeMany(domains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        _lock.EnterWriteLock();
        try
        {
            _blocked.Clear();
            foreach (var d in normalized) _blocked.Add(d);
        }
        finally { _lock.ExitWriteLock(); }
    }

    public void AddBlockedDomains(IEnumerable<string> domains)
    {
        var normalized = NormalizeMany(domains).ToArray();

        _lock.EnterWriteLock();
        try
        {
            foreach (var d in normalized) _blocked.Add(d);
        }
        finally { _lock.ExitWriteLock(); }
    }

    public bool RemoveBlockedDomain(string domain)
    {
        var d = NormalizeOne(domain);
        if (d.Length == 0) return false;

        _lock.EnterWriteLock();
        try { return _blocked.Remove(d); }
        finally { _lock.ExitWriteLock(); }
    }

    public bool IsBlocked(string domain)
    {
        var d = NormalizeOne(domain);
        if (d.Length == 0) return false;

        _lock.EnterReadLock();
        try
        {
            // Pontos match
            if (_blocked.Contains(d)) return true;

            // Subdomain match is, ha a fő domain tiltva van.
            var labels = d.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length >= 3)
            {
                for (int i = 1; i < labels.Length - 1; i++)
                {
                    var parent = string.Join('.', labels.Skip(i));
                    if (_blocked.Contains(parent)) return true;
                }
            }

            return false;
        }
        finally { _lock.ExitReadLock(); }
    }

    private static IEnumerable<string> NormalizeMany(IEnumerable<string> domains)
    {
        foreach (var raw in domains ?? Enumerable.Empty<string>())
        {
            var d = NormalizeOne(raw);
            if (d.Length == 0) throw new ArgumentException("Invalid selected DNS domain.");

            yield return d;


        }
    }

    private static string NormalizeOne(string? raw) => HostsGuardian.Core.Models.DomainName.Normalize(raw);
}
