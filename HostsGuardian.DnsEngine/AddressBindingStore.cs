using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

/// <summary>Atomic, bounded observations; DNS workers only read a snapshot and evaluate freshness.</summary>
public sealed class AddressBindingStore
{
    private BindingRead _snapshot = new(0, []);
    private readonly object _gate = new();
    public BindingRead Read() => Volatile.Read(ref _snapshot);
    internal void PublishObserved(ImmutableArray<AddressBindingObservation> observations)
    {
        lock(_gate) {
            var current=Read();if(current.Observations.SequenceEqual(observations))return;
            if(current.Generation==long.MaxValue) { Volatile.Write(ref _snapshot,new(current.Generation,[]));return; }
            Volatile.Write(ref _snapshot,new(current.Generation+1,observations));
        }
    }
    public bool Replace(BindingReplace candidate)
    {
        if (candidate.Observations.IsDefault || candidate.Observations.Length > 4096) throw new ArgumentException("Invalid bindings");
        foreach (var observation in candidate.Observations)
        {
            if (observation == null || !IPAddress.TryParse(observation.Address, out var address) || address.AddressFamily != AddressFamily.InterNetwork
                || address.ToString() != observation.Address || observation.DeviceId == Guid.Empty
                || string.IsNullOrWhiteSpace(observation.Provenance) || observation.Provenance.Length > 128
                || observation.NetworkScope?.Length > 128 || observation.Interface?.Length > 64
                || (observation.MacEvidence!=null && HostsGuardian.Core.Services.DevicePolicyIdentity.NormalizeMac(observation.MacEvidence)!=observation.MacEvidence)
                || observation.ExpiresAtUtc <= observation.ObservedAtUtc
                || observation.ExpiresAtUtc - observation.ObservedAtUtc > TimeSpan.FromDays(1))
                throw new ArgumentException("Invalid binding observation");
        }
        lock (_gate)
        {
            var current = Read();
            if (current.Generation != candidate.ExpectedGeneration || current.Generation == long.MaxValue) return false;
            Volatile.Write(ref _snapshot, new(current.Generation + 1, candidate.Observations));
            return true;
        }
    }
    public static (Guid? DeviceId, string State) Resolve(BindingRead bindings, FullDnsPolicy policy,
        DnsRequestContext context, DateTimeOffset now)
    {
        if (!IPAddress.TryParse(context.SourceAddress, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            return (null, "UnsupportedAddressFamily");
        var observations = bindings.Observations.Where(b => b.Address == context.SourceAddress && b.NetworkScope == context.NetworkScope).ToArray();
        var fresh = observations.Where(b => b.Validated && b.ObservedAtUtc <= now && now < b.ExpiresAtUtc).ToArray();
        if (fresh.Length == 0) return (null, observations.Length == 0 ? "Unknown" : "StaleOrUnvalidated");
        var ids = fresh.Select(b => b.DeviceId).Distinct().ToArray();
        if (ids.Length != 1) return (null, "Ambiguous");
        var device = policy.Devices.SingleOrDefault(d => d.DeviceId == ids[0]);
        if (device == null) return (null, "Unregistered");
        if(fresh.Any(b=>b.MacEvidence!=null && HostsGuardian.Core.Services.DevicePolicyIdentity.NormalizeMac(device.Mac)!=b.MacEvidence))
            return (null,"StaleOrUnvalidated");
        if (device.Mac != null && policy.Devices.Count(d => d.Mac == device.Mac && (context.NetworkScope == null || d.Scope == device.Scope)) != 1)
            return (null, "AmbiguousStableIdentity");
        return (device.DeviceId, "Validated");
    }
}
