using System.Text.Json;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public sealed record MonitorEvent(DateTimeOffset AtUtc, string Level, string Component, string Message);
public sealed record LocalMonitorSnapshot(int SchemaVersion, DateTimeOffset EmittedAtUtc, int ProcessId,
    DateTimeOffset StartedAtUtc, DnsServiceStatus Status, MonitorEvent[] Events)
{
    public TopologySnapshot? Topology {get;init;}
    public ValidatorHealth? Validator {get;init;}
    public EngineDiagnosticsSnapshot? Diagnostics { get; init; }
    public OperationalEventBatch? OperationalEvents { get; init; }
}

/// <summary>Optional Engine-owned, read-only status file; independent of policy and management credentials.</summary>
public sealed class LocalMonitorStatusPublisher
{
    private readonly IEngineRuntimeStatus _status;
    private readonly string _path;
    private readonly Func<FullDnsPolicy>? _policy;
    private readonly Func<BindingRead>? _bindings;
    private readonly Func<ValidatorHealth>? _validator;
    private readonly DateTimeOffset _started = DateTimeOffset.UtcNow;
    public LocalMonitorStatusPublisher(IEngineRuntimeStatus status, string path,Func<FullDnsPolicy>? policy=null,Func<BindingRead>? bindings=null,Func<ValidatorHealth>? validator=null)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Monitor status path must be absolute");
        _status = status; _path = path; _policy=policy; _bindings=bindings; _validator=validator;
    }
    public void PublishOnce()
    {
        var directory = Path.GetDirectoryName(_path)!;
        if (!Directory.Exists(directory) || new DirectoryInfo(directory).LinkTarget != null || new FileInfo(_path).LinkTarget != null)
            throw new IOException("Monitor requires an owned, existing runtime directory");
        var snapshot=new LocalMonitorSnapshot(1, DateTimeOffset.UtcNow, Environment.ProcessId,
            _started, _status.GetSnapshot(), EngineLog.RecentEvents()) {
                Validator = _validator?.Invoke(),
                Diagnostics = (_status as EngineRuntimeStatus)?.Diagnostics?.Snapshot(),
                OperationalEvents = (_status as EngineRuntimeStatus)?.Diagnostics?.Health.Read()
            };
        if(_policy is not null && _bindings is not null && snapshot.Diagnostics?.Devices is {} devices)
        {
            string[] gateways=[];
            try{gateways=System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==System.Net.NetworkInformation.OperationalStatus.Up)
                .SelectMany(n=>n.GetIPProperties().GatewayAddresses).Select(g=>g.Address.ToString()).Take(8).ToArray();}catch(System.Net.NetworkInformation.NetworkInformationException){}
            snapshot=snapshot with{Topology=HostsGuardian.Core.Services.TopologyProjection.Build(_policy(),devices.LanDevices,_bindings(),snapshot.EmittedAtUtc,gateways:gateways,resolvers:snapshot.Diagnostics?.Resolvers)};
        }
        var bytes=SerializeBounded(snapshot);
        var temporary = Path.Combine(directory, ".monitor-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options)) { stream.Write(bytes); stream.Flush(true); }
            File.Move(temporary, _path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public static byte[] SerializeBounded(LocalMonitorSnapshot snapshot)
    {
        var options=new JsonSerializerOptions {PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
        var bytes=JsonSerializer.SerializeToUtf8Bytes(snapshot,options);
        if(bytes.Length>131072 && snapshot.Topology is not null)
        {
            snapshot=snapshot with{Topology=null};bytes=JsonSerializer.SerializeToUtf8Bytes(snapshot,options);
        }
        if(bytes.Length>131072 && snapshot.Diagnostics?.Devices is {} devices)
        {
            var compact=devices.LanDevices.Select(d=>d with {Evidence=d.Evidence.Take(1).ToArray(),EvidenceOmitted=d.EvidenceOmitted+Math.Max(0,d.Evidence.Length-1)}).ToArray();
            do
            {
                snapshot=snapshot with {Diagnostics=snapshot.Diagnostics with {Devices=devices with {LanDevices=compact,OmittedLanDevices=devices.OmittedLanDevices+devices.LanDevices.Length-compact.Length}}};
                bytes=JsonSerializer.SerializeToUtf8Bytes(snapshot,options);
                if(bytes.Length<=131072 || compact.Length==0)break;
                compact=compact.Take(compact.Length-1).ToArray();
            }while(true);
        }
        if(bytes.Length>131072)throw new IOException("Monitor snapshot exceeds limit");
        return bytes;
    }
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        var reported = false;
        do
        {
            try { PublishOnce(); reported = false; }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                if (!reported) EngineLog.Warning("Monitor", "Local status unavailable; Engine remains independent");
                reported = true;
            }
            try { if (!await timer.WaitForNextTickAsync(cancellationToken)) break; }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
        } while (!cancellationToken.IsCancellationRequested);
    }
}
