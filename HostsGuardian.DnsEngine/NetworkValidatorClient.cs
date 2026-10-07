using System.Net.Sockets;
using System.Text.Json;
using HostsGuardian.Core.Models;
namespace HostsGuardian.DnsEngine;

public interface IEndpointValidator
{
    Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest request,CancellationToken cancellation);
    Task<bool> ProbeAsync(CancellationToken cancellation)=>Task.FromResult(true);
    string FailureReason=>"Validator unavailable";
}

/// <summary>One bounded exchange; only a background producer calls this client.</summary>
public sealed class NetworkValidatorClient(string path,IValidatorEndpointTrust? trust=null):IEndpointValidator
{
    private readonly IValidatorEndpointTrust _trust=trust ?? new LinuxValidatorEndpointTrust();
    private string _failure="Not checked";
    public string FailureReason=>Volatile.Read(ref _failure);
    private static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
    public async Task<EndpointValidationResult?> ValidateAsync(EndpointValidationRequest request,CancellationToken cancellation)
        =>await ExchangeAsync(request,cancellation) as EndpointValidationResult;
    public async Task<bool> ProbeAsync(CancellationToken cancellation)=>await ExchangeAsync(null,cancellation) is true;
    private async Task<object?> ExchangeAsync(EndpointValidationRequest? request,CancellationToken cancellation)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            var before=_trust.Inspect(path);
            using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint(path),deadline.Token);
            _trust.Authenticate(socket,before,path);
            using var stream=new NetworkStream(socket);
            var greeting=new byte[64];var greetingCount=0;
            while(greetingCount<greeting.Length)
            {
                if(await stream.ReadAsync(greeting.AsMemory(greetingCount,1),deadline.Token)==0)throw new IOException("Validator rejected caller or stopped");
                if(greeting[greetingCount++]==10)break;
            }
            if(System.Text.Encoding.ASCII.GetString(greeting,0,greetingCount)!="HG-NETWORKVALIDATOR/2 AUTHORIZED\n")throw new IOException("Validator authorization greeting invalid");
            Volatile.Write(ref _failure,"Authenticated IPC ready");
            if(request is null)return true; // Health probe never requests ARP.
            var bytes=JsonSerializer.SerializeToUtf8Bytes(request,Json);
            if(bytes.Length>1023)return null;
            await stream.WriteAsync(bytes,deadline.Token);await stream.WriteAsync(new byte[]{10},deadline.Token);
            var response=new byte[4096];var count=0;
            while(count<response.Length)
            {
                var read=await stream.ReadAsync(response.AsMemory(count,1),deadline.Token);
                if(read==0)return null;
                if(response[count++]==10)break;
            }
            if(count==response.Length || response[count-1]!=10)return null;
            return JsonSerializer.Deserialize<EndpointValidationResult>(response.AsSpan(0,count-1),Json);
        }
        catch(Exception e) when(e is SocketException or IOException or JsonException or OperationCanceledException or ArgumentException or DllNotFoundException or EntryPointNotFoundException)
        {Volatile.Write(ref _failure,e is OperationCanceledException?"Validator readiness/exchange timeout":"Validator endpoint unavailable or untrusted: "+e.GetType().Name);return null;}
    }
}
