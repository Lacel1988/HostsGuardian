using HostsGuardian.Core.Models;
using System.Net;
using System.Net.NetworkInformation;
namespace HostsGuardian.Core.Services;
public static class PassiveIdentityEvidence
{
    private static readonly object Gate=new();
    private static DateTimeOffset ReadAt;
    private static NetworkIdentityEvidence[] Cached=[];
    private static BindingEvidenceRead BindingCached=new(default,false,[]);
    // The same bounded kernel read feeds diagnostics and binding; ARP cache-only fallback is not trusted.
    public static BindingEvidenceRead ReadBindingEvidence()
    { lock(Gate) { Read(); return BindingCached; } }
    public static BindingEvidenceRead ParseBindingNeighbours(string json,DateTimeOffset now)
    {
        try {
            if(json.Length>65536)return new(now,false,[]);
            using var doc=System.Text.Json.JsonDocument.Parse(json);
            if(doc.RootElement.ValueKind!=System.Text.Json.JsonValueKind.Array || doc.RootElement.GetArrayLength()>=64)return new(now,false,[]);
            var bindingRows=new List<NetworkIdentityEvidence>();
            foreach(var item in doc.RootElement.EnumerateArray()) {
                if(item.ValueKind!=System.Text.Json.JsonValueKind.Object || !item.TryGetProperty("dst",out var dst) ||
                   !IPAddress.TryParse(dst.GetString(),out var ip) || !item.TryGetProperty("dev",out var dev) ||
                   string.IsNullOrWhiteSpace(dev.GetString()) || dev.GetString()!.Length>64 ||
                   !item.TryGetProperty("state",out var states) || states.ValueKind!=System.Text.Json.JsonValueKind.Array)
                    return new(now,false,[]);
                var names=states.EnumerateArray().Select(v=>v.GetString()).ToArray();
                if(names.Any(n=>string.IsNullOrEmpty(n)))return new(now,false,[]);
                var mac=item.TryGetProperty("lladdr",out var link)?DevicePolicyIdentity.NormalizeMac(link.GetString()):"";
                if((mac is "" or "00:00:00:00:00:00") && !names.Contains("FAILED") && !names.Contains("INCOMPLETE"))return new(now,false,[]);
                bindingRows.Add(new(ip.ToString(),mac,"","OBSERVED: kernel neighbour state; read time is not ownership confirmation",KernelTime(item,"updated",now) ?? now)
                    {ReadAtUtc=now,ConfirmedAtUtc=KernelTime(item,"confirmed",now),KernelUpdatedAtUtc=KernelTime(item,"updated",now),EvidenceTimeKnown=KernelTime(item,"updated",now)!=null,Interface=dev.GetString()!,NeighborState=string.Join("/",names),PrivateMacPossible=IsPrivateMac(mac)});
            }
            return new(now,true,bindingRows.ToArray());
        } catch(Exception e) when(e is System.Text.Json.JsonException or InvalidOperationException or ArgumentException) {return new(now,false,[]);}
    }
    public static NetworkIdentityEvidence[] Read()
    {
        lock(Gate)
        {
            if(DateTimeOffset.UtcNow-ReadAt<TimeSpan.FromSeconds(15))return Cached;
            ReadAt=DateTimeOffset.UtcNow;return Cached=ReadUncached();
        }
    }
    public static void Invalidate(){lock(Gate)ReadAt=default;}
    private static NetworkIdentityEvidence[] ReadUncached()
    {
        var now=DateTimeOffset.UtcNow; BindingCached=new(now,false,[]); var rows=new Dictionary<string,NetworkIdentityEvidence>();
        try
        {
            foreach(var adapter in NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback))
                foreach(var ip in adapter.GetIPProperties().UnicastAddresses.Where(a=>!IPAddress.IsLoopback(a.Address)))
                {
                    var address=ip.Address.ToString(); var mac=DevicePolicyIdentity.NormalizeMac(adapter.GetPhysicalAddress().ToString());
                    rows[adapter.Name+"|"+address+"|"+mac]=new(address,mac,new string(Environment.MachineName.Take(128).ToArray()),"OBSERVED: local OS adapter and hostname",now)
                        { Interface=adapter.Name, NeighborState="LOCAL", PrivateMacPossible=IsPrivateMac(mac) };
                    if(rows.Count>=64) return rows.Values.ToArray();
                }
            if(OperatingSystem.IsLinux())
            {
                var file=new FileInfo("/proc/net/arp");
                using var reader=file.OpenText(); int lines=0;
                while(reader.ReadLine() is {} line && ++lines<=256 && rows.Count<64)
                {
                    if(line.Length>512) continue;
                    var fields=line.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
                    if(fields.Length<6 || !IPAddress.TryParse(fields[0],out var address) || fields[2]!="0x2") continue;
                    var mac=DevicePolicyIdentity.NormalizeMac(fields[3]);
                    if(mac=="" || mac=="00:00:00:00:00:00") continue;
                    rows[fields[5]+"|"+address+"|"+mac]=new(address.ToString(),mac,"","OBSERVED: kernel neighbour cache; presence is not proof of online state",now)
                        {Interface=fields[5],NeighborState="CACHED",PrivateMacPossible=IsPrivateMac(mac)};
                }
                foreach(var item in ReadLinuxNeighbours(now))
                    if(rows.Count<64) rows[item.Interface+"|"+item.Address+"|"+item.Mac]=item;
            }
        }
        catch(Exception e) when(e is System.IO.IOException or UnauthorizedAccessException or NetworkInformationException) { }
        return rows.Values.Take(64).ToArray();
    }
    internal static bool IsPrivateMac(string mac) => mac.Length>=2 && byte.TryParse(mac[..2],System.Globalization.NumberStyles.HexNumber,null,out var first) && (first&2)!=0;
    public static NetworkIdentityEvidence[] ParseNeighbours(string json, DateTimeOffset now)
    {
        if(json.Length>65536) return [];
        var rows=new List<NetworkIdentityEvidence>();
        try
        {
            using var doc=System.Text.Json.JsonDocument.Parse(json);
            foreach(var item in doc.RootElement.EnumerateArray().Take(128))
            {
                if(!item.TryGetProperty("dst",out var dst) || !IPAddress.TryParse(dst.GetString(),out var ip) ||
                    !item.TryGetProperty("dev",out var dev) || !item.TryGetProperty("lladdr",out var link)) continue;
                var mac=DevicePolicyIdentity.NormalizeMac(link.GetString());if(mac=="" || mac=="00:00:00:00:00:00") continue;
                var states=item.TryGetProperty("state",out var state)?state.EnumerateArray().Select(s=>s.GetString()).ToArray():[];
                if(states.Contains("FAILED") || states.Contains("INCOMPLETE")) continue;
                var iface=dev.GetString()??"";if(iface.Length>64)continue;
                rows.Add(new(ip.ToString(),mac,"","OBSERVED: kernel neighbour state; read time is not ownership confirmation",KernelTime(item,"updated",now) ?? now)
                    {ReadAtUtc=now,ConfirmedAtUtc=KernelTime(item,"confirmed",now),KernelUpdatedAtUtc=KernelTime(item,"updated",now),EvidenceTimeKnown=KernelTime(item,"updated",now)!=null,Interface=iface,NeighborState=string.Join("/",states),PrivateMacPossible=IsPrivateMac(mac)});
            }
        }
        catch(Exception e) when(e is System.Text.Json.JsonException or InvalidOperationException or ArgumentException) {return [];}
        return rows.Take(64).ToArray();
    }
    private static NetworkIdentityEvidence[] ReadLinuxNeighbours(DateTimeOffset now)
    {
        try
        {
            using var p=new System.Diagnostics.Process {StartInfo=new("ip") {UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true}};
            p.StartInfo.ArgumentList.Add("-s");p.StartInfo.ArgumentList.Add("-j");p.StartInfo.ArgumentList.Add("neigh");p.Start();
            // A dedicated bounded reader avoids depending on a busy request/echo thread pool.
            var read=Task.Factory.StartNew(()=>ReadBounded(p.StandardOutput),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
            var errors=p.StandardError.ReadToEndAsync();
            if(!p.WaitForExit(1000)){p.Kill(true);return [];}
            if(!read.Wait(250) || p.ExitCode!=0)return [];
            BindingCached=ParseBindingNeighbours(read.Result,now);
            return ParseNeighbours(read.Result,now);
        }
        catch(Exception e) when(e is System.ComponentModel.Win32Exception or InvalidOperationException or System.IO.IOException) {return [];}
    }
    private static DateTimeOffset? KernelTime(System.Text.Json.JsonElement item,string field,DateTimeOffset readAt)
    {
        // ip -s -j reports ages in seconds. Missing/malformed ages fail closed.
        if(!item.TryGetProperty(field,out var value) || !value.TryGetInt64(out var seconds) || seconds<0 || seconds>315360000)return null;
        return readAt.AddSeconds(-seconds);
    }
    private static string ReadBounded(System.IO.StreamReader reader)
    {
        var chars=new char[65537];int count=0;
        while(count<chars.Length){var read=reader.Read(chars,count,chars.Length-count);if(read==0)break;count+=read;}
        return count>65536?"":new string(chars,0,count);
    }
}
