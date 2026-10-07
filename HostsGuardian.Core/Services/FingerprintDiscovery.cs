using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using HostsGuardian.Core.Models;

namespace HostsGuardian.Core.Services;
/// <summary>Bounded standards discovery. Memory-only, explicit refresh, no execution-policy effect.</summary>
public static class FingerprintDiscovery
{
    private static readonly SemaphoreSlim Gate=new(1);
    private static FingerprintEvidence[] _evidence=[];
    private static DateTimeOffset _last;
    public static string LastReport {get;private set;}="Discovery not requested; absence of evidence is not absence of capability.";
    public static string Clean(string value)=>new(value.Where(c=>!char.IsControl(c)).Take(256).ToArray());
    public static FingerprintEvidence[] Snapshot(DateTimeOffset now)=>Volatile.Read(ref _evidence).Where(e=>e.ObservedAtUtc>=now.AddMinutes(-5)).ToArray();
    private static bool Local(IPAddress address)=>NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)
        .SelectMany(n=>n.GetIPProperties().UnicastAddresses).Any(a=>a.Address.AddressFamily==address.AddressFamily && SamePrefix(a.Address,address,a.PrefixLength));
    private static bool SamePrefix(IPAddress a,IPAddress b,int bits)
    {
        var x=a.GetAddressBytes();var y=b.GetAddressBytes();for(var i=0;i<x.Length;i++){var count=Math.Clamp(bits-i*8,0,8);var mask=count==0?0:256-(1<<(8-count));if((x[i]&mask)!=(y[i]&mask))return false;}return true;
    }
    public static async Task RefreshAsync(CancellationToken cancel=default)
    {
        if(!await Gate.WaitAsync(0,cancel))return;
        try
        {
            if(DateTimeOffset.UtcNow-_last<TimeSpan.FromMinutes(1))return;
            _last=DateTimeOffset.UtcNow;
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancel);timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var rows=new List<FingerprintEvidence>();var notes=new List<string>();
            await Task.WhenAll(Collect("mDNS",rows,notes,timeout.Token),Collect("SSDP",rows,notes,timeout.Token));
            Volatile.Write(ref _evidence,rows.DistinctBy(e=>(e.Address,e.Provider,e.Kind,e.Value)).Take(128).ToArray());
            LastReport=$"Bounded IPv4 multicast discovery: {rows.Count} evidence items. "+string.Join(" ",notes)+" IPv6 multicast provider not implemented; no reply is inconclusive.";
        }
        finally{Gate.Release();}
    }
    private static async Task Collect(string provider,List<FingerprintEvidence> rows,List<string> notes,CancellationToken cancel)
    {
        try
        {
            using var client=new UdpClient(AddressFamily.InterNetwork);
            client.Client.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
            client.Client.Bind(new IPEndPoint(IPAddress.Any,provider=="mDNS"?5353:0));
            var group=IPAddress.Parse(provider=="mDNS"?"224.0.0.251":"239.255.255.250");var port=provider=="mDNS"?5353:1900;
            if(provider=="mDNS")client.JoinMulticastGroup(group);
            client.Client.SetSocketOption(SocketOptionLevel.IP,SocketOptionName.MulticastTimeToLive,provider=="mDNS"?255:2);
            var request=provider=="mDNS"?MdnsQuery():Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
            await client.SendAsync(request,new IPEndPoint(group,port),cancel);
            var descriptions=new HashSet<string>();var count=0;
            while(count++<128)
            {
                var packet=await client.ReceiveAsync(cancel);if(packet.Buffer.Length>8192 || !Local(packet.RemoteEndPoint.Address))continue;
                var address=packet.RemoteEndPoint.Address.ToString();var now=DateTimeOffset.UtcNow;
                var parsed=provider=="mDNS"?ParseMdns(packet.Buffer,address,now):ParseSsdp(packet.Buffer,address,now);
                lock(rows){rows.AddRange(parsed.Take(Math.Max(0,128-rows.Count)));}
                if(provider=="SSDP" && descriptions.Count<4)
                {
                    var location=SsdpHeaders(packet.Buffer).GetValueOrDefault("location","");
                    if(SafeLocation(location,address) && descriptions.Add(location))
                    {
                        var description=await Description(location,address,cancel);
                        lock(rows){rows.AddRange(description.Take(Math.Max(0,128-rows.Count)));}
                    }
                }
            }
        }
        catch(Exception e) when(e is SocketException or OperationCanceledException or IOException or HttpRequestException)
        {lock(notes)notes.Add(provider+": "+(e is OperationCanceledException?"bounded window completed":"provider unavailable"));}
    }
    public static byte[] MdnsQuery()
    {
        using var stream=new MemoryStream();stream.Write(new byte[]{0,0,0,0,0,1,0,0,0,0,0,0});
        foreach(var label in "_services._dns-sd._udp.local".Split('.')){stream.WriteByte((byte)label.Length);stream.Write(Encoding.ASCII.GetBytes(label));}
        stream.Write(new byte[]{0,0,12,128,1});return stream.ToArray();
    }
    public static FingerprintEvidence[] ParseMdns(byte[] packet,string address,DateTimeOffset now)
    {
        try
        {
            if(packet.Length is <12 or >8192 || (packet[2]&128)==0)return [];
            int U16(int p){if(p+2>packet.Length)throw new FormatException();return(packet[p]<<8)|packet[p+1];}
            string Name(ref int offset)
            {
                var parts=new List<string>();var p=offset;var jumped=false;var seen=new HashSet<int>();
                for(var depth=0;depth<32;depth++)
                {
                    if(p>=packet.Length || !seen.Add(p))throw new FormatException();var length=packet[p++];
                    if(length==0){if(!jumped)offset=p;var result=string.Join('.',parts);if(result.Length>256)throw new FormatException();return result;}
                    if((length&192)==192){if(p>=packet.Length)throw new FormatException();var target=((length&63)<<8)|packet[p++];if(!jumped)offset=p;jumped=true;p=target;continue;}
                    if(length>63 || p+length>packet.Length)throw new FormatException();var label=Encoding.UTF8.GetString(packet,p,length);if(label.Any(char.IsControl))throw new FormatException();parts.Add(label);p+=length;
                }
                throw new FormatException();
            }
            var pos=12;var questions=U16(4);var records=U16(6)+U16(8)+U16(10);if(questions>32 || records>64)return [];
            for(var i=0;i<questions;i++){Name(ref pos);pos+=4;}
            var result=new List<FingerprintEvidence>();
            for(var i=0;i<records;i++)
            {
                var owner=Name(ref pos);var type=U16(pos);var expired=pos+8<=packet.Length && packet.AsSpan(pos+4,4).SequenceEqual(new byte[4]);pos+=8;var length=U16(pos);pos+=2;var end=pos+length;if(end>packet.Length)throw new FormatException();
                if(type==12 && !expired){var targetPos=pos;var target=Name(ref targetPos);if(targetPos>end)throw new FormatException();
                    if(owner.Equals("_services._dns-sd._udp.local",StringComparison.OrdinalIgnoreCase) && target.StartsWith('_') && target.EndsWith(".local",StringComparison.OrdinalIgnoreCase))result.Add(new(address,"mDNS","Service",target,now));}
                pos=end;
            }
            return result.ToArray();
        }
        catch(Exception e) when(e is FormatException or ArgumentException or IndexOutOfRangeException){return [];}
    }
    public static Dictionary<string,string> SsdpHeaders(byte[] packet)
    {
        var result=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);if(packet.Length>8192)return result;
        var lines=Encoding.UTF8.GetString(packet).Split("\r\n");if(lines.Length>64 || !lines[0].StartsWith("HTTP/1.1 200",StringComparison.Ordinal))return result;
        foreach(var line in lines.Skip(1)){var colon=line.IndexOf(':');if(colon<1)continue;var key=line[..colon].Trim();var value=line[(colon+1)..].Trim();if(value.Length>512 || value.Any(char.IsControl) || result.ContainsKey(key))return new();result[key]=value;}
        return result;
    }
    public static FingerprintEvidence[] ParseSsdp(byte[] packet,string address,DateTimeOffset now)
    {
        var h=SsdpHeaders(packet);return h.TryGetValue("st",out var role)?[new(address,"SSDP","DeviceRole",Clean(role),now)]:[];
    }
    public static bool SafeLocation(string location,string peer)=>Uri.TryCreate(location,UriKind.Absolute,out var uri) && uri.Scheme=="http" && uri.UserInfo=="" && uri.Fragment=="" && location.Length<=512 && IPAddress.TryParse(uri.Host,out var host) && IPAddress.TryParse(peer,out var address) && host.Equals(address) && !IPAddress.IsLoopback(host) && !host.Equals(IPAddress.Any);
    private static async Task<FingerprintEvidence[]> Description(string location,string address,CancellationToken cancel)
    {
        try
        {
            using var handler=new SocketsHttpHandler{AllowAutoRedirect=false,UseProxy=false,MaxResponseHeadersLength=8,ConnectTimeout=TimeSpan.FromMilliseconds(500)};
            using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(1)};
            using var response=await http.GetAsync(location,HttpCompletionOption.ResponseHeadersRead,cancel);if(!response.IsSuccessStatusCode || response.Content.Headers.ContentLength>16384)return [];
            using var input=await response.Content.ReadAsStreamAsync(cancel);using var buffer=new MemoryStream();var bytes=new byte[1024];int count;
            while((count=await input.ReadAsync(bytes,cancel))>0){if(buffer.Length+count>16384)return [];buffer.Write(bytes,0,count);}
            return ParseDescription(buffer.ToArray(),address,DateTimeOffset.UtcNow);
        }
        catch(Exception e) when(e is HttpRequestException or IOException or OperationCanceledException){return [];}
    }
    public static FingerprintEvidence[] ParseDescription(byte[] xml,string address,DateTimeOffset now)
    {
        if(xml.Length>16384)return [];
        try
        {
            using var input=new MemoryStream(xml);using var reader=XmlReader.Create(input,new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=16384});
            var document=System.Xml.Linq.XDocument.Load(reader);return document.Descendants().Where(e=>e.Name.LocalName is "deviceType" or "manufacturer" or "modelName" or "friendlyName").Take(16).Where(e=>e.Value.Length<=256 && !e.Value.Any(char.IsControl)).Select(e=>new FingerprintEvidence(address,"SSDP",e.Name.LocalName=="deviceType"?"DeviceRole":"Advertised "+e.Name.LocalName,e.Value,now)).ToArray();
        }
        catch(XmlException){return [];}
    }
}
