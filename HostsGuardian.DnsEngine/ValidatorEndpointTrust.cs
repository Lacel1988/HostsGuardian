using System.Net.Sockets;
using System.Runtime.InteropServices;
namespace HostsGuardian.DnsEngine;

public sealed record EndpointFile(uint Owner,uint Group,ushort Mode,ulong Inode,uint DeviceMajor,uint DeviceMinor);
public interface IValidatorEndpointTrust
{
    EndpointFile Inspect(string path);
    void Authenticate(Socket socket,EndpointFile before,string path);
}

/// <summary>PID1-created socket, protected ancestors, no symlinks; UID alone is never trust.</summary>
public sealed class LinuxValidatorEndpointTrust:IValidatorEndpointTrust
{
    [DllImport("libc",SetLastError=true)] private static extern int statx(int dirfd,string path,int flags,uint mask,byte[] buffer);
    [DllImport("libc",SetLastError=true)] private static extern uint getegid();
    [DllImport("libc",SetLastError=true)] private static extern int getsockopt(int fd,int level,int option,byte[] value,ref uint length);
    public static void ValidateMetadata(EndpointFile file,bool socket,uint group)
    {
        if(file.Owner!=0 || (file.Mode&0xf000)!=(socket?0xc000:0x4000) ||
           (socket ? (file.Mode&0xfff)!=0x1b0 || file.Group!=group : (file.Mode&0x12)!=0))
            throw new IOException("Validator endpoint owner/type/permissions untrusted");
    }
    private static EndpointFile Read(string path)
    {
        var bytes=new byte[256];
        if(statx(-100,path,0x100|0x800,0x7ff,bytes)!=0 || (BitConverter.ToUInt32(bytes,0)&0x11b)!=0x11b)
            throw new IOException("Validator endpoint metadata unavailable");
        return new(BitConverter.ToUInt32(bytes,20),BitConverter.ToUInt32(bytes,24),BitConverter.ToUInt16(bytes,28),
            BitConverter.ToUInt64(bytes,32),BitConverter.ToUInt32(bytes,136),BitConverter.ToUInt32(bytes,140));
    }
    public EndpointFile Inspect(string path)
    {
        if(!OperatingSystem.IsLinux() || !Path.IsPathFullyQualified(path) || Path.GetFullPath(path)!=path || path.Contains("//",StringComparison.Ordinal) || path.Length>100)
            throw new IOException("Noncanonical validator endpoint");
        var group=getegid();var result=Read(path);ValidateMetadata(result,true,group);
        var parent=Path.GetDirectoryName(path)!;
        while(true)
        {
            ValidateMetadata(Read(parent),false,group);
            if(parent=="/")break;
            parent=Path.GetDirectoryName(parent)!;
        }
        return result;
    }
    public static void ValidateCreator(int pid,uint uid,uint gid)
    {
        if(pid!=1 || uid!=0 || gid!=0)throw new IOException("Validator listener was not created by PID1/root");
    }
    public void Authenticate(Socket socket,EndpointFile before,string path)
    {
        var credentials=new byte[12];uint length=12;
        if(getsockopt(socket.Handle.ToInt32(),1,17,credentials,ref length)!=0 || length!=12)
            throw new IOException("Validator peer credentials unavailable");
        ValidateCreator(BitConverter.ToInt32(credentials,0),BitConverter.ToUInt32(credentials,4),BitConverter.ToUInt32(credentials,8));
        if(Inspect(path)!=before)throw new IOException("Validator socket replaced during connection");
    }
}
