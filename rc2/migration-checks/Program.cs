using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.Loader;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

if(args.Length is <2 or >4) throw new ArgumentException("Read-only input policy, NEW private rehearsal directory, optional previous Engine DLL, optional userstore to COPY");
var input=Path.GetFullPath(args[0]);var output=Path.GetFullPath(args[1]);
if(Directory.Exists(output)||File.Exists(output))throw new ArgumentException("Output must not exist; no overwrite or in-place migration permitted");
if(!OperatingSystem.IsWindows())Directory.CreateDirectory(output,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);else Directory.CreateDirectory(output);
string Sha(string path)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
var sourceSha=Sha(input);var rows=new List<object>();
void Check(string name,bool pass){rows.Add(new{name,pass});File.WriteAllText(Path.Combine(output,"checks.json"),JsonSerializer.Serialize(rows,new JsonSerializerOptions{WriteIndented=true}));if(!pass)throw new InvalidOperationException(name);}
var backup=Path.Combine(output,"policy-before.json");File.Copy(input,backup);
var before=new PolicyPersistence(backup).Load();Check("Original copy accepted by new release",before.State=="Restored"&&before.Policy?.Policy is not null);
var old=before.Policy!.Policy!;var converted=PolicyCanonicalization.Canonicalize(old with{SchemaVersion=4,SavedDomains=DomainBlockList.Entries(old)});
var options=new JsonSerializerOptions{PropertyNamingPolicy=JsonNamingPolicy.CamelCase};
Check("Only schema and saved membership changed",JsonSerializer.Serialize(converted with{SchemaVersion=old.SchemaVersion,SavedDomains=old.SavedDomains},options)==JsonSerializer.Serialize(old,options));
var target=Path.Combine(output,"policy-schema4.json");
new PolicyPersistence(target).Commit(new(before.Policy.Revision+1,converted.GlobalBlockedDomains.ToArray()){Policy=converted},false);
Check("Schema4 reload",new PolicyPersistence(target).Load().Policy?.Policy?.SchemaVersion==4);
var domains=old.GlobalBlockedDomains.Concat(old.Overrides.Select(r=>r.Domain)).Distinct().ToArray();
var names=domains.Concat(domains.Select(d=>"child."+d)).Append("harmless.invalid").ToArray();
var ids=old.Devices.Select(d=>(Guid?)d.DeviceId).Append(null).ToArray();int compared=0;
foreach(var time in new[]{DateTimeOffset.UtcNow,DateTimeOffset.UtcNow.AddHours(6),DateTimeOffset.UtcNow.AddDays(1)})
 foreach(var id in ids)foreach(var domain in names){var a=PolicyDecision.Explain(old,id,domain,time);var b=PolicyDecision.Explain(converted,id,domain,time);if(JsonSerializer.Serialize(a.Winner,options)!=JsonSerializer.Serialize(b.Winner,options)||JsonSerializer.Serialize(a.Chain,options)!=JsonSerializer.Serialize(b.Chain,options))throw new Exception("Decision drift");compared++;}
Check("Global device child-domain decision chains unchanged",compared>0);
Check("Schema4 policy backup export import",JsonSerializer.Serialize(PolicyBackup.Import(PolicyBackup.Export(converted)),options)==JsonSerializer.Serialize(converted,options));
var rollback=Path.Combine(output,"policy-rollback.json");File.Copy(backup,rollback);
Check("Byte-exact rollback copy",Sha(rollback)==sourceSha);
if(args.Length>=3)
{
 var dll=Path.GetFullPath(args[2]);var context=new AssemblyLoadContext("previous-release-check",true);
 context.Resolving+=(_,name)=>{var p=Path.Combine(Path.GetDirectoryName(dll)!,name.Name+".dll");return File.Exists(p)?context.LoadFromAssemblyPath(p):null;};
 var assembly=context.LoadFromAssemblyPath(dll);var type=assembly.GetType("HostsGuardian.DnsEngine.PolicyPersistence")!;
 string Load(string path){var instance=Activator.CreateInstance(type,path)!;var value=type.GetMethod("Load")!.Invoke(instance,null)!;return (string)value.GetType().GetProperty("State")!.GetValue(value)!;}
 Check("Previous real Engine accepts unchanged original backup",Load(backup)=="Restored");
 Check("Previous real Engine rejects schema4 as expected",Load(target)=="Invalid");
 Check("Previous real Engine accepts byte-restored rollback",Load(rollback)=="Restored");context.Unload();
}
string? userSha=null;
if(args.Length==4)
{
 var users=Path.GetFullPath(args[3]);userSha=Sha(users);var auth=Path.Combine(output,"auth");
 if(!OperatingSystem.IsWindows())Directory.CreateDirectory(auth,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);else Directory.CreateDirectory(auth);
 var copy=Path.Combine(auth,"users.json");File.Copy(users,copy);if(!OperatingSystem.IsWindows())File.SetUnixFileMode(copy,UnixFileMode.UserRead|UnixFileMode.UserWrite);
 using(var directory=new UserDirectory(copy)){Check("Existing userstore loads without bootstrap or password change",directory.Initialized);}
 Check("Copied userstore byte unchanged after new Engine load",Sha(copy)==userSha);
 Check("Live source userstore unchanged",Sha(users)==userSha);
}
Check("Live/source policy never changed",Sha(input)==sourceSha);
File.WriteAllText(Path.Combine(output,"summary.json"),JsonSerializer.Serialize(new{pass=true,sourcePolicySha256=sourceSha,sourceRevision=before.Policy.Revision,targetRevision=before.Policy.Revision+1,decisionsCompared=compared,userstoreSha256=userSha,inPlaceMigration=false,liveLoginTested=false,checks=rows.Count},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"Offline migration and rollback: {rows.Count} PASS; {compared} equivalent decisions; no source writes");
