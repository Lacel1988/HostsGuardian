using System.Globalization;
using HostsGuardian.Core.Models;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace HostsGuardian.Core.Services;

public sealed record DeviceTypeDefinition(string Id,string Label,string IconKey,string[] Aliases,string[] HostnameHints,double[][][] Strokes)
{
    public string IconPath => string.Join(" ",Strokes.Select(points=>"M "+string.Join(" L ",points.Select(p=>p[0].ToString(CultureInfo.InvariantCulture)+","+p[1].ToString(CultureInfo.InvariantCulture)))));
}
public sealed record DeviceTypeAssessment(DeviceTypeDefinition Type,string Source,string Confidence,string Provenance)
{
    public string EvidenceState {get;init;}="CURRENT";
    public DateTimeOffset? LastClassifiedUtc {get;init;}
}
/// <summary>Shared presentation rules. Does not execute discovery, mutate registration, or classify inside Engine.</summary>
public static class DeviceTypes
{
    private sealed record Catalog(int SchemaVersion,DeviceTypeDefinition[] Types);
    public static IReadOnlyList<DeviceTypeDefinition> All { get; } = Load();
    private static DeviceTypeDefinition[] Load()
    {
        using var stream=typeof(DeviceTypes).Assembly.GetManifestResourceStream("HostsGuardian.Core.DeviceTypes.json")!;
        var catalog=JsonSerializer.Deserialize<Catalog>(stream,new JsonSerializerOptions {PropertyNameCaseInsensitive=true})!;
        if(catalog.SchemaVersion!=1)throw new InvalidOperationException("Unsupported type catalog");
        return catalog.Types;
    }
    public static DeviceTypeDefinition? Find(string? value) => All.FirstOrDefault(t=>string.Equals(t.Id,value,StringComparison.OrdinalIgnoreCase) || t.Aliases.Any(a=>string.Equals(a,value,StringComparison.OrdinalIgnoreCase)));
    public static DeviceTypeAssessment Present(string? confirmed,DeviceClassification? classification,IEnumerable<string> hostnames,DateTimeOffset now,InferredClassificationMemory? retained=null)
    {
        if(!string.IsNullOrWhiteSpace(confirmed))return Assess(confirmed,[]);
        if(retained is not null && retained.RetainUntilUtc>now && retained.Classification.AssessedAtUtc<=now.AddSeconds(5) && retained.Classification.DeviceType!="Unknown" && Find(retained.Classification.DeviceType) is not null && retained.Classification.Confidence is "Medium" or "High")
        {
            var last=retained.Classification;var conflict=classification?.ConflictingEvidence==true;
            var currentSupported=classification?.DeviceType==last.DeviceType && classification.Confidence is "Medium" or "High";
            var state=conflict?"CONFLICT":!currentSupported || (last.EvidenceFreshUntilUtc ?? last.AssessedAtUtc.AddMinutes(5))<now?"STALE":"CURRENT";
            return new(Find(last.DeviceType) ?? Find("Unknown")!,"INFERRED",last.Confidence,last.Reason+" "+string.Join("; ",retained.Provenance)+(conflict?" Current evidence conflicts; this is the last reliable inference.":"")){EvidenceState=state,LastClassifiedUtc=last.AssessedAtUtc};
        }
        if(classification is null)return Assess("",hostnames);
        if(classification.AssessedAtUtc<now.AddMinutes(-5) || classification.AssessedAtUtc>now.AddSeconds(5))return new(Find("Unknown")!,"UNKNOWN","Unknown","Classification expired; refresh observations.");
        return new(Find(classification.DeviceType) ?? Find("Unknown")!,classification.DeviceType=="Unknown"?"UNKNOWN":"INFERRED",classification.Confidence,classification.Reason);
    }
    public static DeviceTypeAssessment Assess(string? confirmedType,IEnumerable<string> observedHostnames)
    {
        var unknown=Find("Unknown")!;
        if(!string.IsNullOrWhiteSpace(confirmedType))return Find(confirmedType) is {} confirmed ?
            new(confirmed,"USER-CONFIRMED","User","Explicit user-owned type metadata; not physical identity evidence.") :
            new(unknown,"UNKNOWN","Unknown","Unrecognized user metadata retained; no automatic replacement.");
        var names=observedHostnames.Where(n=>!string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if(names.Length!=1)return new(unknown,"UNKNOWN","Unknown","Insufficient or conflicting observed hostname evidence; MAC/vendor alone is not a type.");
        var tokens=Regex.Split(names[0].ToLowerInvariant(),"[^a-z0-9]+").ToHashSet(StringComparer.Ordinal);
        var hints=All.Where(t=>t.HostnameHints.Any(tokens.Contains)).ToArray();
        return hints.Length==1 ? new(hints[0],"INFERRED","Low","Observed hostname category hint; name is not proof of device type.") :
            new(unknown,"UNKNOWN","Unknown","No unique supported hostname category hint; MAC/vendor alone is not a type.");
    }
}
