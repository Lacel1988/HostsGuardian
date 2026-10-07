using System.Collections.Immutable;
using System.Text.Json;
using HostsGuardian.Core.Models;
using HostsGuardian.Core.Services;
using HostsGuardian.DnsEngine;

internal static class RoadmapPolicyTests
{
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
    public static void Run(Action<string,Action> test, string directory)
    {
        var device=Guid.NewGuid();var group=Guid.NewGuid();var profile=Guid.NewGuid();var service=Guid.NewGuid();
        ProgramRule Rule(DeviceDomainRuleState state) => new(Guid.NewGuid(),null,service,state);
        var p = new FullDnsPolicy(3,["fixture.invalid"],[new(device,"Device",null,"fixture","explicit")],[]) { Program = new(
            [new(group,"Kids",[device],[Rule(DeviceDomainRuleState.Allow),Rule(DeviceDomainRuleState.Block)])],
            [new(service,"Fixture service","user-1",["fixture.invalid","cdn.fixture.invalid"])],
            [new(profile,"School Night",true,true,false,[],[group],[Rule(DeviceDomainRuleState.Allow)])],[]) };
        p=PolicyCanonicalization.Canonicalize(p);
        var now=new DateTimeOffset(2026,1,5,22,0,0,TimeSpan.Zero);
        test("Roadmap schema3 profiles override groups while retaining conflicting and global evidence",()=>
        {
            var result=PolicyDecision.Explain(p,device,"cdn.fixture.invalid",now);
            Check(result.Winner.Layer==PolicyLayer.ActiveProfile && result.Winner.State==DeviceDomainRuleState.Allow,"Layer precedence lost");
            Check(result.Chain.Any(r=>r.Layer==PolicyLayer.DeviceGroup && r.State==DeviceDomainRuleState.Block) &&
                  result.Chain.Any(r=>r.Layer==PolicyLayer.DeviceGroup && r.State==DeviceDomainRuleState.Allow) &&
                  result.Chain.Any(r=>r.Layer==PolicyLayer.Global),"Overridden/conflicting evidence discarded");
        });
        test("Roadmap device override wins and same-layer Block wins over Allow",()=>
        {
            var withDevice=p with { Overrides=[new(device,"fixture.invalid",DeviceDomainRuleState.Allow),new(device,"cdn.fixture.invalid",DeviceDomainRuleState.Block)] };
            var result=PolicyDecision.Explain(withDevice,device,"cdn.fixture.invalid",now);
            Check(result.Winner.Layer==PolicyLayer.DeviceOverride && result.Winner.State==DeviceDomainRuleState.Block,"Device Block precedence lost");
            var groupsOnly=p with { Program=p.Program! with { Profiles=[] } };
            Check(PolicyDecision.Explain(groupsOnly,device,"fixture.invalid",now).Winner.State==DeviceDomainRuleState.Block,"Group conflict did not Block");
        });
        test("Roadmap same-layer Block beats a narrower Allow and preserves every candidate",()=>
        {
            var allow = new ProgramRule(Guid.NewGuid(),"cdn.fixture.invalid",null,DeviceDomainRuleState.Allow);
            var block = new ProgramRule(Guid.NewGuid(),"fixture.invalid",null,DeviceDomainRuleState.Block);
            var conflicting = p with { Program=p.Program! with { Profiles=[p.Program.Profiles[0] with { Rules=[allow,block] }] } };
            var result=PolicyDecision.Explain(conflicting,device,"cdn.fixture.invalid",now);
            Check(result.Winner.Layer==PolicyLayer.ActiveProfile && result.Winner.RuleId==block.RuleId,
                "Narrower Allow incorrectly defeated same-layer Block");
            Check(result.Chain.Any(r=>r.RuleId==allow.RuleId),"Losing Allow evidence discarded");
            var reversed=conflicting with { Program=conflicting.Program! with {
                Profiles=[conflicting.Program.Profiles[0] with { Rules=[block,allow] }],
                Groups=conflicting.Program.Groups.Reverse().ToImmutableArray() } };
            Check(result.Chain.SequenceEqual(PolicyDecision.Explain(reversed,device,"cdn.fixture.invalid",now).Chain),
                "Decision evidence depends on input enumeration order");
            var deviceAllow=conflicting with { Overrides=[new(device,"fixture.invalid",DeviceDomainRuleState.Allow)] };
            Check(PolicyDecision.Explain(deviceAllow,device,"cdn.fixture.invalid",now).Winner.State==DeviceDomainRuleState.Allow,
                "A less-specific layer Block incorrectly defeated Device Allow");
        });
        test("Roadmap unknown identity never acquires device or group policy",()=>
        {
            var result=PolicyDecision.Explain(p,null,"fixture.invalid",now);
            Check(result.Winner.Layer==PolicyLayer.Global && !result.Chain.Any(r=>r.Layer!=PolicyLayer.Global),"Unknown identity inherited group/profile");
        });
        test("Roadmap overnight schedules use explicit zone and previous starting day",()=>
        {
            var schedule=new PolicySchedule(Guid.NewGuid(),profile,"Bedtime",true,"Etc/UTC",[DayOfWeek.Monday],22*60,6*60);
            Check(PolicyDecision.Active(schedule,now) && PolicyDecision.Active(schedule,now.AddHours(7)) &&
                  !PolicyDecision.Active(schedule,now.AddHours(8)) && !PolicyDecision.Active(schedule,now.AddDays(1)),"Overnight/day boundary wrong");
            var scheduled=p with { Program=p.Program! with { Profiles=[p.Program.Profiles[0] with { AlwaysActive=false }],Schedules=[schedule] } };
            Check(PolicyDecision.Explain(scheduled,device,"fixture.invalid",now).Winner.ScheduleId==schedule.ScheduleId,"Schedule provenance missing");
            Check(PolicyDecision.Explain(scheduled,device,"fixture.invalid",now.AddHours(8)).Winner.Layer==PolicyLayer.DeviceGroup,"Inactive profile applied");
        });
        test("Roadmap references and unknown schedule zones fail before mutation",()=>
        {
            foreach(var invalid in new[]{ p with {Program=p.Program! with {Groups=[p.Program.Groups[0] with {DeviceIds=[Guid.NewGuid()]}]}},
                p with {Program=p.Program! with {Schedules=[new(Guid.NewGuid(),profile,"Invalid",true,"Not/AZone",[DayOfWeek.Monday],60,120)]}} })
            {
                var rejected=false;try{PolicyCanonicalization.Canonicalize(invalid);}catch(ArgumentException){rejected=true;}
                Check(rejected,"Invalid program accepted");
            }
        });
        test("Roadmap schema2 remains stable and schema3 persistence restores complete program",()=>
        {
            var legacy=PolicyCanonicalization.Canonicalize(FullDnsPolicy.Empty);
            Check(legacy.SchemaVersion==2 && !JsonSerializer.Serialize(legacy).Contains("Program"),"Legacy payload shape changed");
            var path=Path.Combine(directory,"roadmap-policy.json");var store=new PolicyPersistence(path);
            store.Commit(new(1,p.GlobalBlockedDomains.ToArray()){Policy=p},false);
            var read=store.Load();Check(read.Policy?.Policy?.SchemaVersion==3 && read.Policy.Policy.Program?.Groups.Length==1,"Program lost on restart");
            var application=new PolicyApplicationService(new RuleStore("roadmap-fixture"),store);
            application.InitializeForStartup();var before=File.ReadAllBytes(path);
            var result=application.SetSafeMode(true);application.SetSafeMode(false);
            Check(result.Success && File.ReadAllBytes(path).SequenceEqual(before) && application.ReadFullPolicy().Revision==1,"Safe Mode mutated persisted program");
        });
        test("Roadmap oversized explanation paths are rejected before any conflict evidence could be discarded",()=>
        {
            var profiles=Enumerable.Range(0,129).Select(_=>new ProgramRule(Guid.NewGuid(),"fixture.invalid",null,DeviceDomainRuleState.Allow)).ToImmutableArray();
            var tooLarge=p with {Program=p.Program! with {Profiles=[p.Program.Profiles[0] with {Rules=profiles}]}};
            var rejected=false;try{PolicyCanonicalization.Canonicalize(tooLarge);}catch(ArgumentException){rejected=true;}
            Check(rejected,"Unbounded explanation accepted");
        });
        test("Roadmap catalog definitions alone never create filtering policy",()=>
        {
            var catalogOnly=p with {GlobalBlockedDomains=[],Overrides=[],Program=p.Program! with {Groups=[],Profiles=[]}};
            var result=PolicyDecision.Explain(catalogOnly,device,"fixture.invalid",now);
            Check(result.Winner.State==DeviceDomainRuleState.Allow && result.Chain.Length==1,"Catalog seeded policy");
        });
    }
}
