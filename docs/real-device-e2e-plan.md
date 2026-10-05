# Representative real-device E2E plan — prepared, NOT started

Phase 5E-8 whole-LAN/router/DHCP acceptance remains PAUSED. Use Lenovo, one phone,
and one TV/TV box only. Begin after Vivo monitor/Engine runtime validation and
explicit approval for each networking, deployment, credential or runtime-policy
operation. Do not change router/DHCP or test every household device.

## Preflight and rollback evidence

1. Read the existing committed full policy/revision/instance, runtime status,
   mapping generation/observations and this PC's resolver configuration. Preserve
   canonical baseline policy and existing system configuration in approved storage.
   Never export bearer tokens/private certificates in the test evidence.
2. Record Engine endpoint/listeners, configured upstream, timestamps, policy-file
   restore health and exact installed service. Identify rollback commands from
   these observed settings. Do not guess interface names/unit names or prior DNS.
3. Obtain approval before assigning a test device's DNS directly to the Engine,
   modifying policy/bindings, restarting the service, or changing Safe Mode.
   Keep changes isolated to representative devices; do not alter router/DHCP.
4. Confirm browser/OS encrypted DNS, VPN, mobile data and caches do not bypass the
   tested resolver. Human phone/TV interaction is required for these settings.
   Browser playback/blocking alone does not prove DNS-source identity.

## Automated evidence available before physical testing

Regression fixtures already prove UDP/TCP identity propagation, actual device
Allow/Block/Safe Mode decisions on loopback, policy isolation, mapping expiry,
conflict/reassignment, persistence/restart, authentication and CAS/readback.
`/v2/dns-observations` provides bounded authenticated evidence of actual packets;
`/v2/effective-policy` explains current binding/rule decisions without mutation.
Canonical full-policy readback and revision/instance guards detect mismatches.
Bindings intentionally expire and are not restored after restart.

## Minimal physical sequence

Choose approved benign test domains (for example example.com and example.org),
and preserve all unrelated production rules/device registrations. Build the
complete candidate policy for review before asking to authorize replacement.
Use fresh queries/subdomains and the authoritative DNS observations to avoid
conflating cached application behavior with a new Engine request.

| Step | Expected proof | Human interaction |
|---|---|---|
| Observe queries before registration | Actual Lenovo/phone/TV source IPv4 identities and transport/timestamp appear in Engine observations; router-proxy/NAT collapse is detected | Trigger a fresh query on each phone/TV; select resolver as approved |
| Review registry and mappings | Unique DeviceIds with honest MAC evidence/provenance; explicitly validated current scoped IP bindings with short expiry; no identity inferred from port/name | Verify device settings/MAC/address; approve binding observations |
| Global block with all devices Inherit | Each received test query resolves to the correct DeviceId and global Block; unknown/unbound clients also use global | Trigger fresh phone/TV requests |
| Phone Allow override | Phone's matching global block is bypassed; Lenovo/TV remain blocked | Fresh phone and TV requests |
| TV Block override on globally allowed domain | TV blocked; Lenovo/phone allowed; parent/exact behavior matches the reviewed candidate | Fresh TV and phone requests |
| Interleave queries | Actual identities and effective decisions remain isolated between the three devices | Trigger each representative device |
| Safe Mode enter/exit | All filtering bypassed; full policy bytes/revision unchanged; exit restores decisions | Trigger phone/TV during bypass and after exit; approve runtime Safe Mode action |
| Approved Engine restart | Complete committed policy/revision restore; binding generation resets; devices inherit global until explicitly refreshed/validated bindings restore overrides | Approve service restart; fresh phone/TV queries after mapping refresh |
| Cleanup/rollback | Restore original full policy using CURRENT expected revision/instance; restore original bindings or clear test observations; restore each device's original resolver settings | Restore phone/TV settings and approve runtime/Windows changes |

A policy rollback is a new policy edit, so revision advances; never force an old
revision back into the Engine. Safe Mode alone changes no revision. If source IPs
collapse to a router/proxy, mappings conflict, scopes overlap, or a device bypasses
DNS, STOP acceptance and document the observation; do not invent identity or
modify the router to rescue the test.

## Approval format for the continuation

```
HUMAN ACTION REQUIRED
MACHINE: LENOVO or VIVO
WHY: <observed reason for the sensitive operation>
EXACT ACTION: <reviewed command/configuration/policy and rollback>
```

No physical-device requests or runtime policy/network changes were executed during
this Windows source checkpoint.
