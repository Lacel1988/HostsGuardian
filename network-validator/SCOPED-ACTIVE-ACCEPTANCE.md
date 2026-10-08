# Scoped active IPv4 validation (startup configuration)

Engine executes; Monitor observes; WPF decides. This source change does not
authorize deployment or live probing. Existing helper authentication, PID1 socket,
CAP_NET_RAW separation and target/rate restrictions are unchanged.

## Activation

On the new candidate only, explicitly configure all three Engine environment
variables before startup:

```text
HOSTSGUARDIAN_ACTIVE_VALIDATION=1
HOSTSGUARDIAN_ACTIVE_VALIDATION_DEVICE_IDS=<registered-DeviceId-D-format>[,<another-approved-DeviceId>]
HOSTSGUARDIAN_ACTIVE_VALIDATION_SECONDS=120
```

Duration is an integer from 5 through 300 seconds; at most 64 unique, nonempty
registered GUIDs are accepted. No whitespace, empty entry or duplicate is accepted.
Missing/malformed/unknown/ambiguous scope or duration means passive-only mode,
never global probing. The old `ACTIVE_VALIDATION=1` alone no longer enables ARP.
`ACTIVE_VALIDATION=0` or unset preserves passive binding and IPC-only health.
The configured protected validator socket must also exist for active production.
No TV/device/address is a default. Registration must be unique initially and
remain present/unique. Removed approval becomes inactive until another startup.

For a separately approved human test, an Engine-specific temporary runtime
systemd override may carry those variables. Loading that override and restarting
the Engine is required for initial activation. No helper restart, capability grant,
policy edit or router change is needed. Do not execute against the old deployed
binary: it does not understand the scope/deadline and would use the global switch.

## Evidence and runtime deadline

Only allowlisted DeviceIds can become active candidates. Their MAC and IPv4 must
resolve uniquely through the current registry and complete fresh neighbour read.
STALE may select an exact candidate; only a fresh authenticated helper's matching
TargetedARP reply grants active evidence. IP/name alone, randomized-MAC aliases,
duplicate/conflicting evidence and IPv6 never create approved active bindings.

The window starts when startup configuration is parsed, using a monotonic clock.
The displayed UTC deadline is informational; UTC changes cannot extend approval.
A backwards/nonfinite/failing monotonic clock permanently disables that window.
No new exchange starts with less than three seconds remaining; an exchange has
a deadline of at most three seconds and results are rechecked against approval
and registry/evidence after the await. Late results cannot revive expired approval.
An immutable binding snapshot carries a monotonic validity guard: DNS reads reject
all active evidence immediately at expiry even with a frozen/backwards wall clock.
An independent watchdog restores passive publication without waiting for in-flight
IPC (scheduler dispatch may lag, but cannot extend active binding validity).
Passive production continues on the regular two-second cycle, without restart.
Accepted active observations are removed, not converted into passive evidence.
Only independently fresh REACHABLE evidence can produce subsequent passive bindings.
Helper failure creates no fresh active binding; existing accepted leases remain
bounded by their <=45-second evidence expiry AND the scoped monotonic deadline.

DNS request workers do not await ARP, IPC, discovery or passive refresh. Lack of a
validated identity falls back to global policy; it is not an automatic deny-all.
IPv6 DNS transport is supported, but IPv6 per-device binding remains unsupported.
ARP is an unauthenticated network claim, not cryptographic physical identity.

## Verification and rollback (human approval required)

Before startup record policy revision/hash/registrations, Safe Mode, executable
identity, unit/capability state and approved target list. Reserve a bounded test
window and prepare rollback. DNS restart interruption requires explicit approval.
Read existing protected Monitor status and authenticated management GET endpoints:

- `validator`: state (IPC health), mode, approvedTargetCount, deadlineUtc,
  remainingSeconds, modeReason, activeValidationEnabled, checkedAtUtc.
- `/v2/bindings`: exact observed IP/MAC, intended DeviceId, TargetedARP method,
  validation time/expiry/generation, compared with current approved registry.
- `/v2/effective-policy?address=<current-IP>&domain=<domain>` without invented scope:
  intended DeviceId and effective rule. This readback sends no policy.

Expected expiry: mode Passive, reason Expired, remainingSeconds 0, active flag
false; no accepted TargetedARP binding remains. READY may remain true: it only
means authenticated IPC. Natural DNS requests may prove actual attribution;
binding success does not prove Block policy or application blocking/coverage.
Unknown resolver paths remain Unknown. Preserve policy/Safe Mode/security hashes.

Normal end-of-window needs no restart: probing stops and passive production resumes.
Remove the temporary override and reload approved unit metadata afterward to
prevent a future restart rearming a fresh window. For emergency early rollback,
remove ONLY the acceptance override, reload metadata and restart Engine with
`HOSTSGUARDIAN_ACTIVE_VALIDATION=0`; confirm fresh OFF diagnostics and unchanged
policy. Preserve installed validator socket boot enablement and helper privileges.
Startup configuration intentionally permits a new window on a later restart if
the ON override is left installed; it is not a persistent one-shot grant.
