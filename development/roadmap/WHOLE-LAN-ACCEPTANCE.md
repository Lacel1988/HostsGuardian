# Phase 5E-8 — final human gate

State: WAITING_FOR_HUMAN after source integration verification. No router, DHCP,
firewall, networking, systemd, polkit or production deployment changes are automatic.

## Before any change

1. Identify the currently deployed Engine version, actual LAN address, advertised
   Management endpoint, certificate trust, policy revision/hash, Safe Mode, listener
   status and real router model/firmware. Use existing authenticated readback and
   Monitor/read-only diagnostics; do not infer current addresses from development
   examples. Record current DHCP DNS settings, lease duration and IPv6 DNS behavior.
2. Confirm a human-reviewed deployment/rollback plan for this source candidate
   before migrating production policy to schema 3. Export the currently authorized
   policy backup. Preserve existing package/candidate artifacts and credentials.
3. Investigate NeedDaemonReload=yes separately. Do not combine an unexplained
   systemd reload/restart with router acceptance or silently run daemon-reload.
4. Select at least two consenting real LAN clients, including one other than the
   Windows development machine. Record their current DNS configuration and valid
   DeviceId/binding evidence. Unsupported/ambiguous identity remains explicit.
5. Check alternate DNS paths (IPv6 DNS, client VPN/private DNS/DoH) and required
   rollback access. Do not change them without specific authorization.

If any precondition fails, stay WAITING_FOR_HUMAN and report the missing evidence.
Concrete address/model-specific commands are generated only after these read-only
facts are available; no placeholder command should be executed as a guess.

## Human action batch, once reviewed

1. If needed, install the reviewed Engine/Monitor source candidate using the
   separately approved deployment plan. Verify healthy UDP/TCP and authenticated
   Management first, with the original authorized policy still restored.
2. In the actual router's LAN/DHCP DNS settings, replace the reviewed primary DNS
   field with the verified Engine LAN address. Preserve a screenshot/export of
   previous settings. Do not invent a fallback that bypasses intended policy.
3. Renew DHCP leases on the selected clients using their normal OS network UI.
   Verify assigned DNS addresses before issuing user-chosen DNS queries.
4. Through WPF, register/review real devices and bindings if necessary. Preview
   narrowly scoped user-authorized group/profile/domain rules, explicitly deliver,
   and confirm instance/revision/hash readback. Never seed synthetic incidents or
   test domains into production without an explicit reviewed policy action.
5. On each real client, exercise the reviewed allowed/blocked cases for UDP and
   TCP, active/inactive schedules, device override and inherited group policy.
   Compare Engine winning/overridden evidence, DeviceId and mapping generation.
6. Close WPF and Monitor normally. Verify Engine DNS remains available from both
   clients. Reopen viewers and verify truthful fresh state and retained policy.
7. Explicitly exit any tested Safe Mode and restore/remove only the reviewed
   temporary policy changes. Confirm final semantic baseline with a fresh readback.

After each action, automatic read-only checks record current listener/management
state, client DNS evidence, policy revision/hash, binding identity, Engine decision
chain and bounded activity/incident evidence. Natural incident coverage remains
pending when no real incident occurs; it is never manufactured to claim PASS.

## Rollback

If resolution, authentication, identity or enforcement differs from the reviewed
expectation, stop the sequence. Restore the captured router DHCP DNS fields, renew
affected client leases, and verify ordinary resolution. If source deployment
caused the fault, use the reviewed previous package/service rollback separately,
retaining credentials and the prior authorized policy backup. A schema-3 policy
must not be fed blindly to an older Engine; restore the matching reviewed schema-2
backup under explicit human authorization. Preserve fault/audit evidence.

No network or privileged commands have been executed by this plan.
