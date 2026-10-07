# Real-LAN candidate acceptance extensions

This source candidate extends a80da0f with native Windows notifications and read-only device-aware Linux diagnostics. Production acceptance is distinct from source regression evidence. Historical acceptance plan; see [v0.4.0](checkpoint-v0.4.0.md) for current release status.

## Windows notifications

Unpackaged per-user Windows toast registration uses the Microsoft Notifications Toolkit, without administrator rights. Clicking a toast restores the Control Center and navigates; no policy action is encoded. Category preferences and foreground suppression apply. Windows notification settings/Do Not Disturb may suppress banners. Internal notification state is not proof of delivery. A labeled `--notification-acceptance` transport check runs with isolated configuration and never contacts production; its history/activation evidence is temporary.

System/health warning, failure and confirmed recovery can reach native notifications. In-memory condition suppression and a bounded per-user hash/expiry journal limit duplicates across restart; corrupt journal fails quiet and remains preserved. Only hashes/times persist, not device names, domains or credentials. Foreground unread notifications are retried once when backgrounded; continuously active conditions do not repeat indefinitely.

Schedule warnings poll authenticated Engine readback, not drafts. Status before/after must agree with policy instance/revision, clocks must be fresh, Safe Mode must be off, and a validated unexpired binding must support each device. Shared policy precedence proves all catalog domains currently Allow under an active schedule and become Block within ten minutes. Otherwise no warning is invented. UTC minute evaluation handles local timezone/overnight rules. Warning text names the registered/confirmed device, service and transition time, and states the forecast depends on unchanged Engine policy. DNS policy is not a guarantee that cached application sessions terminate at that instant.

Replaced/cancelled/incoherent schedule evidence withdraws pending/native history warnings on the next bounded poll (30 seconds plus request deadlines); toast expiration is the transition time. No queued future toasts survive offline stale evidence. Restart suppression keys include device/service/transition; unrelated policy revision changes cannot repeatedly warn the same transition. EN/HU internal text remains live; delivered Windows content uses the language at delivery.

Optional +15-minute extension actions are not implemented. Toast clicks cannot extend, restrict or mutate policy. Usage estimates never change filtering. Any future extension needs explicit confirmation, temporary expiry, deterministic provenance and audit.

## Device-aware diagnostics

Engine-owned aggregate counters feed the existing diagnostic snapshot/local publication; no second identity database or raw-query pipeline exists. Validated binding/registry DeviceIds combine observed IP changes. Unknown traffic is grouped by address/scope and stays Unknown, without a manufactured permanent DeviceId or retroactive assignment. Confirmed aliases come from current Engine policy; otherwise registered names are marked OBSERVED, not claimed as discovered hostnames. No inferred vendor/type is fabricated.

The extension is bounded to 64 source epochs, ten-minute aggregate buckets with up to one bucket (10 seconds) cutoff rounding, memory only. Eviction counts expose incomplete coverage. Last seen/last DNS activity, allowed/blocked/failed/SERVFAIL/dropped/rejected and separate rejected TCP connection counts are observed. Two coherent samples produce per-source rates and contribution; missing/reset samples remain unavailable. The fixed informational high-contribution hint is >=10 q/s and >=50%, never an automatic fault or enforcement action. Failure counts are diagnostic context, not proof of a specific incident's cause.

Local publication now uses owner-only 0600 because it contains aliases and addresses. Engine and installed Monitor must run under the same authorized owner. Other users are not implicitly authorized to read device context. The authenticated diagnostic API retains existing HTTPS/bearer security. No raw query domains, credentials, keys or complete policy are exported in this device view. Existing aggregate Monitor panels remain; device diagnostics has no rename/group/profile/schedule/policy/icon/ownership actions.

## Acceptance gates

Use real query ground truth after reviewed deployment. Source fixtures prove mechanics only. Record actual native banner/click UX, real health/recovery, authorized effective schedule warnings, real device binding/alias propagation, rates/outcomes vs query counts and identity uncertainty. Real DeviceId coverage cannot be claimed from address-only traffic. Router/DHCP configuration and privileged lifecycle/package installation remain manual human actions. Existing policy is preserved unless a separate explicit policy action is reviewed.


## Passive identity evidence and visible device diagnostics

Authenticated `/v2/identity-evidence` exposes at most 64 ephemeral address records from local OS adapters/hostname and, on Linux, the kernel ARP cache. It performs no active fingerprinting, router access or hostname probes. Kernel cache membership is not proof of current online state. Observed hostname and MAC are metadata, not a DeviceId or authoritative policy binding. Private/randomized MACs cannot establish permanent physical identity. No automatic registration or alias assignment occurs.

WPF combines this read-only Engine evidence with its existing bounded scan. The local Windows adapter fills its own missing MAC/name. Contradictory scan/Engine MAC evidence is not merged. Observed name/suggestion has a separate read-only column; the existing editable alias field remains. Confirmed aliases take precedence. Vendor-only evidence uses the existing limited OUI hint list, rejects locally administered MACs and never assigns a phone/type solely from the vendor. Unknown display remains first-class; heuristic type suggestions are inferred rather than confirmed.

Engine device diagnostics attach passive network evidence where available, while stable DeviceId still requires the existing reviewed registration and validated binding model. Monitor consumes that same evidence read-only; it neither discovers independent identities nor maintains a separate database. Device diagnostics opens expanded beneath the aggregate panels, inside a vertically scrollable Diagnostics page. A page heading and selected-tab contrast identify the current page. Actual GTK visibility and human recognizability remain acceptance gates after updated deployment.


## Compact device diagnostics presentation

Device diagnostics uses at most 64 compact rows, ranked by current coherent rate then retained received count. Name/uncertainty, current address, rate/recent queries, allowed/blocked/failed/dropped counts and last observation are visible together. Selection is retained by ephemeral tracking epoch across refresh/reordering; one detail pane shows MAC/hostname/DeviceId and outcome/timing evidence. First observation, provenance, connection-count semantics and visibility caveats are expandable. No unsupported device type/vendor or previous bindings are invented. Missing recent DNS is not labelled offline.

A client MAC may have no reverse-DNS hostname through the Engine DNS path. Windows OS knows its own local hostname but this is not automatically published as an Engine registry alias. Passive MAC evidence alone cannot determine a human name/owner or prove permanent identity, particularly with privacy MACs/IP changes. Automatic human identity remains partial; no real-device rename/registration is performed to obtain acceptance.
