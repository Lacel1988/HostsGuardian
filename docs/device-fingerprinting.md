# Device fingerprinting V1

## Ownership and evidence

Shared observation services collect and classify session evidence. The Engine hosts the existing authenticated discovery API and diagnostics transport; classification never participates in DNS policy execution, registration, stable identity or binding. WPF consumes inference and owns explicit user confirmation. Monitor displays read-only evidence. No presentation classifier or identity editor is added to Engine.

Evidence records contain observed address, provider, semantic kind, untrusted value and observation time. Classification contains inferred category, confidence, reason, evidence and assessment time. Address correlation is session-scoped, withheld for conflicting observations or omitted network evidence; it is not a permanent DeviceId association.

## Providers and confidence

- mDNS DNS-SD service enumeration: standard PTR query, response-only parsing with bounded compression traversal. Printing service types support Printer. Android-TV remote, generic casting and AirPlay roles alone cannot distinguish a TV from a streaming box and do not establish physical class.
- SSDP standard M-SEARCH: device-role advertisements. Standard printer and InternetGateway/WANConnection roles support Printer/Network. MediaRenderer alone remains a capability, not proof of TV/Speaker.
- UPnP descriptions: at most four advertised HTTP description URLs, only literal same-peer addresses on attached LAN prefixes. No redirects, proxy, credentials, external URL resolution or arbitrary port scan. Device role, manufacturer, model and friendly-name claims remain distinct observations. Manufacturer/model strings alone never classify.
- Existing observed hostname: conservative shared token vocabulary; Low confidence only. Friendly-name drafts and user aliases are not hostname evidence.
- ARP/NDP/local interface: existing transient correlation and presence. Private MAC explicitly makes OUI vendor unavailable. Existing sparse OUI hints are supporting context only, never category votes.

Confidence: one class-specific protocol role = Medium; distinct class-specific protocol providers agreeing = High; hostname or advertised category-name only = Low; a TV/Streaming/Speaker name hint with a compatible MediaRenderer role = Medium. This is agreement of untrusted claims, not physical proof. Repeated services from one provider cannot raise confidence. Any conflicting category vote produces Unknown with retained evidence. Unknown is successful uncertainty, not a failure. Advertisements can be forged; confidence is qualitative evidence agreement, not authenticated physical identity or calibrated probability.

Explicit user type, including Unknown, always wins. Invalid legacy user metadata is retained, not silently replaced. Inference never persists to user metadata. Fresh observation and historical inference are separate: a supported Medium/High result retains its type, confidence, classification timestamp and summarized provenance after the five-minute evidence TTL. Presentation says evidence stale; current conflicting evidence is explicit and the historical result does not claim current certainty. A new supported result can replace it. Low hints still expire to Unknown.

## Bounds and security

Explicit authenticated refresh only; one-minute debounce, five-second multicast window concurrent with existing six-second LAN refresh to fit the eight-second client deadline. IPv4 default multicast interface only in V1; IPv6-only services may remain unavailable. No automatic broad scanning added.

At most 128 datagrams/provider, 8192 accepted bytes/datagram, 128 retained evidence items, 32 items per classification. Excess classification evidence produces Unknown. Raw fingerprint evidence has a five-minute memory-only lifetime. The last reliable summary has at most 64 session-observation keys, four provenance entries and a 24-hour cap; identical evidence does not renew its timestamp or retention. It retains no raw evidence array, hostnames, model descriptions or addresses. Restart clears inference. Provisional LAN observations retain the existing ten-minute expiry and may disappear; a new session observation does not inherit a historical summary from IP alone. No permanent raw packet retention or new telemetry pipeline. Existing owner-only publisher payload limits remain enforced.

mDNS accepts at most 32 questions/64 records and 32 compression steps; malformed/truncated data and goodbye TTL-zero records do not classify. SSDP rejects oversized, duplicate or control-bearing headers. Descriptions use strict timeouts, a 16 KiB cap, XML DTD prohibition and no external resolver. LAN strings have length/control-character limits. Missing/unavailable providers retain truthful Unknown.

WPF uses localized category/confidence labels and shared vector icons; detailed evidence is under identification details. Monitor shows evidence under technical details. User-confirmed metadata remains delivered only by explicit policy delivery.

## Classifier coverage audit

The shared model/UI has 13 choices: Unknown, Phone, Tablet, Laptop, Computer, TV, Streaming, Console, Speaker, Printer, Network, IoT and Server. Unknown is the truthful fallback, not an inferable physical category. IoT is currently manual-only. The other eleven types can be inferred, often only weakly:

| Type | Exact supported tokens / protocol evidence | Maximum current confidence | Deterministic coverage |
|---|---|---|---|
| Phone | `iphone`, `phone` name tokens | Low | every catalog token |
| Tablet | `ipad`, `tablet` | Low | every catalog token |
| Laptop | `laptop`, `notebook` | Low | every catalog token |
| Computer | `desktop` | Low | every catalog token |
| TV | `tv`, `television`; compatible SSDP MediaRenderer role | Medium with name + renderer; otherwise Low | all tokens, renderer agreement, conflicts |
| Streaming | `chromecast`, `settop`; compatible MediaRenderer | Medium with name + renderer; otherwise Low | all tokens, renderer agreement |
| Console | `xbox`, `playstation` | Low | every catalog token |
| Speaker | `speaker`; compatible MediaRenderer | Medium with name + renderer; otherwise Low | token, renderer agreement |
| Printer | `printer`; mDNS `_ipp._tcp.local`, `_ipps._tcp.local`, `_printer._tcp.local`; SSDP Printer:1 | High when mDNS and SSDP class-specific roles agree; otherwise Medium protocol / Low name | all services, SSDP XML/role, independent agreement, duplicates |
| Network | `router`; SSDP InternetGatewayDevice:1, WANConnectionDevice:1 | Medium protocol / Low name | both roles, token |
| Server | `server`, `nas` | Low | every catalog token |
| IoT | no automatic rule | manual only | negative unsupported-name test |
| Unknown | insufficient, malformed, expired weak, generic or conflicting signals | Unknown | empty, generic casting, vendor-only, hostile, stale and conflict tests |

Name tokens apply to observed hostname or advertised friendlyName, never user alias/draft. Tokens match words split on non-ASCII alphanumerics, not arbitrary substrings. Existing `iphone`, `ipad`, `chromecast`, `xbox`, `playstation` are explicitly brand/family-specific *weak name hints*, not vendor/OUI/model-based identification. No router-vendor, Samsung model, household IP/MAC, LAN prefix or environment condition is used. Their presence does not authenticate ownership or device category.

False positives remain possible from renamed devices, spoofed advertisements, print-server capabilities, virtual gateways and renderer-capable computers. MediaRenderer plus an arbitrary name is qualitative agreement, not physical proof. A name hint contradicting a strong role yields Unknown rather than suppressing the disagreement; a previously reliable summary is displayed as historical with a conflict warning. Two protocol claims are not cryptographically independent identity proof. Generic casting, AirPlay, Android-TV remote and manufacturer/model alone remain Unknown.

Fixed within V1: evidence-expiry semantics, localized selector rendering, complete deterministic coverage of existing rules, bounded historical summaries, and inventory lifecycle view/removal gaps. Deferred deliberately: stronger automatic Phone/Tablet/Laptop/Computer/Console/Server/IoT rules, IPv6 multicast enrichment, authenticated physical classification, long-term inferred-class persistence and persisted observation history. No weak heuristic was added to inflate coverage.

## Registered inventory versus discovery

Readback compatibility: WPF captures supported inference even when an older Engine supplies only current classification. A bounded `ClassificationReadModel` reuses the existing summary cache, keyed by the producer's session observation GUID; the API client retains it across row reconstruction and each DeviceVm retains it across updates. Changing Engine endpoint/credential reference resets the client readback scope. IP/name alone never imports a summary into a different observation. Explicit user type wins; valid retained inference wins over current Unknown/Low. New supported classification updates the summary before presentation, while a contradictory classification remains explicit conflict evidence. The UI expiry timer continues normally and marks retained evidence stale instead of erasing type. No classification history can be recovered if the first read arrives after evidence expired and the producer supplies neither historical summary nor fresh supported class.

The existing persisted `FullDnsPolicy.Devices` registry is the inventory, not the live observation store. WPF loads known devices at startup, keeps them during scans and appends absent registrations after refresh. Friendly alias, confirmed type, owner/location and group memberships remain user-owned persistent policy state. Known and discovered rows are explicitly distinguished. Absence means presence unknown, not proven Offline; cached neighbour evidence never proves Online. Last seen is preserved where available in the current WPF session; after restart it is unknown unless new evidence exists. No permanent observation store was added. Monitor remains a bounded live diagnostic view, not an inventory editor.

Registration existence is checked against that persisted registry, not inferred from a non-null row DeviceId. After successful Engine-policy import and local persistence, WPF reconciles existing rows: orphaned associations lose the DeviceId, deleted friendly name, type draft/confirmation and groups, while retaining their network observation and supported inference. Valid registrations receive imported metadata; ambiguous observations stay provisional beside a separate registered inventory row. Defensive save recovers an orphan and reports that explicit registration is required instead of logging a successful identity save. Register validates actual membership and permits explicit registration of a recovered row with a new DeviceId. No deleted user metadata is silently re-created.

Returning observations use the existing unique, explicit registered-MAC association, with provenance and randomized-MAC caveats. IP/name alone, multiple MACs, duplicate observations or omitted evidence cannot merge a registration. A registered row remains separately visible when correlation is ambiguous. Fingerprint expiry never deletes the registry.

Forget device requires confirmation and changes only the local persisted draft. It removes the registration/metadata, device overrides and device memberships. Profiles scoped exclusively to that device and their schedules are removed to avoid orphaned references; shared groups, services, global policy and other devices remain. It does not ban/disconnect a device, and Engine delivery is still explicit. Failed persistence restores the prior draft. Rediscovery after forgetting is provisional and does not recover deleted user metadata. Inactivity/TTL never invokes Forget.

## Acceptance

Real-LAN feasibility demonstrated DNS-SD and SSDP responses without privilege or configuration changes. Exact candidate collector/classifier validation and anonymous result inventory are retained outside the repository. The real phone may remain Unknown; no vendor/model/household-specific rules were added. Protocol capability recognition does not prove exclusive DNS coverage. Production deployment and human rendering remain behind the guarded gate.
