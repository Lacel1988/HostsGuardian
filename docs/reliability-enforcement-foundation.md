# Reliability & Enforcement Foundation — 2026-10-13

Ez helyi, integrált fejlesztési jelölt. Nem produkciós acceptance és nem teljes
Network Enforcement. Engine végrehajt; WPF dönt; Monitor megfigyel. A
NetworkValidator a meglévő, korlátozott belső helper marad.

## Kiindulás és bizonyíték

Git alap: `8f517c081a52385e22b182db910428d251dead45`, meglévő módosított munkafa.
Az előző 200 ms-os refresh, WPF instanceId/CAS, exact Restore és generikus recovery
változtatásai megmaradtak; nem tekintjük ezeket már telepítettnek.
Az október 13-i audit és a korábbi live jelentések szerint a produkciós helper
IPC READY mellett végleg elveszíthette a passzív receivert Wi-Fi-kiesés után.
Az akkori read-only baseline ezt alátámasztotta: IPC READY, capture UNAVAILABLE,
Safe Mode OFF, Active Validation OFF. Az akkori telepített forrás eltért a Git
HEAD-től. A privát policy és gépállapot részletes bizonyítéka nem publikált adat.
Az október 28-i forrásellenőrzés: [publikálási verifikáció](publication-verification-2026-10-28.md).
A futó szolgáltatásokat, policyt, hálózatot és biztonsági konfigurációt nem
módosítottuk. Linuxon csak külön `/tmp` fixture-ök futottak jogosultságnövelés nélkül.

## Javított útvonalak

| Terület | Forrás / viselkedés | Igazolás és korlát |
|---|---|---|
| Receiver lifecycle | `network-validator/validator.py`: `_receive`, `_receive_generation`, `observe`, `snapshot` | .25–5 s leállítható backoff; minden socket lezárul; új generation + helper instance; régi claim/cache kiürül; késői generáció elutasítva. Receive-only, nem promiscuous. |
| Capture health | `PassiveDnsL2Evidence.cs`, `EndpointValidation.cs`, `Program.cs`, `topology_ui.py` | IPC és capture külön állapot; capture READY csak használható receiverrel. READY nem DeviceId vagy Online bizonyíték. |
| Binding race | `RequestBindingRefresh.cs:16`, `DnsRequestProcessor.cs:43` | IPv4 hiányzó/lejárt bindingnál 200 ms saját monotón budget, három koordinált receive-only read; staggered kérés nem használ befejezett pre-packet ablakot. Utána új policy/binding snapshot. |
| Identity safety | `PassiveDnsL2BindingProducer.cs`, `AddressBindingStore.cs:54` | Friss packet + egyértelmű regisztrált MAC + interfész/neighbor konfliktusellenőrzés. STALE önmagában nem validál. IP-only fallback és TTL-hosszabbítás nincs. |
| Index | `AddressBindingStore.cs:10` | Immutábilis address/scope index; minden konfliktusjelölt megmarad. Ugyanaz a freshness/registry/scope ellenőrzés. |
| Telemetria | `DnsRequestContext.cs`, `DnsObservationStore.cs`, UDP/TCP transport, `ApiServer.cs:297` | CorrelationId, sequence, qtype, revision, binding generation, decision, response code/bytes, időtartam és helyi socket-write állapot. |
| Idő | `PassiveDnsL2BindingProducer.cs`, `DnsCoverageEvidence.cs`, `DnsObservationStore.cs` | Monotón binding élettartam-korlát, health-age, coverage-cache és retention; wall timestamp továbbra is provenance, jövőbeli claim elutasítva. |
| Restore | `DeviceOverrideRestore.cs`, WPF MainViewModel, `p0_policy_restore.py` | ABSENT különbözik explicit Inherit-től. CAS/instanceId, részleges Restore és idempotencia; idegen változtatás nem írható felül. |
| Recovery átadás | `recovery_activation.py` | Egy meglévő unitpár, pinelt session/kód, régi session original-check, unprivileged check, 90 s maximum következő firing ellenőrzése uptime alapján, atomikus unitcsere, bájtpontos rollback. Loaded-config pinelésből a változó PID/timestamp/next-firing mezők kizárva; ExecStart és timer duration változása elutasítva. |
| Upgrade | `network-validator/l2_upgrade.py` | Már engedélyezett passzív baseline ismét frissíthető duplikált opt-in nélkül; régi helper `--passive-dns` rollback során megmarad. |

A DNS-nek segédhiba esetén is működnie kell: ismeretlen identitásra az eredeti
globális policy érvényes, nem egy feltételezett eszköz szabálya. Ez identitásra
fail-closed; nem automatikus minden-ismeretlen hálózati tiltás.

A passzív Ethernet/MAC állítás nem kriptográfiai eszközhitelesítés. Egy ellenséges,
azonos L2-n lévő kliens spoofing-kockázata megmarad; megfigyelt ütközés, túlcsordulás,
hibás checksum, fragment, interface/generation eltérés és lejárt evidence kizár.
Router/proxy forrás-MAC nem alakítható tetszőleges végkliens DeviceId-jává.
Nem állítjuk, hogy Wi-Fi aktivitás vagy cached ARP bizonyítja az Online állapotot.

## IPv6 foundation — BLOCKED

A DNS UDP/TCP IPv4/IPv6 továbbra is támogatott és izolált integrációban tesztelt.
A jelenlegi helper IPv4 Ethernet DNS-frame-eket gyűjt; ebből IPv6 privacy address,
NDP vagy prefixváltás után nem származtatható biztonságos DeviceId.
Az új belső szerződés `Ipv6IdentityState=UnsupportedPassiveEvidence`; az API
`ipv6DeviceEnforcement=false`, a resolver `UnsupportedAddressFamily` állapotot ad.
Sem EUI-64 címformátum, sem fingerprint, hostname vagy IP nem jogosít fel identityre.

A teljes IPv6-attribúcióhoz receive-only IPv6 frame-parser és bounded extension /
fragment kezelés, azonos interfészgenerációhoz kötött NDP/on-link korroboráció,
checksum/freshness/conflict ellenőrzés és több privacy address biztonságos kezelése
kell. Prefix/interface változás invalidál; tesztelendő router-proxy és több cím/MAC.
Ezek hiányában teljes IPv6 per-device enforcementet nem jelentünk késznek.

## Bounded bizonyíték és export

2048 rekord / 15 perc, 512 elemű nem várakozó producer queue. Túlterheléskor
drop/eviction számláló jelzi a hiányt. Nincs raw DNS payload vagy tartós DNS-history.
Az autentikált `/v2/dns-observations` bounded exportja acceptance előtt/után
megőrizhető; teljes terhelés alatt ez sem garantál veszteségmentes auditot.
`ResponsePrepared` nem elküldés; `TransportWriteSucceeded` helyi socket-write,
nem kliensoldali átvétel. A valódi wire response és app-block külön live bizonyíték.
Negatív/future wall-clock age nem hosszabbítja meg a monotón megőrzési budgetet.

## Recovery korlátok

Generikus session: egy kifejezetten jóváhagyott DeviceId és legfeljebb 64 domain;
eredeti ABSENT/explicit állapotok, scope ledger, CAS, idempotens részleges Restore.
Az aktiváló nem módosít Engine-t, helper-t vagy hálózatot, root sessiont nem futtat;
a recovery a manifestben kijelölt felhasználóként, üres capability-settel és ProtectSystem=strict alatt fut.
A next-firing abszolút boot-monotón érték; a `11h...` önmagában nem 11 órás várakozás.

Ez a handover még nincs élesítve. Tesztelt hibák automatikus unit-rollbacket adnak,
SIGINT/TERM is rollbacket indít. A régi timer megállítása előtt egy független,
120 s-on belül ütemezett systemd unit-layout rollback guard ellenőrzendő. A guard
ugyanazt a pinelt rollback útvonalat használja, lock-foglaltság/hiba esetén 5 s
retryvel; nem második policy recovery. Sikeres handover után leáll.
SIGKILL esetén függetlenül visszaállítja a régi unitpárt; reboot esetén az eredeti
boot-enabled unitnév és atomikus lemezállapot marad. A watchdog előfeltétele és parancsútvonala determinisztikus fixture-rel tesztelt;
a tényleges PID1/hard-kill/reboot viselkedés éles megszakítással nem igazolt.
Külön jóváhagyott aktiváláskor igazolni kell a guardot és a tényleges next firinget,
majd recovery működését; addig nincs új live Block és a jelenlegi TV recovery
nem kerül leállításra.

## GUI állapotszemantika

Policy saved ≠ deployed ≠ identity validated ≠ DNS decision ≠ response write ≠
client application blocked ≠ network enforcement. A meglévő WPF CAS/instanceId
és exact Restore javítások regresszióval megmaradtak. Monitor külön jelzi IPC/capture
állapotát és IPv6 korlátját. Linux GTK render nincs bizonyítva headless SSH alatt;
kimaradt GUI-teszt nem PASS és nem FAIL. Friss capture sem bizonyítja a teljes DNS-lefedettséget.

## Integrált ellenőrzés és következő acceptance

A végső külső jelentés tartalmazza a pontos, közös forrásra futtatott testmátrixot,
buildlogokat, benchmarkot, manifestet és hash-eket. Windows WPF és Linux release
build készült; Linux fixture nem érintette a valódi DNS-t vagy szolgáltatásokat.
A produkciós baseline read-only megőrzés-ellenőrzés, nem új live enforcement teszt.

Következő valódi acceptance: külön jóváhagyott guarded Engine/helper upgrade,
capture lifecycle down/up izoláltan, friss regisztrált IPv4 binding, WPF-only
egy-domain Block → valódi kliens DNS-válasz → exact Restore → Allow. Éles policy
előtt a recovery megszakítási gate teljesítendő. IPv6 identity és full network
enforcement külön BLOCKED. A család hálózata és más eszközök policyje változatlan.

## Network Enforcement — kizárólag terv

Engine belső `NetworkEnforcementAdapter`: capability/query, policy revisionhez
kötött Prepare(snapshot, target-scope), Apply(transaction), Readback és Rollback.
A DNS és Network capability külön, Default Unsupported. Monitor csak diagnosztika;
WPF explicit felhasználói döntést ad, nem hamis automatikus network PASS-t.

Kötelező előfeltétel az igazolt, megkerülhetetlen IPv4 **és** IPv6 PEP/chokepoint
egy izolált tesztszegmensben. A jelenlegi Vivo DNS-szerver nem ilyen gateway.
Adapter minimális jogosultságú belső executorral, explicit fail-open/fail-closed
döntéssel; nftables atomikus dedikált-table tranzakció, scope-hash, readback,
időkorlát és korábbi ruleset rollback. Nincs teljes családi ruleset-flush.
Conntrack/established flow kezelése külön döntés; DNS szabály nem egyenértékű
YouTube-media felismeréssel. QUIC, TLS, shared CDN és alternatív DNS korlátok
megmaradnak. Nincs éles tűzfal-implementáció vagy topológiaváltoztatás.
