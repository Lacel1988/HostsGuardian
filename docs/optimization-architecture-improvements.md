# Optimization & Architecture Improvement Report

2026-10-13 — baseline: meglévő HostsGuardian implementáció és megőrzött munkafa.
Az értékelés nem korlátozódik a hibák javítására. Az alábbi öt szempont minden
javaslatnál külön szerepel: jelenlegi haszon, jövőbeli haszon, erőforrás,
megbízhatóság/biztonság, komplexitás/fenntarthatóság.

## Mérés és bevezetés

Izolált Release mikrobenchmark, 10 000 lookup / változat. Nem end-to-end DNS
latency, és nem production throughput-ígéret. JIT/GC/scheduler miatt a 4096-os
linear mérés gyorsabb lehet a 1024-esnél; ebből skálázási görbét nem állítunk.
Az index rebuild költségét a lookup benchmark nem tartalmazza.

| Prototípus | Baseline | Alternatíva | Allokáció | Döntés |
|---|---:|---:|---:|---|
| 64 binding lookup | 40.995 ms scan | 0.717 ms index | 640064 → 0 B | Bevezetve, immutábilis snapshotban |
| 1024 binding lookup | 178.757 ms scan | 0.624 ms index | 640064 → 0 B | Bevezetve |
| 4096 binding lookup | 155.484 ms scan | 0.955 ms index | 640064 → 0 B | Bevezetve |
| 2048 rekord completion | 472.590 ms queue rebuild | 0.820 ms dictionary | 491760000 → 160 B | Bevezetve, bounded FIFO mellett |

Az address/scope index nem választ győztes identitást: ugyanarra a kulcsra minden
claim megmarad. Determinisztikus equivalence teszt hasonlítja össze linear és
indexed resolver eredményét scope, konfliktus, stale, Unknown és IPv6 esetekben.
Snapshot atomikus; immutable policy nem változott. Visszaállítás: korábbi Engine
release, policy migration nélkül. A completion index ugyanígy csak diagnosztika.

## Ötszempontú értékelés

Kategóriák: **Szükséges**; **Mérhető előny**; **Stratégiai**; **Nem indokolt**.

| Javaslat / kategória | Jelenlegi haszon | Jövőbeli haszon | Erőforrás | Megbízhatóság / biztonság | Komplexitás / döntés |
|---|---|---|---|---|---|
| Receiver supervisor + generation / Szükséges | Wi-Fi-kiesésből helyreáll | interfészcsere kezelhető | max 5 s retry, lezárt socket | régi evidence nem él tovább | kicsi; bevezetve |
| Per-request budget + single-flight / Szükséges | race előtt refresh | több kliens burst | megosztott IPC; max 200 ms caller | nincs cross-device identity vagy global probe | közepes; staggered/cancel teszttel bevezetve |
| Immutable address/scope index / Mérhető előny | kisebb lookup/allokáció | 4096 binding határnál is hasznos | rebuild memória plusz; hot path olcsó | minden conflict megmarad | kicsi; bevezetve |
| Bounded queue + completion dictionary / Szükséges és Mérhető előny | response-evidence, nem 64 rekord | több esemény/correlation | 512 queue, 2048 retention; overflow látható | DNS nem vár telemetriára | közepes; bevezetve |
| Monotón lifetime/cache / Szükséges | wall-clock ugrás nem nyújt TTL-t | időkonzisztencia | kis overhead | nincs future-time trust | kicsi; bevezetve |
| Atomikus unit-publication / Szükséges | nem félfájl rollback | újrahasználható handover | ritka fsync I/O | bájtpontos előző/candidate állapot | kicsi; bevezetve, független handover rollback guarddal |
| Readiness capability separation / Szükséges | IPC nem capture PASS | több identity backend | nincs új probe | unsupported truthful | kicsi; bevezetve |
| DNS upstream single-flight / Stratégiai | most nincs mért bottleneck | nagy burst csökkenthető | potenciálisan kevesebb upstream I/O | response ID, policy revision, device/view izoláció kell | közepes/magas; most nem integrálva |
| Radix trie/domain suffix index / Stratégiai | most nincs match benchmark | sok szabályhoz jobb alap | több memória, olcsóbb suffix match | IDNA/suffix precedence equivalence kell | közepes; külön prototype + mérés után |
| LRU/TinyLFU DNS cache / Stratégiai | lehetséges upstream csökkentés | nagyobb LAN | memória/TTL költség | policy revision + DNSSEC + negative TTL, nem megkerülő cache | magas; most nem integrálva |
| Min-heap expiry / Nem indokolt jelenleg | bounded kicsi halmaz | nagyobb retentionnél hasznos lehet | heap bookkeeping | régi generation kezelése bonyolódik | mérés előtt nincs csere |
| EWMA health rate / Stratégiai | kevésbé zajos jelzés | stabil trendek | minimális CPU | megfigyelt eredmény, nem enforcement-fact | kicsi; küszöb/latency validáció szükséges |
| Bloom filter / Nem indokolt | index már pontos és bounded | nagyon nagy negatív lookupnál lehet haszon | plusz memória/hash | false positive nem lehet policy decision | most aránytalan |
| Per-device refresh fairness / Stratégiai | staggered gate javítva | burst/starvation csökkentés | plusz queue/scope management | csak hiteles evidence, nincs ranking identity | előbb contention mérés; nincs új scheduler |
| Helper frame prefilter/kernel BPF / Stratégiai | most userland limit fail-closed | több DNS packetnél kevesebb CPU | kernel-side reduction | filter hibája evidence-vesztés, új audit kell | nincs plusz privilegizáció; előbb terhelésmérés |
| Network adapter capability/transaction / Stratégiai | most nincs chokepoint | későbbi enforcement alap | nem mért | atomikus apply/rollback + minimális privilege | csak konkrét terv, nincs live implementáció |
| Bayes/fingerprint authority / Nem indokolt | bizonytalan identity | megjelenítésben lehet érték | modellterhelés | nem elfogadható authoritatív DeviceId | enforcementhez elutasítva |

## Hibaterhelés és mérési korlát

Determinista tesztek: helper timeout/cancel, 32 párhuzamos kérés shared refresh,
staggered két forrás, lejárt claim, conflicting MAC/IP, random/private MAC,
socket/interface generation loss, 20 000 telemetria producer, partial recovery,
CAS conflict és atomic publish failure. Helper timeout a 200 ms-os budget +
scheduler toleranciája; a részletes log tényleges mérési értéket tartalmaz.
Mikrobenchmark nem helyettesíti p95/p99 DNS-terhelést vagy Wi-Fi live down/up tesztet.
Nem vezettünk be új algoritmust pusztán újdonság miatt; két mért index előnyét
equivalence regresszió és korábbi-release rollback támasztja alá.

Következő mérés izolált Linux load alatt: friss versus hiányzó binding p50/p95/p99,
multi-device fairness, helper read amplification, snapshot rebuild allocation,
queue overflow és DNS response write. Eredmények nélkül nincs általános latency
vagy teljes hálózati skálázhatósági PASS állítás.
