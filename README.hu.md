# HostsGuardian

**[English](README.md) | [Magyar](README.hu.md)**

C#/.NET DNS-policy projekt Windows WPF Control Centerrel, Linux DNS Engine-nel és Linux diagnosztikai Monitorral.

> **Pre-1.0 fejlesztői jelölt, v0.4.0 alapokon.** A korábbi globális DNS Block/Restore bizonyítékát lent ismertetjük. A jelenlegi forrásnak helyi regressziós lefedettsége van; új éles elfogadási vizsgálat nem történt. A megbízható eszközspecifikus védelem és teljes LAN-lefedettség nincs igazolva.

Publikálás előkészítése: **2026. október 28.** A munkafa nem új commit, tag, bináris kiadás vagy telepítés. A [verifikációs jelentés](docs/publication-verification-2026-10-28.md) külön kezeli a forrásteszteket, a verzióazonosságot és a korábbi működési bizonyítékot.

## Cél és architektúra

**Az Engine végrehajt. A Monitor megfigyel. A WPF dönt.** Regisztráció, jelenlét, igazolt identitás, policy-küldés, DNS-válasz és alkalmazásblokkolás külön állapot.

A WPF kezeli a regisztrációt, felhasználói nevet/típust és döntéseket; hitelesített HTTPS-en kapcsolódik az Engine-hez. A Monitor identitás/policy tekintetében csak olvas. A NetworkValidator korlátozott belső helper, nem negyedik vezérlőkomponens. DNS nem halad át WPF-en; az Engine életciklusát systemd kezeli.

**Az Engine DNS-szerver, nem minden kliens kötelező gatewaye.** Beállított DNS nem bizonyít tényleges DNS-útvonalat. A szűrés nem garantálja meglévő kapcsolat megszakítását, és nem zárja ki az alternatív resolvert, titkosított DNS-t vagy cache-t. Az architektúra diagramja az angol README-ben található.

## Képességek

| Képesség | Állapot |
|---|---|
| WPF indulás, Domains/Devices, EN/HU | Korábbi csomag emberi ellenőrzése; a jelenlegi WPF izolált regressziói sikeresek. |
| Globális WPF Block → valódi sinkhole → Restore | VERIFIED: 2026. október 13. |
| IPv4/IPv6 UDP/TCP, upstream | IMPLEMENTED, korábbi deployment/readiness; nem teljes LAN. |
| Registry, név/típus, device policy | IMPLEMENTED; megbízható éles szelektív enforcement PARTIAL / UNVERIFIED. |
| DeviceId, passzív evidence, TTL/konfliktus | IMPLEMENTED; freshness/receiver KNOWN ISSUES. |
| Revision/CAS, Safe Mode, persistence | IMPLEMENTED, regresszió és korábbi runtime-bizonyíték. |
| Csoport/profil/schedule/service catalog | IMPLEMENTED szerződés/evaluator; teljes valódi eszközteszt UNVERIFIED. |
| Notification/audit/log | IMPLEMENTED / PARTIAL; rekord nem bizonyít natív kézbesítést. |
| Monitor blokkolási adatcsatorna | VERIFIED; GUI-esemény UNVERIFIED. |
| Receiver recovery és korlátozott frissítés | A jelölt része generáció-, timeout- és megszakítási regressziókkal; éles igazolásra vár. |
| Korrelált DNS-diagnosztika | 512 várakozó esemény, 2048 döntés, 15 perc monoton megőrzés és veszteségszámlálók; helyi socket-write nem kliensoldali kézbesítés. |
| Pontos eszközszabály-visszaállítás és kapcsolati állapot | ABSENT/Inherit/Allow/Block megőrzése és WPF mocktesztek; az elküldés külön művelet. |
| Védett frissítés és helyreállítás | Forrás és izolált tesztek megtartva; root/PID1, hard-kill és reboot éles igazolása még szükséges. |
| Teljes LAN / Network Enforcement | BLOCKED: coverage és kötelező chokepoint nem igazolt. |

Részletes forrás/teszt és megőrzött koncepció: [Architecture and roadmap](docs/ARCHITECTURE_AND_ROADMAP.md).

## Technológia és algoritmusok

.NET 8/C#, WPF, saját DNS/HTTPS Engine; Python GTK/PyGObject/Cairo; systemd service/socket; konzolos regresszió és Python unittest.

Immutable policy snapshot/CAS: `EnginePolicyState.cs`, `PolicyApplicationService.cs`. Determinisztikus precedence: Device override → aktív profil/schedule → csoport → globális, azonos szinten Block győz (`PolicyDecision.cs`). Normalizált pontos és ponttal elválasztott aldomainillesztés (`DevicePolicyEvaluator.cs`). Korlátozott konkurencia/timeout (`DnsProxyServer.cs`, `DnsRequestProcessor.cs`). Evidence-alapú identitás, történelmi IP önmagában nem elég (`AddressBindingStore.cs`).

Adaptív Simple/Indexed, tanuló service discovery, SQLite/WAL nincs megvalósítottként állítva. A fix, változtathatatlan cím/scope index és a korlátozott diagnosztikai sor a jelenlegi forrás része.

## Korábbi valódi DNS-bizonyíték

A korábbi dokumentáció az alábbi kontrollált Windows–Linux Engine tesztet rögzíti **2026. október 13-áról**, `example.com` lekérdezéssel. A publikálási ellenőrzés során ezt nem ismételtük meg; a teszt nem igazolja a jelenlegi jelölt éles telepítettségét:

| Fázis | Válasz |
|---|---|
| Baseline | NOERROR: `104.20.23.154`, `172.66.147.243`. |
| WPF Domains Block, revision 46 | NOERROR: `0.0.0.0`, TTL 60. |
| Monitor adat | GlobalBlock, blokkolt kérés, DeviceId Unknown. |
| WPF Restore, revision 47 | Normál válasz és eredeti policy-szemantika visszaállt. |

A felhasználó Lenovo és mobil böngészőből is sikeres Domains-blokkolást jelzett; ez emberi megfigyelés, nem rögzített eszközspecifikus acceptance. Revision miatt a fájlhash változhat; Restore az eredeti policy-tartalomra vonatkozik az elvárt revision-metaadat kivételével.

Bizonyított: globális szűrés az Engine-hez érkező kérésre. Nem bizonyított: Devices enforcement, automatikus identitás megbízhatósága, teljes LAN, DoH-ellenállás, Monitor GUI-esemény.

## Telepítés, konfiguráció és tesztek

A történelmi deployment-útmutatókat az adott release-hez ellenőrizni kell. [Monitor útmutató](linux-monitor/README.md). Credential/certificate/gépspecifikus config ne kerüljön Gitbe. WPF: támogatott HTTPS enrollment; draft és explicit delivery külön. A kliensnek ténylegesen ezt a resolvert kell választania; e dokumentáció nem engedélyez hálózati változtatást.

```powershell
dotnet build HostsGuardian.sln -c Release
dotnet run --project HostsGuardian.Wpf -c Release
dotnet run --project HostsGuardian.RegressionTests -c Release
dotnet run --project HostsGuardian.Wpf.RegressionTests -c Release
```

Windows/.NET 8 WPF szükséges. Python: külön `network-validator`, `linux-monitor`, `development/roadmap` könyvtárban `python3 -B -m unittest discover -v`. GTK-hoz Linux grafikus függőségek szükségesek; skip nem végrehajtott GUI-teszt. Development build nem automatikusan elfogadott release.

A friss Windows tesztmátrix, parancsok, kihagyások és verziókorlátok a [verifikációs jelentésben](docs/publication-verification-2026-10-28.md) találhatók. Core/Engine: **332 sikeres csoport**; WPF: **39 PASS üzenet**, 0 kilépési kód. A Python-eredmények külön jelzik a sikeres és kihagyott teszteket. A GTK-kihagyás nem GUI-siker; a régebbi Linux-eredmények történelmi bizonyítékok.

A recovery szkriptek karbantartott források, nem törlendő lemezképek. Generált privát session, credential, tanúsítvány, buildkimenet és recovery image ne kerüljön Gitbe. A transfer bootstrap alapkönyvtára `/var/tmp/hostsguardian-transfer`; a csomagkészítő explicit `transferDirectory` értéket adhat meg. A bootstrap előállítása nem végez és nem engedélyez telepítést.

## Biztonság

Hitelesített HTTPS/enrollment, revision/instance CAS, PID1/root socket és peer/élő folyamatellenőrzés. Engine CAP_NET_BIND_SERVICE; csak a korlátozott helper kaphat CAP_NET_RAW-t a service-en keresztül. Passzív MAC nem kriptográfiai identitás; teljes IP/MAC megszemélyesítés nem kizárt.

STALE neighbour nem online bizonyíték. Regisztráció, GUI-kapcsoló, draft és API-siker nem enforcement-bizonyíték.

## Ismert korlátok és prioritások

1. P0: DeviceId, kétklienses szelektív Block/Restore, receiver/freshness race és őszinte WPF állapot.
2. P1: router/gateway, IPv4/IPv6, alternatív DNS/DoH, vendorfüggetlen coverage/chokepoint.
3. P2: grafikus blokkesemény, korreláció, retention/audit.
4. P3: hivatalos WPF csomag, reprodukálható manifest, cleanup/retention.

IPv6 attribúció, natív notification/schedule acceptance, populated device-policy és generikus éles recovery nincs teljesen igazolva. Természetes forgalom/incidens opportunisztikus bizonyíték. systemd reload és történelmi caveat az aktuális deploymentnél ellenőrzendő; e publikálás runtime-ot nem változtat.

**Fejlesztés alatt:** korábbi globális DNS-szűrés dokumentálva; megbízható általános eszközenforcement a következő acceptance. Nincs új deployment, tag vagy bináris release. A program a repository MIT licencét használja; a betűkészletek külön [Orbitron](HostsGuardian.Wpf/Assets/Fonts/OFL.txt) és [Exo](HostsGuardian.Wpf/Assets/Fonts/Exo-OFL.txt) értesítéseit megőrizzük.
