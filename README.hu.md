# HostsGuardian

**[English](README.md) | [Magyar](README.hu.md)**

C#/.NET DNS-policy projekt Windows WPF Control Centerrel, Linux DNS Engine-nel és Linux diagnosztikai Monitorral.

> **v0.4.0 — pre-1.0, fejlesztés alatt.** A globális DNS Block/Restore valódi végponti bizonyítékkal rendelkezik. A megbízható eszközspecifikus enforcement és teljes LAN-lefedettség nincs igazolva. Nem kész hálózatvédelmi berendezés.

## Cél és architektúra

**Az Engine végrehajt. A Monitor megfigyel. A WPF dönt.** Regisztráció, jelenlét, igazolt identitás, policy-küldés, DNS-válasz és alkalmazásblokkolás külön állapot.

A WPF kezeli a regisztrációt, felhasználói nevet/típust és döntéseket; hitelesített HTTPS-en kapcsolódik az Engine-hez. A Monitor identitás/policy tekintetében csak olvas. A NetworkValidator korlátozott belső helper, nem negyedik vezérlőkomponens. DNS nem halad át WPF-en; az Engine életciklusát systemd kezeli.

**Az Engine DNS-szerver, nem minden kliens kötelező gatewaye.** Beállított DNS nem bizonyít tényleges DNS-útvonalat. A szűrés nem garantálja meglévő kapcsolat megszakítását, és nem zárja ki az alternatív resolvert, titkosított DNS-t vagy cache-t. Az architektúra diagramja az angol README-ben található.

## Képességek

| Képesség | Állapot |
|---|---|
| WPF indulás, Domains/Devices, EN/HU | VERIFIED: emberi felülvizsgálat, kijelölt csomag elindult. |
| Globális WPF Block → valódi sinkhole → Restore | VERIFIED: 2026. október 13. |
| IPv4/IPv6 UDP/TCP, upstream | IMPLEMENTED, korábbi deployment/readiness; nem teljes LAN. |
| Registry, név/típus, device policy | IMPLEMENTED; megbízható éles szelektív enforcement PARTIAL / UNVERIFIED. |
| DeviceId, passzív evidence, TTL/konfliktus | IMPLEMENTED; freshness/receiver KNOWN ISSUES. |
| Revision/CAS, Safe Mode, persistence | IMPLEMENTED, regresszió és korábbi runtime-bizonyíték. |
| Csoport/profil/schedule/service catalog | IMPLEMENTED szerződés/evaluator; teljes valódi eszközteszt UNVERIFIED. |
| Notification/audit/log | IMPLEMENTED / PARTIAL; rekord nem bizonyít natív kézbesítést. |
| Monitor blokkolási adatcsatorna | VERIFIED; GUI-esemény UNVERIFIED. |
| Receiver recovery, bounded refresh, új telemetry/recovery | Helyi candidate; e dokumentációs checkpoint nem publikálja forrásként és nem állítja telepítettnek. |
| Teljes LAN / Network Enforcement | BLOCKED: coverage és kötelező chokepoint nem igazolt. |

Részletes forrás/teszt és megőrzött koncepció: [Architecture and roadmap](docs/ARCHITECTURE_AND_ROADMAP.md).

## Technológia és algoritmusok

.NET 8/C#, WPF, saját DNS/HTTPS Engine; Python GTK/PyGObject/Cairo; systemd service/socket; konzolos regresszió és Python unittest.

Immutable policy snapshot/CAS: `EnginePolicyState.cs`, `PolicyApplicationService.cs`. Determinisztikus precedence: Device override → aktív profil/schedule → csoport → globális, azonos szinten Block győz (`PolicyDecision.cs`). Normalizált pontos és ponttal elválasztott aldomainillesztés (`DevicePolicyEvaluator.cs`). Korlátozott konkurencia/timeout (`DnsProxyServer.cs`, `DnsRequestProcessor.cs`). Evidence-alapú identitás, történelmi IP önmagában nem elég (`AddressBindingStore.cs`).

Adaptív Simple/Indexed, tanuló service discovery, SQLite/WAL nincs megvalósítottként állítva. Fix index és bounded queue külön helyi candidate.

## Valódi DNS-bizonyíték

2026. október 13-án kontrollált Windows kliens közvetlenül az Engine-t kérdezte `example.com`-ról:

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

Megőrzött candidate: Core/Engine 332 PASS; WPF 33 PASS; Windows helper 82 PASS + 1 skip; recovery 36 PASS; Monitor 60 PASS + 22 skip. Linux fixture: Core/Engine 332, helper 83, recovery 36 PASS; Monitor 63 PASS + 19 skip. Ezek korábbi candidate-regressziók, nem e dokumentációs commit új tesztjei vagy produkciós acceptance.

## Biztonság

Hitelesített HTTPS/enrollment, revision/instance CAS, PID1/root socket és peer/élő folyamatellenőrzés. Engine CAP_NET_BIND_SERVICE; csak a korlátozott helper kaphat CAP_NET_RAW-t a service-en keresztül. Passzív MAC nem kriptográfiai identitás; teljes IP/MAC megszemélyesítés nem kizárt.

STALE neighbour nem online bizonyíték. Regisztráció, GUI-kapcsoló, draft és API-siker nem enforcement-bizonyíték.

## Ismert korlátok és prioritások

1. P0: DeviceId, kétklienses szelektív Block/Restore, receiver/freshness race és őszinte WPF állapot.
2. P1: router/gateway, IPv4/IPv6, alternatív DNS/DoH, vendorfüggetlen coverage/chokepoint.
3. P2: grafikus blokkesemény, korreláció, retention/audit.
4. P3: hivatalos WPF csomag, reprodukálható manifest, cleanup/retention.

IPv6 attribúció, natív notification/schedule acceptance, populated device-policy és generikus éles recovery nincs teljesen igazolva. Természetes forgalom/incidens opportunisztikus bizonyíték. systemd reload és történelmi caveat az aktuális deploymentnél ellenőrzendő; e publikálás runtime-ot nem változtat.

**Fejlesztés alatt:** hasznos globális DNS-szűrés igazolt; megbízható általános eszközenforcement a következő acceptance. Nincs új deployment, tag vagy bináris release.
