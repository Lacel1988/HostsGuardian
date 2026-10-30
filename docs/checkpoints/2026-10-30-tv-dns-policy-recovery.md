# Technikai checkpoint — TV DNS-policy helyreállás, 2026-10-30

Ez dokumentációs Git-checkpoint, nem telepítés, certcsere vagy production elfogadás.
A repository kiinduló forrás-HEAD-je `6038615e2cfc121dfd9c3e8682c049304c7be25f`,
ága `feature/ai-gate1-foundation`. **Ez a commit nincs a futó production binárissal
függetlenül megfeleltetve.** A checkpoint nem állít ilyen azonosságot.

## Bizonyíték és idővonal

A helyi idők Europe/Budapest szerintiek; október 30-án UTC+1.

| Idő | Megfigyelés | Forrás / korlát |
|---|---|---|
| 2026-10-13 19:08:33 UTC | PolicyCommit 62 → 63, sikeres, szemantikailag változatlan szállítás | Megőrzött Engine-audit |
| 2026-10-30 15:32:37 helyi | A vizsgálatban látott Engine-process elindult | systemd; nem a bináris telepítési ideje |
| 16:00 után | YouTube élő adás után új keresés nem működött, az újranyitott app hálózati hibát adott; Netflix működött | Felhasználói beszámoló, pontos perc nélkül |
| 16:09 | Globális youtube.com tiltás, rev. 63; TV-hez társított 8 blokkolás/600 s | Hitelesített read-only Engine API |
| 16:11 | A felhasználói TV-azonosítók és a friss L2-kötési jelentés egyezett | Regisztráció + PassiveDnsL2; nem kriptográfiai fizikai identitás |
| **16:31:12** | **Sikeres, tartós PolicyCommit 63 → 64; globális youtube.com szabály eltávolítva** | Engine-audit, tartós policy, API, offline hash-összevetés |
| Ugyanebben a másodpercben | WPF sikeres DNS-policy visszaigazolási esemény | Windows auditnapló |
| A kézi műveletek után | YouTube ismét működött | Felhasználói beszámoló; pontos újrapróbaidő nem ismert |
| 16:43 | Rev. 64; TV-hez társított tízperces sorban 112 allowed, 0 blocked | Új read-only API-minta |
| 16:47 | A regisztrált telefon-MAC-hez társítható forrás egy DNS-kérése megfigyelt, DeviceId null | Nem bizonyítja a korábbi YouTube resolver-útját |

Az Engine audit pontos ideje `2026-10-30T15:31:12.6456504Z`; a WPF confirmation
`2026-10-30T15:31:12.572Z`. Külön gépórákból nem állítunk milliszekundumos hálózati sorrendet.
Az audit management-boundary műveletet rögzít, személyazonosítás nélkül. A WPF-napló
és a tartós Engine-commit együtt igazolja a kliensoldali visszaigazolást és a szerveroldali változást;
a teljes kattintássorrend/egyedi HTTP-korreláció nem rekonstruált.

## Policy és hash-bizonyíték

A jelenlegi megfigyelt Engine-revízió **64**. A rev. 63 → 64 változás nem csak helyi
draft: az Engine lemezen lévő policyja és authenticated API-ja ugyanazt az új állapotot adta.

| Fingerprint típusa | Rev. 63 | Rev. 64 |
|---|---|---|
| Python rendezett-kulcsos kanonikus policy-JSON SHA256 | `d1dd448d8cfc49c98395ff8f807cac10395da45b6364e151ba4e92acd861cdb7` | `1207951e000c56b2f50fa3c2db0140842c1cf543fa2bf652d55ab27978bef3c7` |
| Engine-audit .NET serializer SHA256 | `497D6133AF2A606D006EE6171F9A17422DF912D51B9044C9DB870B6E1ACB093E` | `04BE7A821D49072A9F6EA07F191353F5AD5D79DBD8F4EDC47F2D37F76B1149FA` |

Helyi, csak memóriában végzett kontroll: a rev. 64 teljes policy .NET hash-e egyezett
a rev. 64 audit-hash-sel. Csak a `youtube.com` szabály globális listába visszaillesztése
a rev. 63 audit-hash-t adta. A megőrzött auditon alapuló rekonstrukció ezért alátámasztja,
hogy **más globális szabály, registry, device override vagy program nem változott** ebben
a commitban. Rekonstruált policy nem került az Engine-be. A két kanonizálási család
hash-ei közvetlenül nem összehasonlíthatók; az audit nem függetlenül aláírt trustlánc.

## Production release és source-különbség

Az effektív systemd ExecStart által kijelölt release azonosítója:
**`c74c828e1e9a4680`**. Ez release-azonosító, nem automatikusan Git-commit.

| Production fájl | SHA256 |
|---|---|
| Engine apphost | `0a56ca6401dd625352c0073f4c3ea6247b43a3dbc1aff09baadad879e145c1d4` |
| HostsGuardian.DnsEngine.dll | `41ce0f217209b56377f333db9a3d046183d04ced2cbb39f83e7f9dc93922b7ea` |
| HostsGuardian.Core.dll | `66e23b97435174422fe812d543c45f27869ab887d38c4b77291b809beecdd8bf` |

A payload fájlideje október 8-i; a pontos telepítési idő és sourceCommit nem állapítható
meg ebből. A meglévő védett deployment-receipt nem volt olvasható az engedélyezett
SSH-felhasználóval; jogosultságmegkerülés nem történt.

A hiba és helyreállás megfigyeléseiben ugyanaz a **PID 1334 / instance 82c742ea** szerepelt,
systemd `NRestarts=0`; a vizsgálati időszakban nem látszott process-/instance-váltás.
Ez nem teljes történeti restart-audit. A mostani repository vagy egy helyi build
forrástörténete nem bizonyítja, mi volt korábban telepítve. A korábbi
[publikációs ellenőrzés](../publication-verification-2026-10-28.md) is elkülöníti a candidate-forrást
a production elfogadástól.

## Minősítés és nyitott kérdések

**CONFIRMED:** revízió 63 → 64; sikeres persistálás; globális youtube.com eltávolítása;
WPF confirmation esemény; TV-hez társított DNS-blokkolási döntések.

**STRONGLY SUPPORTED:** policyeltávolítás és YouTube-helyreállás kapcsolata;
globális DNS-szűrés hatása ebben az incidensben.

**INCONCLUSIVE:** az eredeti YouTube-hibát okozó konkrét kérés/válasz; szelektív
per-device enforcement; a Galaxy S22 Ultra eltérő viselkedésének oka; pontos régi telepítési idő.
Az apphibát/Netflix működését és a helyreállást a felhasználó jelentette; ezek nem
önállóan rögzített alkalmazás-telemetria adatai.

A korábbi képhiba mellett továbbmenő videóhoz eltérő domének, cache vagy tartós
kapcsolat adhat magyarázatot, de egyik sem bizonyított. IPv6/alternatív DNS/DoH
használata sem állítható tényként. A regisztráció és friss kötés nem per-device elfogadás.

**Gate 3:** PASS a korlátozott izolált elfogadási feltételekre; új természetes HU/EN
kérdések, érthetőség/relevancia és többfordulós kontextus emberi átvétele nyitott.
**Gate 4: NO-GO.** Az élő TLS/DPAPI/GET és célzott Analyst-mérések sikeresek;
AI HTTP-hitelesítés, jóváhagyott DNS-kontroll és humán átvétel még hiányzik.
Az izolált AI-csomag 210 Python-tesztje a checkpoint előtt lefutott, de a csomag
külön, még nem commitolt munkafában van: ez nem a documentation commit forrás- vagy tesztelfogadása.

## Eredeti bizonyítékok és checkpoint-határ

A teljes retrospektív jelentés privát helyi bizonyíték, címe:
**HostsGuardian-TV-DNS-blocking-and-recovery.md**. Rögzített SHA256:
`5B7A9DFC64970C21BFAE5B8A9F9AA65571ED82FB3A9635275FD903B77C6337C2`.
Nem repository-fájl; nincs hozzá kitalált GitHub-link vagy más gépről elérhetetlen
Windows-útvonal. Szükség esetén jóváhagyott privát csatornán kérhető el a fenntartótól.
Az alapul szolgáló megtisztított audit-/hash-összevetési eredmények ugyancsak privát helyi artefaktumok.

Ez a kis commit kizárólag az angol README-eseményösszefoglalót és ezt a dokumentumot
tartalmazza. Az AI-source, mérési eredmények és további dokumentáció változatlanul
megmarad, külön értékelésre; nem keverjük production-validated source-release állításba.
Nincs benne credential, DPAPI-blob, cert/key, policyfájl, nyers DNS-napló,
MAC/DeviceId, személyes gépútvonal vagy runtime/model asset.

Nem történt production konfiguráció-/policy-/certváltoztatás, Block/Restore,
service/network művelet vagy deploy. A checkpoint nem ad engedélyt ezekre és nem
jelent Gate 4 PASS-t.
