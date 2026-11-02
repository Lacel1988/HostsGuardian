# HostsGuardian — V2.3.1 RC.2

**[English](README.md) | Magyar**

A HostsGuardian DNS-szabálykezelő rendszer, önálló Linux DNS Engine-nel és Windows WPF Control Centerrel. A jogosult felhasználók domainblokkolást kezelhetnek úgy, hogy a mentett beállítás, a mért DNS-hatás és az alkalmazás működése külön értelmezhető marad.

**Production státusz: COMMITTED / PARTIAL GO.** A master fejlesztési alapja az igazolt RC.2 forráscsomagból származik. Nem telepít új kiadást, és nem jelent teljes production acceptance-et.

## Kiindulópontok

- [Aktuális állapot és a következő fejlesztés alapja](docs/CURRENT_STATE.md)
- [Architektúra és konfiguráció](docs/ARCHITECTURE.md)
- [Ismert korlátok](docs/KNOWN_LIMITATIONS.md)
- [Fejlesztési tervek](docs/ROADMAP.md)
- [Kiadástörténet](docs/RELEASE_HISTORY.md)
- [Friss ellenőrzések](docs/VALIDATION.md) · [Forráseredet és adatvédelmi vizsgálat](docs/RELEASE_PROVENANCE.md)

A részletes műszaki dokumentáció angol nyelvű; az aktuális állapot elsődleges leírása a CURRENT_STATE.md.

## Megvalósított képességek

- Linux UDP/TCP DNS-kiszolgálás, meglévő globális és eszközszintű szabálykiértékelés, tartós tárolás és audit.
- 4-es policy-séma: a listában megőrzött domain és a tényleges tiltás külön állapot.
- Engine-alapú Domain Block List: hatókörválasztás, keresés, hozzáadás, ki- és bekapcsolás a sor törlése nélkül, külön törlés. Az eszköznézet a globálisan örökölt tiltást is jelzi.
- HTTPS management API, Engine-oldali Argon2id hitelesítés, lejáró munkamenetek és Admin/Operator/Observer jogosultságellenőrzés.
- WPF-belépés, a meglévő pajzs/lakat animáció, Dashboard és domainkezelés.
- Revízióhoz kötött írás és visszaolvasás, diagnosztikai és monitoring-adatnézetek.

A globális tiltás és visszaállítás éles bizonyítékokkal rendelkezik. Az eszközszintű szabályok és szerepkörök megvalósultak, de a szelektív eszközszintű végrehajtás és az éles Operator/Observer munkamenetek külön nyitott acceptance-feladatok. Az elemzői API-szerződések nem bizonyítanak teljesen telepített és elfogadott AI-szolgáltatást.

## Architektúra

Az Engine hajtja végre az engedélyezett szabályokat. A WPF visszaolvasott állapotot és felhasználói vezérlést biztosít. A Linux monitoring megfigyel. Az AI elemez és javasol. A kliensek DNS-forgalma közvetlenül az Engine-hez jut; a WPF nem DNS-átjáró. A független szolgáltatás életciklusát a systemd kezeli. Részletek: [Architecture](docs/ARCHITECTURE.md).

## Forrásstruktúra és build

Az aktuális alapállapot a `rc2/source`; az izolált tesztek a `rc2/tests` és `rc2/migration-checks` könyvtárban vannak. A gyökér `HostsGuardian.sln` az **RC.2 hivatalos solutionje**, kizárólag RC.2 projektekkel és egyetlen aktuális WPF-fel. A régi gyökérprojekt-könyvtárak történeti forrásként, `README.LEGACY.md` jelöléssel maradnak meg; a régi solution a `legacy/HostsGuardian.PreRC2.sln` helyre került. A külön AI-fejlesztési ág nincs automatikusan beolvasztva.

.NET 8 vagy kompatibilis SDK szükséges. A WPF-hez Windows desktop célzási és futtatási támogatás kell. A projektfájlokban rögzített csomagokat kell visszaállítani; a konszolidáció nem vezetett be új alkalmazásfüggőséget.

```sh
# Teljes hivatalos solution Windows alatt:
dotnet build HostsGuardian.sln -c Release
# Linux alatt is támogatott Engine-build:
dotnet build rc2/source/HostsGuardian.DnsEngine/HostsGuardian.DnsEngine.csproj -c Release
dotnet build rc2/source/HostsGuardian.Wpf/HostsGuardian.DesignPrototype.csproj -c Release
dotnet run --project rc2/source/HostsGuardian.RegressionTests/HostsGuardian.RegressionTests.csproj -c Release
dotnet run --project rc2/tests/IntegrationChecks.csproj -c Release -- ./rc2/test-output/integration
```

Az Engine buildje és regressziói Windows és natív Linux alatt újonnan lefutottak. Windows alatt a WPF buildje és a tényleges WPF/loopback-HTTPS ellenőrzések is sikeresek. A forrásvizsgáló regressziókat a teljes checkoutból futtasd: két kifejezetten történeti WPF-teszt a megőrzött gyökérfájlokat használja. A kezdeti útvonalhibát és a javítást is a [Validation](docs/VALIDATION.md) dokumentálja.

## Telepítés és konfiguráció alapjai

1. Előbb izolált ellenőrzés szükséges. Őrizd meg a korábbi működő Engine-t a hozzá tartozó policy-mentéssel együtt.
2. Helyben biztosítsd a szolgáltatás tulajdonosát, a privát hitelesítési tárhelyet, management credentialt, TLS-tanúsítványt és privát kulcsot, valamint a policy és monitor útvonalait. Ezeket ne commitold.
3. Az Engine konfigurációs környezeti változóit az [Architecture](docs/ARCHITECTURE.md) sorolja fel. Csak új telepítéskor inicializáld az első Admint, helyi terminálban, egyedi erős jelszóval. Meglévő userstore-t ne inicializálj újra.
4. Őrizd meg a systemd védelmeit, és ellenőrizd a tényleges service-felhasználó hozzáférését. A véglegesített telepítés örökölt `Restart=on-failure` szabályt használ; ezt a véglegesítés Engine-újraindítás és policyírás nélkül ellenőrizte.
5. A WPF meglévő kapcsolódási folyamatában állítsd be a HTTPS-origint, a megbízható tanúsítványt és a védett helyi credentialt. Engine-fiókkal jelentkezz be.
6. A kliensek DNS-átállítása előtt ellenőrizd az API-visszaolvasást, az UDP/TCP DNS-t és a rollback feltételeit. Ez az ág nem telepít és nem állít routert.

A környezetfüggő telepítők, recovery-adatok és credentialek nem részei a publikációnak. A fenti lista előfeltételeket rögzít, nem univerzális, egyparancsos telepítőt.

## Korlátok és tervek

A DNS-policy csak az Engine-hez eljutó kérésekre érvényesül. A cache, meglévő kapcsolatok, IPv6 DNS-választás és alternatív DNS/DoH befolyásolhatja az alkalmazások működését. Egyetlen domain nem feltétlenül képvisel egy teljes, többdomaines szolgáltatást. Részletek: [Known Limitations](docs/KNOWN_LIMITATIONS.md).

**A Service-Aware DNS Policy és az AiSeNa fejlesztési irányok, nem kész production képességek.** Lásd: [Roadmap](docs/ROADMAP.md).

A tisztított forrás a tesztnevek és a tesztútvonalak kezelése miatt szándékosan eltér a telepített RC.2 snapshotjától. Az eredeti release hash-ek megmaradtak. Egy korábbi személyhez köthető tesztmegjelenítési név továbbra is elérhető a Git-előzményekben; történetátírás nem történt. Lásd: [Provenance](docs/RELEASE_PROVENANCE.md).

## Licenc

Lásd a [LICENSE.txt](LICENSE.txt) fájlt és a projektfájlokban hivatkozott csomagok licenceit.
