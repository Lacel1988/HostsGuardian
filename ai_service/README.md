# HostsGuardian AI Security Analyst — elkülönített fejlesztési checkpoint

Ez a csomag **nem production AI-release és nem WPF-integráció**. A WPF AI Security
Analyst felülete még nincs kész. Gate 3 technikai elfogadás: izolált PASS, humán HU/EN
értékelés nyitott. **Gate 4: NO-GO**; a teljes élő AI HTTP-, jóváhagyott DNS-kontroll-
és emberi átvétel nem teljes. A repository source nem bizonyítottan a telepített
Vivo Engine binárisának pontos forrása.

## Megőrzött implementáció

- FastAPI loopback API, szigorú request-/workflow-/konkurenciahatárokkal.
- LangGraph: determinisztikus read-only diagnosztikai routing, hibrid BM25L/MiniLM/RRF
  visszakeresés, evidencia-validáció és korlátos összefoglalás.
- Helyi Ollama-provider; a modell rövid, sémával korlátozott claim-azonosítókat vagy
  ellenőrizhető forrásidézeteket választ. Nem generálhat futtatható eszközhívást,
  SQL-t, shell-parancsot vagy jogosultságmódosítást.
- Explicit UI-nyelv elsőbbsége; igazolt API-jelentés, hipotézis, dokumentáció,
  synthetic fixture és ismeretlen külön kezelése. A kötés nem fizikai identitásbizonyíték;
  a policy-visszaolvasás nem kliensoldali blokkolási bizonyíték.
- Előzmény csak session-határolt RAM-ban; metadata-retention 168 óra DNS/identity/
  diagnostic, 48 óra AI-hiba, alapból 4 MiB összkorláttal. Nincs tartós chatnapló.
- Opcionális Engine-adapter: explicit privát HTTPS origin, pontos jóváhagyott leaf
  SHA256, lánc/IP/érvényességi ellenőrzés, bearer hitelesítés és hét rögzített GET útvonal.
  A CurrentUser DPAPI-híd nem exportál visszafejtett credentialt; natív puffert nulláz.

A modellpromptba nem kerül nyers Engine policy/binding vagy credential. A modell
nem választ tetszőleges endpointot. Nincs automatikus remediation vagy modelldownload.

## Konfiguráció és helyi futtatás

Python 3.11+ és a `pyproject.toml` szerinti függőségek szükségesek; a
`requirements.lock` a fejlesztéskor rögzített verziókat őrzi. A tesztek TLS-fixture-je
helyi .NET 8 SDK-t is használhat. Ez a checkpoint-feladat nem telepít függőséget.

A `.env.example` **sablon**, nem aktív helyi konfiguráció és nem tárolható benne titok.
A `Settings` a `HG_AI_` környezeti változókat olvassa, nem tölti be automatikusan
a sablont. Az Engine-adapter alapból ki van kapcsolva. A helyi Ollama-modellt és
endpointot az operátornak a ténylegesen meglévő assetekhez kell explicit beállítania;
a sablon modellneve nem igazolja, hogy a modell telepítve van.

```sh
python -m hostsguardian_ai
python -m pytest -q
```

Induláskor nem történik Engine-probe vagy automatikus modellletöltés. Éles adapter
engedélyezéséhez explicit endpoint, függetlenül jóváhagyott publikus cert/pin,
védett Engine-tokenfájl és az Engine-tokenétől eltérő AI-kliens-token szükséges.
A token értéke nem kerülhet argumentumba, sablonba, Gitbe vagy chatbe.
DPAPI-fájl esetén `HG_AI_ENGINE_TOKEN_FORMAT=dpapi-current-user` használható az eredeti,
engedélyezett Windows-felhasználó alatt; más platformra nincs decryption fallback.
Élő módban a tartalommentes `/v1/health` kivételével az AI HTTP API klienshitelesítést kér.
Nincs automatikus TOFU vagy plaintext HTTP Engine-fallback.

## Értékelési bemenetek és bizonyítékhatár

Az `evaluation/corpus` és `evaluation/manifest.json` a Gate 2 jóváhagyott, hash-elt
szintetikus/technikai korpusza. A `queries.json`, Gate 3 `cases.json` és
`relevance-judgments.json` reprodukálható tesztbemenet, nem felhasználói chatnapló.
A Gate 3 `correction-manifest.json` az alapcorpus és a külön `policy-concepts.md`
bővítés együttes előkészítéséhez tartozik. A modell/index létrehozása külön,
operátor által engedélyezett, helyi folyamat; szükséges asseteket ez a repo nem tölt le.
A `model-provenance.json` publikus modellfájl-hash-eket tartalmaz, nem modellfájlokat.

A generált mérési eredmények, korábbi NO-GO/ablation kísérletek, helyi indexek és
gépspecifikus Gate-riportok nincsenek ebben a source-checkpointban. Privát helyi
artefaktumként megmaradtak. A checkpoint nem állítja, hogy minden nyitott elfogadási
kritérium kész vagy az izolált eredmény production megfelelőséget jelent.

A kliensnél ellenőrzött read-only runner:

```sh
python -m hostsguardian_ai.gate4_acceptance --help
```

A runner explicit `--authorized-live-read` és jóváhagyott connection-inputok nélkül
nem kérhet élő Engine-adatot. A kapcsoló önmagában nem helyettesít felhasználói engedélyt.
Csak a hét rögzített GET-et használja, nem ad automatikus Gate 4 PASS-t. A
`/v2/dns-observations` nincs az adapter allowlistjén.

## Fájlhatár és tesztállapot

`local-data/`, modell/runtime, index, metadata-napló, credential/DPAPI-fájl, valódi
cert/key, helyi `.env`, cache és bináris nem source asset. Ezeket az ignore-szabályok
védik; a tiszta source-checkout nem tartalmaz működő production kapcsolatot.
A tesztek saját szintetikus credentialt és ideiglenes tesztcertet készítenek,
nem használnak production tokent vagy kulcsot.

A source-checkpoint auditja előtt lefutott teljes Python-suite: **210 PASS**.
A source-módosítás utáni végső futás eredményét a checkpoint-jelentés rögzíti;
a valódi modellmérések és a teljes Gate 3/4 elfogadás ettől külön bizonyítékok.
Nyitott: humán HU/EN/többfordulós minőség, AI HTTP élő klienshitelesítés,
DNS-kontroll, WPF AI UI és általános production AI-elfogadás.
