# G1/G2 isolated validation — 2026-11-03

> Az eredeti MVP- és F01/F02-jelentések történeti bizonyítékok, eredeti
> eredményeikkel megőrizve. A friss, tesztkódtól független acceptance-ellenőrzés
> e dokumentum végén található: 73 regressziós és 20 külön acceptance-teszt.
> **ACCEPTANCE PASS a dokumentált, megbízható folyamaton belüli G1/G2 managed fejlesztési scope-ra.**
> A külön engedélyezett valódi Windows-symlink követő ellenőrzése SYMLINK_PASS.
> A korábbi futások eredményei és SKIP-jei történetileg változatlanok;
> nem történt új teljes regresszió. A scope és a megmaradó korlátok alább szerepelnek.

## Identity and scope

- Worktree at execution: the dedicated G1/G2 linked worktree before migration;
  original machine path retained only in private inventory record H0.
- Branch: `dev/orchestrator-g1-g2`
- Baseline and unchanged HEAD: `769556d2e9a183da272e4f3a114eafe37165498b`
- Python: 3.11.9, Windows. No added runtime dependencies.
- Changes are confined to `development/orchestrator`. No project commit, merge,
  push, deployment, product build/test or production configuration operation ran.
  Temporary test repositories have their own fixture commits only.

## Executed checks

`python development/orchestrator/run-tests.py`: **58 tests run in 59.674 seconds;
57 passed, 1 skipped, 0 failures/errors.**

Raw output:
private historical evidence record H1, log basename `tests-final.txt`.
The private evidence index retains the original machine location.

After the full suite, the PASS wording was specialized for diff-check versus edit
operations, so diff-check permission does not claim edit before-hash verification.
The two affected tests were rerun and passed (2.648 seconds):
`test_diff_check_has_exact_empty_component_scope` and
`test_legitimate_edit_and_user_file_preservation`.

`git diff --check`: passed.

Coverage includes:

| Check | Observed result |
|---|---|
| Unauthorized component, missing/mismatched authorization | BLOCK; zero fake executor calls |
| Protected/detached branches; primary checkout | BLOCK; no file changes |
| Traversal, metadata, Windows path aliases, invalid names | BLOCK; no target writes |
| Junction escape, hard link, duplicate target, nested repo | BLOCK; external/user files preserved |
| Symlink escape | Skipped: host lacks unprivileged symlink creation; Windows junction case passed |
| Authorized edit; explicit cross-component edit | Exactly one dispatch; intended fixture content changed |
| Missing evidence | REVISE; no dispatch; final acceptance NOT_EVALUATED |
| Stale source, policy, HEAD, payload, before hash | BLOCK; no dispatch |
| Reused instance authorization / source change during decision notification | No second dispatch / no dispatch |
| Failed/timed-out source probes | Typed BLOCK; no dispatch |
| Historical/arbitrary commands | BLOCK; no dispatch |
| Legacy local DEV run / direct execute | Typed BLOCK; fixture source unchanged |
| None/malformed/inconsistent guard result, duplicate snapshot JSON | Typed auditable failure; dependent work stops |
| Fake PASS worker text or injected prior Decision | Cannot replace policy evaluation or missing authorization |
| ANSI, newline, bidi controls; JSON/text consistency | Escaped fields; same authoritative status |
| ASCII terminal without explicit --plain | Automatic plain fallback |
| Non-UI core edit | UX research NOT_APPLICABLE; no unrelated prerequisite |
| CLI inspect/denial/success/evidence reuse | No inspect/denial dispatch; separate acceptance; evidence not overwritten |
| Production side effects | Process-spy permits only 10 local read-only Git probes during fake dispatch; no product or transport executor |

The extended process-spy test initially exposed a pre-existing `ls-files` call
without `--no-optional-locks`; this was corrected. Snapshot probes now also have
20-second command timeouts. The final full run above includes these changes.

## Measured cost

Five samples, small three-file temporary Git worktree, fake executor, no product
execution:

| Measurement | Median |
|---|---:|
| Existing source snapshot + SHA-256 identity | 242.706 ms |
| One G1/G2 evaluation including snapshot | 242.849 ms |
| Managed fake dispatch with two evaluations | 486.528 ms |

Double evaluation adds approximately one more snapshot compared with one snapshot
alone. The 0.143 ms median difference between one evaluation and snapshot is within
measurement noise; no performance improvement is claimed. These are not large-tree,
production, full CLI/ledger fsync or end-to-end product measurements. CLI preflight
performs an additional evaluation before creating evidence. Source hashing scales
with file count/bytes; ignored/external inputs are outside this identity.

## Existing worktrees observed after validation

| Branch | HEAD | Dirty entries |
|---|---|---:|
| feature/ai-gate1-foundation | 15ae7fb9e36912bf37bd42b98a4c58af3a62219c | 69 |
| release/sync-v2.3.1-rc.2 | 769556d2e9a183da272e4f3a114eafe37165498b | 0 |
| dev/orchestrator-m1 | a3d4c18cca0cca8d87466beea39077ef629ce7fc | 0 |
| dev/roadmap-integration | 2b802e3f232d7bdbe7eac7ae0f28fd150549a23f | 51 |

All four pre-existing branches and HEADs match the initial worktree inventory.
The AI tree retains its original 69-entry status. No implementation/test command
targeted these trees. This is Git state evidence, not a before/after byte-hash
attestation of every file in every existing tree.

## Decision

**CONDITIONAL GO for review and trusted local G1/G2 edit/diff-check use.** The
isolated tests demonstrate prevention and legitimate dispatch at the managed
boundary. Final human acceptance is NOT_EVALUATED; no production-wide or external
shell protection is claimed. See G1-G2-GOVERNANCE.md for unsigned local authorization
assertions, external/direct execution routes, ignored inputs, race windows,
nontransactional edits and per-instance replay limitations.

GOV-REC-01 remains a deferred specification; no remediation was implemented or
automatically enabled by passing these tests.

## F01/F02 célzott javítás — 2026-11-03

Az acceptance-audit két reprodukált hibáját kódjavítás és új regressziós tesztek
kezelik. A korábbi NO-GO megállapítást ez a fejlesztői ellenőrzés nem írja felül:
az acceptance lezárásához külön, független újraellenőrzés szükséges.

### Azonosság és hatókör

- Repository: the dedicated pre-migration G1/G2 linked worktree; original
  machine location retained in private inventory record H0.
- Branch: `dev/orchestrator-g1-g2`; HEAD: `769556d2e9a183da272e4f3a114eafe37165498b`.
- Az azonosságot minden projektfájl-módosító patch előtt ellenőriztem.
- Kizárólag development.py, workbench.py, governance.py, az új
  tests/test_no_go_regressions.py és ez a bizonyítékjelentés változott ebben a javításban.

### F01 — PASS a végrehajtott regressziós ellenőrzésekre

A közös evidence_directory() minden mkdir/manifest/ledger/log/summary írás előtt
ellenőrzi a ticketet és a teljes feloldott célútvonalat. Az abszolút/traversal
ticketek, elválasztók, Windows stream/device/short-name/namespace/drive-relative és
záró pont/szóköz aliasok elutasításra kerülnek. A végleges cél az engedélyezett
evidence-szülő közvetlen gyermeke marad; nem kerülhet egyik regisztrált forrásmunkafa
vagy a közös Git-metaadatok alá sem. Mindkét legacy belépő ezt használja.

Az eredeti abszolút-ticket reprodukció master fixture-rel mindkét belépőnél
elutasított. A tesztek írási és mkdir csapdákat, valamint dispatch mockot használnak:
a tiltott esetekben nulla írás és nulla DEV-dispatch történt. A legitim HG-001 ticket,
a relatív evidence-szülő és mindkét belépő külső evidence-létrehozása működik;
a történeti forrásírás ezek után továbbra sem kap automatikus engedélyt.

### F02 — PASS a végrehajtott regressziós ellenőrzésekre

A közös prepare_edits() teljes csomagot készít elő: editmezők, path/hash/content
típusok, replacement-lista és minden old/new mező, egyedi helyettesítés, forráshash,
valamint a teljes eredmény UTF-8 kódolhatósága. Ezt a governance a PASS előtt, az
executor pedig minden mkdir/fájlírás előtt meghívja. Az executor már előre kódolt
bájtokat ír; nincs késői szövegtípus- vagy kódolási ellenőrzés az írási ciklusban.

Az eredeti második-edit content:null reprodukció dispatch előtt BLOCK. További
negatív esetek: számszerű/lista tartalom, nem kódolható surrogate, hibás replacement
lista/elem/old/new/mezőszerkezet, üres old, hiányzó tartalom, hibás hash, hiányzó új
fájlra alkalmazott replacement és nem található old. A teljes csomag hibájánál az
első fájl is változatlan; nincs executor-dispatch. A belső executor külön ellenőrzése
is nulla mkdir/írás hívást igazol. A legitim többfájlos, replacementet és magyar
UTF-8/CRLF tartalmat használó engedélyezett művelet pontosan egyszer dispatch-elt.

### Futtatott ellenőrzések

- Célzott: `python -B -m unittest tests.test_no_go_regressions -v`
  a development/orchestrator könyvtárból: **10/10 PASS, 25.687 s**.
- Teljes: `python -B development/orchestrator/run-tests.py`:
  **68 teszt, 67 PASS, 1 kihagyott, 0 hiba; 89.913 s**.
- A PYTHONDONTWRITEBYTECODE=1 beállítás megakadályozta a bytecode-fájlírást.
- `git diff --check`: PASS.
- Nyers teljes tesztkimenet:
  private historical evidence record H2, log basename `full-suite.txt`.
- A symlink-teszt **NOT_EVALUATED**: a környezet nem engedélyezi a szükséges
  jogosultság nélküli symlink-létrehozást. A Windows junction teszt sikeres.
- Öt kis fixture-minta mediánja: snapshot 258.434 ms, evaluation 273.082 ms,
  guarded fake dispatch 533.066 ms. Ez nem teljes CLI-/nagy repository-mérés.

### Munkafák megőrzése és korlátok

Az AI, RC.2, M1 és roadmap munkafák javítás előtti/utáni branch, HEAD és teljes
porcelain-státusza egyezett. Az összes követett/nem ignorált fájl útvonalából és
tartalmából számolt SHA-256 ujjlenyomat is pontosan egyezett mind a négy munkafánál.
Ez nem terjed ki az ignorált állományokra és minden fájlrendszer-metaadatra.

Nem történt projektcommit, merge, push, deployment, produkciós DNS/hálózati művelet,
G3–G6 vagy GOV-REC-01 implementáció. A tesztek csak saját ideiglenes Git-fixture-jeiket
módosították. Automatikus rollback és tranzakciós rendszer nem készült. A korábban
dokumentált külső végrehajtási utak, megbízható folyamat/operátor feltételezés,
konkurens írók versenyhelyzete és futás közbeni I/O-hibák korlátai megmaradnak.

**Javaslat: CONDITIONAL GO kizárólag a független acceptance-újraellenőrzésre.**
F01/F02 fejlesztői regressziós eredménye PASS; acceptance lezárása és G3 indítása
NOT_EVALUATED/nincs engedélyezve. Az ismert hibák teszttel igazoltan zártak, de ezt
nem tekintem független acceptance-döntésnek.


## Independent acceptance — 2026-11-03

> Historical checkpoint before the separately authorized real-symlink follow-up.
> Its result counts and BLOCKED decision are retained; current scoped acceptance
> is recorded in [the follow-up](#targeted-windows-symlink-verification).

Evidence record: `HG-G1G2-INDEPENDENT-20261103`. This is a separately written
black-box harness from the current audit, not a claim of review by a different
person. It imports the copied implementation, never the existing test fixtures.
All fixture repositories and evidence were outside the development repositories.
No functional Python change was made. Only the three publication documents were
prepared; the eleven candidate Python files retain their audited SHA-256 values.

Baseline: `769556d2e9a183da272e4f3a114eafe37165498b`, branch
`dev/orchestrator-g1-g2`. The active worktree is the migrated linked worktree;
its absolute machine path and private evidence locations belong in the private
inventory, not this publication document. The repository-relative tooling root is
`development/orchestrator/`.

| Requirement | Fresh evidence | Decision |
|---|---|---|
| G1 component scope and exact cross-component authorization | Independent 01, 04, 06, 20; full regression suite | PASS for executed cases |
| G2 other/primary workspace, missing/forged/stale authorization | Independent 02, 03, 15, 17, 18 | PASS; denied dispatch count 0, write attempts 0 |
| F01 evidence/ticket protection | Independent 10, 14, 17; full legacy F01 regressions | PASS for executed cases |
| F02 complete edit preparation | Independent 07–09; full F02 regressions | PASS; malformed later edits preserve the first file |
| Actual Windows junctions | Independent 11 and 14; full suite junction cases | PASS; links created and denial observed |
| Actual Windows symlink | Creation attempted in both suites; Windows error 1314 | NOT_EVALUATED; insufficient privilege, no elevated retry |
| Traversal, ADS/reserved/alternate spelling, hardlink, nested repo | Independent 06, 13, 20; full suite | PASS for executed cases |
| Dirty/untracked/foreign preservation and valid edit | Independent 05; snapshot/hash comparisons | PASS for executed fixture cases |
| Public legacy/direct entry, replay, fake PASS text | Independent 16, 19; full F03/F04 tests | PASS within trusted-process boundary |
| OS-level isolation, hostile Python/independent shell, concurrent writers | Outside documented MVP boundary | NOT_EVALUATED / not claimed |

Fresh full regression: **73 tests, 72 passed, 1 skipped, 0 failures/errors**;
driver wall time **98.041 s**. Fresh independent harness:
**20 tests, 19 passed, 1 skipped, 0 failures/errors**, **39.657 s**.
The two skips concern the same unavailable Windows-symlink capability; they are
not two passed security checks. Historical 58/68 counts above are not relabeled.

The first independent harness attempt constructed authorization after installing
the escaping junction, so source snapshot correctly rejected that fixture before
the planned assertion. The harness was corrected to capture authorization before
the link existed, with a separate direct path-validation assertion. Its first
error log is retained privately; implementation code was not changed.

Code-package SHA-256 (11 candidate Python files, sorted relative path + NUL +
lowercase file SHA-256 + LF): `1b8f706f87a65b2cf6a105433bab8bf628b33490d56c3870d88df347daea85a5`.

Private artifact hashes (filenames are logical evidence references, not public
repository paths; raw logs/fixtures stay private):

| Evidence artifact | SHA-256 |
|---|---|
| `regression-full.log` | `8a859397dc9d816aedac3cbadae7c3438d0ca47fff90629bd4dde1173c19a867` |
| `regression-result.json` | `6755942e4a5394668fd26df53ff81f2ab986d2acc6b4575d2def3311aaa939bb` |
| `independent-full.log` | `31a0c7de9b9c7cdf35e9e4b07fe7eb9a4f8485b20dd92813ecb579bff44a845b` |
| `independent-result.json` | `d3b1384a0562349134fd6ae664eebae94d12228e950411d545aff426fcad2d29` |
| `independent-acceptance.py` | `98dd7ac34d97b8d4d39605e329c3959d618bb724972f2fb466d70276066f2513` |

Fixture timing medians from the five-sample regression test: source snapshot
240.222 ms, evaluation 247.847 ms, guarded fake dispatch 501.317 ms. These small
fixtures do not establish large-repository performance. Source hashing remains
linear in tracked/nonignored bytes and repeats at the dispatch boundary. There
are no added runtime dependencies, background daemon or production operation.

**Decision at that historical checkpoint: ACCEPTANCE BLOCKED / NOT_EVALUATED.** F01/F02 and the other executed
cases passed their current scoped checks; full acceptance remains open until the
real symlink case is executed in an authorized suitable environment and the
required human review is recorded. No G3, commit, push, merge or production
permission follows from these test results. Direct low-level internal calls,
unsigned trusted-operator assertions, process-local replay control, ignored inputs,
TOCTOU windows and nontransactional I/O retain their documented limitations.

Final test runs bypassed inherited bytecode caches using an unused cache prefix
and disabled bytecode writes. The copied historical caches were retained; no
source or production cleanup was performed.

## Targeted Windows symlink verification

2026-11-03. **ACCEPTANCE PASS a dokumentált, megbízható folyamaton belüli G1/G2 managed fejlesztési scope-ra.**

Evidence record: `HG-G1G2-SYMLINK-20261103`. After the separately authorized
manual creation of one synthetic fixture link, the prepared `--verify-existing`
check ran in the ordinary unelevated process and returned **SYMLINK_PASS**, exit 0.
The test refuses an elevated verification process. This was one targeted follow-up,
not a new full regression suite, product build or production test.

| Targeted requirement | Recorded evidence | Result |
|---|---|---|
| Actual Windows file symlink | `is_symlink()` and reparse tag `0xA000000C`; not a mock or junction | PASS |
| Expected outward target | Logical fixture path `fixture/owned/Core/escape.txt` resolves to `fixture/outside-target.txt`, outside the owned fixture worktree | PASS |
| Direct path validation | `scoped_path` rejects the real outward link with `ValueError` | PASS |
| Managed worker boundary | `BLOCK / INVALID_INPUT`; unsafe source rejected before dispatch | PASS |
| Unauthorized dispatch and writes | 0 execute calls; empty write-attempt list; source/foreign file hashes unchanged | PASS |
| External synthetic target | Same SHA-256 before and after verification, shown below | PASS |
| Publication/worktree preservation | Frozen 14-file package and five Git worktree states preserved at verification | PASS |

Target SHA-256: `8bfa708b336f40e3014a92809f63068870d72362e61a529c42a2030f0850c7f6`.
The fixture authorization was pinned before insertion of the link. The unsafe
current source is rejected during snapshot validation; no authorization for an
unsafe snapshot is claimed. The separate direct `scoped_path` check also rejected
the actual link. Both denials occurred before dispatch.

The prior **72 PASS + 1 SKIP** and **19 PASS + 1 SKIP** remain historical results.
This follow-up supplies the missing real-symlink evidence; it does not rewrite
either old skip or claim a new 73/73 or 20/20 full-suite run.

Private evidence artifact hashes (logical references, not public repository files):

| Artifact | SHA-256 |
|---|---|
| `SYMLINK-VERIFICATION-HU.md` | `c07a255b4d426261cb8e3eb91763950339ee5da5c682d11a9bd4530451600109` |
| `verification-result.json` | `a9b23070d29d4ffcbcbcc64455388e55d40e922ea09cde79b8edc4212ad2b08f` |
| `post-symlink-preservation.json` | `ecf6d31a510b715c66b532d247475478420537115f42af152df5f79e51b3c5ac` |

Raw local logs, fixture files, machine paths and authorization documents remain
outside the publication package. The logical fixture paths above describe the
synthetic test layout; they do not refer to checked-in repository fixtures.

This PASS applies only to the documented trusted-process local G1/G2 managed
development boundary. Trusted operator assertions, direct low-level/external
execution, TOCTOU races, per-process replay scope, ignored inputs and
nontransactional multi-file I/O retain their existing limitations. The result is
not production qualification, full security certification, an OS sandbox, or
G3–G6 acceptance. Runtime final-task acceptance remains a separate decision.
No functional Python change, staging, project commit, push, merge or deployment
was performed by this documentation refresh.
