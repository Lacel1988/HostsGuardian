"""Bounded domain query normalization and source-anchored bilingual explanations.

The model selects approved clauses; it never authors unchecked operational claims.
"""
from dataclasses import dataclass
import re

from .routing import normalize


def knowledge_query(question: str) -> str:
    text = normalize(question)
    if any(word in text for word in ("discovery", "felderit", "felfedez")):
        return "device discovery network interface multicast identity"
    if any(word in text for word in ("rrf", "rag", "bm25", "rank fusion", "rangsorfuzio")):
        return "hybrid retrieval reciprocal rank fusion BM25 semantic embedding"
    if "ipv6" in text or "privacy address" in text:
        return "IPv6 per-device enforcement privacy addresses device identity"
    if any(word in text for word in ("youtube", " tv", "teve", "streaming")):
        return "resolver bypass DNS over HTTPS device identity validated address binding"
    if (any(word in text for word in ("binding", "enforcement", "szinkron", "synchron", "revision", "revisio", "eszkozazon"))
        or "azonosit" in text and "eszkoz" in text or "identify" in text and "device" in text):
        return "device identity freshness validated binding policy revision synchronization readback"
    if "domain blocking" in text or "blokkol" in text and "mukodik" in text:
        return "DNS domain blocking policy rules resolver coverage"
    if any(word in text for word in ("policy", "szabalyzat", "szabalyozas")):
        return "DNS policy domain allow block rules explicit selected domains"
    stop = {"what", "is", "the", "a", "an", "how", "why", "explain", "in", "detail", "mi", "az", "a", "hogyan", "miert", "el", "egyszeruen"}
    return " ".join(w for w in re.findall(r"[a-z0-9]+", text) if w not in stop)[:256] or question[:256]


@dataclass(frozen=True)
class Clause:
    key: str
    anchor: str
    en: str
    hu: str
    topics: tuple[str, ...]
    hypothesis: bool = False


CLAUSES = (
    Clause("fusion", "Hybrid retrieval combines BM25 keyword ranking and semantic embedding similarity.",
        "Hybrid search combines keyword matches with matches based on meaning.",
        "A hibrid keresés a kulcsszóegyezést a jelentés szerinti kereséssel kapcsolja össze.", ("hybrid", "retrieval", "bm25", "semantic")),
    Clause("rrf", "Reciprocal Rank Fusion adds reciprocal rank contributions from each ranking.",
        "RRF merges the result lists using their rank positions, rather than adding incompatible raw scores.",
        "Az RRF a találati helyezésekből egyesíti a listákat; nem az eltérő skálájú nyers pontszámokat adja össze.", ("reciprocal", "rank", "fusion")),
    Clause("policy", "A DNS policy defines which domain names are allowed or blocked by explicit rules.",
        "A DNS policy is a set of rules that says which domain names may be resolved and which should be blocked.",
        "A DNS-szabályzat azt rögzíti, hogy mely domainnevek feloldását engedjük, és melyeket tiltjuk.", ("policy", "domain", "allow", "block", "rules")),
    Clause("scope", "A configured policy is not proof that a particular device uses the protected resolver.",
        "Saving a rule does not prove that a particular device is using the protected DNS resolver.",
        "Egy szabály mentése még nem bizonyítja, hogy az adott eszköz a védett DNS-kiszolgálót használja.", ("policy", "device", "resolver", "rules")),
    Clause("binding", "Bindings need interface scope and fresh identity evidence.",
        "The device must have a fresh identity-to-address binding on the correct network interface.",
        "Az eszközhöz friss cím–azonosság-kötés kell, a megfelelő hálózati interfészen.", ("device", "identity", "freshness", "validated", "binding")),
    Clause("stale", "Stale address observations cannot establish which device currently owns an IP address.",
        "An old address observation cannot tell us which device owns that IP address now.",
        "Egy régi címmegfigyelésből nem állapítható meg, hogy most melyik eszközé az IP-cím.", ("device", "identity", "freshness", "binding")),
    Clause("revision", "Equal domain counts do not prove equal policy content.",
        "Matching rule counts do not prove synchronization: compare the complete policy and its revision.",
        "Az egyező szabályszám nem igazolja a szinkront: a teljes szabályzatot és a revíziót kell összevetni.", ("policy", "revision", "synchronization", "readback")),
    Clause("ipv6", "This does not establish reliable IPv6 per-device enforcement.",
        "An IPv6 listener does not prove that filtering is enforced separately for each IPv6 device.",
        "Az IPv6-figyelő működése nem bizonyítja az IPv6-eszközönkénti szűrést.", ("ipv6", "per", "device", "enforcement")),
    Clause("privacy", "Temporary privacy addresses and prefix changes complicate device attribution.",
        "Temporary IPv6 addresses and prefix changes can make device attribution harder.",
        "Az ideiglenes IPv6-címek és a prefixváltások nehezíthetik az eszköz azonosítását.", ("ipv6", "privacy", "addresses", "identity")),
    Clause("bypass", "Clients can avoid a chosen resolver by selecting alternative DNS servers or encrypted DNS over HTTPS.",
        "One possible explanation is that the device uses another DNS resolver or encrypted DNS over HTTPS. We have not verified that this happened.",
        "Lehetséges, hogy az eszköz más DNS-kiszolgálót vagy titkosított DNS over HTTPS feloldást használ. Ezt itt nem igazoltuk.", ("resolver", "bypass", "https", "dns"), True),
    Clause("coverage", "A healthy listener does not prove all client traffic passes through it.",
        "A working DNS listener does not prove that all traffic from the device passes through it.",
        "A működő DNS-figyelő még nem bizonyítja, hogy az eszköz minden forgalma rajta halad át.", ("resolver", "bypass", "coverage", "device")),
)


def supported_clauses(evidence, question):
    query = set(knowledge_query(question).split())
    supported = []
    for clause in CLAUSES:
        matches = [item for item in evidence if item.kind == "approved_documentation" and clause.anchor in item.content]
        if matches:
            score = len(query & set(clause.topics))
            if score:
                supported.append((score, clause, matches[0]))
    supported.sort(key=lambda row: (-row[0], row[1].key))
    return [(clause, evidence) for _, clause, evidence in supported[:5]]


def select_clauses(keys, candidates):
    lookup = {clause.key: (clause, source) for clause, source in candidates}
    if len(keys) != len(set(keys)) or any(key not in lookup for key in keys):
        raise ValueError("Unknown or duplicate grounded clause")
    return [lookup[key] for key in keys]


def render_clauses(selected, language):
    return " ".join((clause.hu if language == "hu" else clause.en) + f" [{source.evidence_id}]"
                    for clause, source in selected)
