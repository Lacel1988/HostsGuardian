"""Read-only troubleshooting knowledge; never observations or model permissions."""
from .analyst_contracts import DiagnosticHypothesis
from .knowledge import knowledge_query

# id -> source anchor, HU statement/step, EN statement/step.
HYPOTHESES = {
    "discovery_visibility": (
        "Multicast discovery requires suitable local network visibility.",
        "A vendéghálózat, VLAN-elkülönítés vagy multicast-szűrés akadályozhatja a felderítést.",
        "Ellenőrizd, hogy a kereső és az eszköz ugyanazon megfelelő hálózati szegmensben van-e, és mit mutat a meglévő felderítési állapot.",
        "Guest-network isolation, separate VLANs or multicast filtering may prevent discovery.",
        "Check the network segments of the scanner and device and inspect existing discovery status."),
    "discovery_receiver": (
        "Discovery receiver availability must be observed separately.",
        "Lehetséges, hogy a passzív felderítő fogadója nem fut, vagy hiba után nem állt helyre.",
        "Nézd meg a fogadó tényleges állapotát, az utolsó megfigyelés idejét és a meglévő helyreállítási hibajelzést.",
        "The passive discovery receiver may be stopped or may not have recovered from a failure.",
        "Inspect receiver status, the last observation time and any existing recovery error report."),
    "resolver_bypass": (
        "Clients can avoid a chosen resolver by selecting alternative DNS servers or encrypted DNS over HTTPS.",
        "Az eszköz más DNS-kiszolgálót vagy DNS over HTTPS feloldást használhat.",
        "Ellenőrizd az eszköz DNS- és titkosított DNS-beállításait, majd vesd össze a megfigyelt DNS-forgalommal.",
        "The device may use another DNS resolver or DNS over HTTPS.",
        "Inspect the device's DNS and encrypted-DNS settings and compare them with observed DNS traffic."),
    "stale_binding": (
        "Bindings need interface scope and fresh identity evidence.",
        "Az eszköz aktuális IP-címe és a nyilvántartott azonosító közötti kötés elavulhatott.",
        "Hasonlítsd össze az aktuális IP-címet, az interfészt és a kötés megfigyelési, illetve lejárati idejét.",
        "The binding between the device's current IP address and its registered identity may be stale.",
        "Compare its current IP, interface, binding observation time and expiry time."),
    "policy_scope": (
        "A configured policy is not proof that a particular device uses the protected resolver.",
        "Lehetséges, hogy a kívánt szabály nem szerepel az eszközre ténylegesen érvényes szabályzatban.",
        "Vesd össze a mentett szabályt a teljes visszaolvasott szabályzattal, annak revíziójával és eszközhatókörével.",
        "The intended rule may not be present in the policy actually applicable to the device.",
        "Compare the saved rule with complete policy readback, its revision and the applicable device scope."),
    "ipv6_gap": (
        "This does not establish reliable IPv6 per-device enforcement.",
        "Az IPv6-címhez nem állhat rendelkezésre megfelelő eszközazonossági bizonyíték.",
        "Ellenőrizd a lekérdezés címcsaládját és az IPv6-eszközkötéshez rendelkezésre álló bizonyítékot.",
        "The IPv6 address may lack sufficient device-attribution evidence.",
        "Inspect the query's address family and the evidence available for IPv6 device attribution."),
    "upstream_unreachable": (
        "Timeouts and transport failures need finite retry limits.",
        "A beállított upstream DNS-kiszolgáló átmenetileg elérhetetlen lehet.",
        "Nézd meg a meglévő állapotjelentés upstream-időtúllépéseit és a hallgató szolgáltatás állapotát külön-külön.",
        "The configured upstream DNS resolver may be temporarily unreachable.",
        "Inspect existing upstream timeout observations and listener status separately."),
}


def diagnostic_hypotheses(question, language, evidence, detail):
    # Future real adapters need typed contradiction rules. Until those exist,
    # never speculate over verified operational observations.
    if any(item.kind == "verified_operational" and item.fact_type not in ("engine_health","dns_status","policy_status","activity_summary") for item in evidence):
        return ()
    query = knowledge_query(question)
    if "discovery" in query:
        keys = ("discovery_visibility", "discovery_receiver", "stale_binding")
    elif "privacy" in query or "synchronization" in query:
        keys = ("stale_binding", "ipv6_gap", "resolver_bypass")
    elif "bypass" in query:
        keys = ("resolver_bypass", "stale_binding", "policy_scope", "ipv6_gap")
    else:
        keys = ("upstream_unreachable", "resolver_bypass")
    result = []
    for key in keys[:2 if detail == "simple" else 3]:
        if key=="upstream_unreachable" and any(e.kind=="verified_operational" and e.fact_type=="dns_status" and e.freshness=="fresh" and e.facts.get("upstream_health")=="Healthy" for e in evidence):
            continue
        anchor, hu_statement, hu_step, en_statement, en_step = HYPOTHESES[key]
        support = tuple(e.evidence_id for e in evidence if e.kind == "approved_documentation" and anchor in e.content)[:4]
        result.append(DiagnosticHypothesis(hypothesis_id=key, basis="documentation" if support else "general_networking_knowledge",
            statement=hu_statement if language == "hu" else en_statement,
            verification_step=hu_step if language == "hu" else en_step, evidence_ids=support))
    return tuple(result)


def localized_diagnostic_message(message, language):
    if language != "hu":
        return message
    translations = {
        "Production device identity, policy and end-to-end DNS enforcement are not verified.": "Az éles eszközazonosság, a szabályzat és a teljes DNS-végrehajtás nincs igazolva.",
        "Knowledge retrieval is not configured.": "A tudás-visszakeresés nincs beállítva.",
        "Knowledge retrieval unavailable or invalid.": "A tudás-visszakeresés nem érhető el vagy érvénytelen.",
        "Insufficient documentation evidence.": "Nincs elegendő dokumentációs bizonyíték.",
        "Diagnostic budget exhausted.": "Elfogyott a diagnosztikai műveletek kerete.",
        "Retrieval skipped: tool budget exhausted.": "A visszakeresés kimaradt, mert elfogyott a műveleti keret.",
        "Summary operation omitted: tool budget exhausted.": "Az összegzés kimaradt, mert elfogyott a műveleti keret.",
        "Conflicting policy revisions; synchronization and enforcement remain unknown.": "Ellentmondó szabályzatrevíziók miatt a szinkron és a végrehajtás továbbra is ismeretlen.",
        "Local generation unavailable; deterministic cited fallback.": "A helyi generálás nem érhető el; forráshoz kötött tartalék válasz készült.",
        "Local generation invalid/unavailable; deterministic cited fallback.": "A helyi generálás hibás vagy elérhetetlen; forráshoz kötött tartalék válasz készült.",
    }
    if message in translations:
        return translations[message]
    if ": " in message and message.split(": ", 1)[0] in {"engine_status", "policy_status", "device_identity_status", "dns_activity_summary"}:
        return "A diagnosztikai forrás nem szolgáltatott használható adatot: " + message
    return "A forrás korlátozott vagy nem ellenőrizhető; további ellenőrzés szükséges."
