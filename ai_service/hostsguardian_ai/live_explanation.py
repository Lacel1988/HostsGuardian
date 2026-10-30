"""Localized rendering of narrowly verified API reports, never enforcement inference."""
def explain_live(record,language):
    text = _explain_live(record, language)
    if record.freshness == "stale":
        return ("Elavult jelentés, nem aktuális állapot: " if language == "hu" else "Stale report, not current status: ") + text
    if record.kind == "live_unverified":
        return ("Nem teljesen ellenőrzött jelentés: " if language == "hu" else "Unverified report: ") + text
    return text


def _explain_live(record,language):
    data=record.facts
    hu=language=="hu"
    yes=lambda value: ("igen" if value else "nem") if hu else ("yes" if value else "no")
    if record.fact_type=="engine_health":
        return (f"A hitelesített Engine API egészségjelzése: {yes(data['ok'])}." if hu else
                f"The authenticated Engine API reports healthy: {yes(data['ok'])}.")
    if record.fact_type=="dns_status":
        return (f"Az Engine szerint UDP-figyelő: {yes(data['udp_listening'])}, TCP-figyelő: {yes(data['tcp_listening'])}; port: {data['dns_port']}. Szűrés: {yes(data['filtering_enabled'])}, Safe Mode: {yes(data['safe_mode'])}. Ez nem igazolja az eszközök DNS-lefedettségét." if hu else
                f"The Engine reports UDP listening: {yes(data['udp_listening'])}, TCP listening: {yes(data['tcp_listening'])}; port {data['dns_port']}. Filtering: {yes(data['filtering_enabled'])}; Safe Mode: {yes(data['safe_mode'])}. This does not verify device DNS coverage.")
    if record.fact_type=="policy_status":
        return (f"A visszaolvasott szabályzat revíziója {record.policy_revision}; globális szabályok: {data['global_rule_count']}, eszközfelülírások: {data['override_count']}. A beállítás nem bizonyít tényleges blokkolást." if hu else
                f"Policy readback reports revision {record.policy_revision}, {data['global_rule_count']} global rules and {data['override_count']} device overrides. Configuration does not prove actual blocking.")
    if record.fact_type=="activity_summary":
        return (f"A {data['window_hours']} órás Engine-összesítésben engedélyezett: {data['allowed']}, blokkolt döntés: {data['blocked']}, hibás: {data['failed']}. Ez nem bizonyítja egy adott TV blokkolását vagy a válasz kliensoldali vételét." if hu else
                f"The {data['window_hours']}-hour Engine summary reports {data['allowed']} allowed, {data['blocked']} blocked decisions and {data['failed']} failures. This proves neither blocking on a specific TV nor client receipt.")
    return ("Az API eszközkötési megfigyelést közölt; az eszközazonosság és a végrehajtás nincs önállóan igazolva." if hu else
            "The API returned a binding observation; physical device identity and enforcement are not independently verified.")
