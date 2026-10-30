import re
import unicodedata

from .analyst_contracts import Route
from .schemas import ToolName


def normalize(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


def forbidden_action(question):
    text = normalize(question)
    words = set(re.findall(r"[a-z0-9_]+", text))
    return bool(words & {"delete", "modify", "change", "execute", "shell", "sql", "powershell", "bash", "sudo", "deploy", "restart", "disable", "enable", "torold", "modositsd", "kapcsold", "telepitsd", "inditsd", "allitsd", "valtoztasd"}) or any(term in text for term in ("ignore instructions", "ignore system", "hagyj figyelmen", "run command"))


def classify(question: str) -> tuple[Route, tuple[ToolName, ...], str, str]:
    text = normalize(question)
    words = set(re.findall(r"[a-z0-9_]+", text))
    hu = bool(words & {"miert", "hogyan", "allapot", "allapota", "magyarul", "egyszeruen", "reszletesen", "nem", "es", "torold", "kapcsold", "mi", "szabalyzat", "teve", "elerheto"})
    language = "hu" if hu else "en"
    detail = "technical" if any(term in text for term in ("technical", "detailed", "revision", "binding", "ipv6", "rrf", "reszletes", "technikai")) else "standard"
    if any(term in text for term in ("simple", "plain language", "simpler", "egyszeru", "roviden")):
        detail = "simple"
    # Deliberately reject action/instruction attempts before any evidence access.
    if forbidden_action(question):
        return "unsupported", (), language, detail
    direct = {t.value: t for t in ToolName}
    if text.strip() in direct:
        return "direct", (direct[text.strip()],), language, detail
    if text.strip() in ("status", "help", "fix it", "segits", "allapot", "mi a baj?", "what is wrong?"):
        return "ambiguous", (), language, detail
    diagnostic = any(term in text for term in ("why", "miert", "diagnose", "investigate", "not blocked", "nem blokkol", "failing", "despite", "hiba", "nem mukodik", "mukodik a", "is domain blocking working", "is dns working",
        "how can i fix", "how to fix", "hogyan javithat", "mit ellenorizzek", "how can i check", "what could cause", "mi okozhat", "lehetseges okok"))
    subject = any(term in text for term in ("dns", "engine", "policy", "device", "youtube", "tv", "teve", "binding", "enforcement", "szabaly", "eszkoz", "blokkol", "discovery", "felderit", "domain blocking"))
    if diagnostic and subject:
        if words & {"tv", "teve", "teven", "youtube"}:
            detail = "simple" if detail == "standard" else detail
        return "investigation", tuple(ToolName), language, detail
    documentation = any(term in text for term in ("explain", "what is", "how does", "documentation", "hogyan", "magyarazd", "mi az", "mi a", "mit jelent"))
    if documentation and any(term in text for term in ("rag", "rrf", "bm25", "dns", "policy", "safe mode", "ipv6", "binding", "embedding", "szabaly", "kot", "vedo", "retriev", "fuzio")):
        return "retrieval", (), language, detail
    if any(term in text for term in ("status", "available", "running", "capability", "allapot", "elerheto", "fut", "kepesseg")):
        for names, tool in (( ("policy", "szabaly"), ToolName.POLICY), (("device", "eszkoz", "identity"), ToolName.DEVICE),
                            (("activity", "forgalom"), ToolName.ACTIVITY), (("engine", "dns"), ToolName.ENGINE)):
            if any(term in text for term in names):
                return "direct", (tool,), language, detail
    return "unsupported", (), language, detail
