"""Bounded, ephemeral follow-up context. Caller text never becomes an observation."""
from .routing import normalize


def response_intent(question):
    text = normalize(question)
    if any(term in text for term in ("why did it fail", "why did this fail", "miert nem sikerult", "miert hibazott", "mi volt a hiba oka")):
        return "failure_reason"
    if any(term in text for term in ("what could cause", "possible causes", "mi okozhat", "lehetseges okok")):
        return "causes"
    if any(term in text for term in ("how can i fix", "how to fix", "how can i check", "hogyan javithat", "hogyan ellenoriz", "mit ellenorizzek")):
        return "verification"
    if any(term in text for term in ("more technical", "deeper technical", "reszletesebb", "technikailag reszletes")):
        return "technical"
    return "summary"


def render_failure_reasons(failures, language):
    hu = language == "hu"
    if not failures:
        return ("A korábbi eredmény nem tartalmazott konkrét hibajelzést; az alapok nem állapíthatók meg belőle." if hu else
                "The previous result contained no specific failure report; it does not establish an underlying cause.")
    sentences = []
    for failure in failures[:3]:
        text = (f"A(z) {failure.source} forrás {failure.status.value} állapotot adott." if hu else
                f"The {failure.source} source returned {failure.status.value}.")
        text += ((f" A kapott okkód: {failure.reason_code}." if hu else f" Reported reason code: {failure.reason_code}.")
                 if failure.reason_code else (" Részletes okkódot nem adott." if hu else " It provided no detailed reason code."))
        sentences.append(text)
    sentences.append("Ez nem igazolja a mögöttes hálózati okot." if hu else "This does not confirm the underlying network cause.")
    return " ".join(sentences)


def render_hypotheses(hypotheses, language, intent):
    hu = language == "hu"
    if not hypotheses:
        return ""
    if intent == "verification":
        return ("Javasolt, csak ellenőrzési lépések: " if hu else "Recommended verification steps only: ") + " ".join(
            f"{i+1}. {h.verification_step}" for i,h in enumerate(hypotheses))
    heading = "Nem igazolt lehetőségek: " if hu else "Unconfirmed possibilities: "
    return heading + " ".join(h.statement + ((" Ellenőrzés: " if hu else " Check: ") + h.verification_step
        if intent in ("causes", "technical") else "") for h in hypotheses)
