# Upstream forwarding failures

Allowed DNS requests are forwarded to a configured upstream resolver. Timeouts and transport failures need finite retry limits. Exhausted forwarding attempts return a failure response instead of hanging forever. Upstream reachability differs from listener availability and domain policy filtering state.
