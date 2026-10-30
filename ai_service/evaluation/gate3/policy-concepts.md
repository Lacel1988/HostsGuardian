# DNS-szabályzat / DNS policy

A DNS policy defines which domain names are allowed or blocked by explicit rules.
A configured policy is not proof that a particular device uses the protected resolver.
The selected domain rules are evaluated separately from device identity and observed DNS coverage.

A DNS-szabályzat kifejezett szabályokkal határozza meg a domainnevek engedélyezését vagy tiltását.
A mentett szabályzat nem bizonyítja, hogy egy adott eszköz a védett DNS-kiszolgálót használja.
Az eszközazonosság és a DNS-forgalom lefedettsége külön bizonyítékot igényel.

Forrás: HostsGuardian.DnsEngine/RuleStore.cs — IsBlocked;
HostsGuardian.DnsEngine/DevicePolicyEvaluator.cs — Explain;
HostsGuardian.Core/Services/PolicyDecision.cs — Explain.
Ez kód alapján készített fogalmi dokumentáció; nem éles működési megfigyelés.
