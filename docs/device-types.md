# Device type presentation and ownership

User-confirmed type is WPF-authored control-plane metadata, delivered only through explicit authenticated policy delivery. Engine forwards the accepted metadata without classifying devices. Monitor consumes it read-only. A friendly name, observed hostname, stable DeviceId and device type remain distinct.

The single `linux-monitor/device-types.json` catalog is embedded in Core and shipped with Monitor. It defines 13 categories, aliases, semantic icon keys and vector strokes used by both interfaces. No emoji font dependency exists. Text labels accompany icons.

A recognized user-confirmed type, including explicit Unknown, overrides inference. Unrecognized legacy metadata is retained and presented as Unknown rather than overwritten. Automatic suggestions use a single unambiguous observed hostname containing a supported category token. These suggestions are INFERRED / Medium, never certain. MAC, IP, vendor and friendly name alone do not classify type. Conflicting hostnames or category hints remain UNKNOWN.

WPF offers an automatic/unconfirmed choice and explicit category choices. Provisional type selection does not create a DeviceId. Registration or local save persists the choice; explicit delivery is required before Monitor sees it. Type metadata creates no DNS binding or policy rule. No permanent identity is derived from a randomized MAC.

Current limitations: no service/model fingerprinting, active probes or vendor taxonomy were added. The real S22 lacks automatically observed hostname evidence and may remain Unknown. Production friendly-name/type round-trip and human icon/layout review require the guarded candidate deployment and an explicitly authorized registration; automated fixtures do not substitute for that acceptance.
