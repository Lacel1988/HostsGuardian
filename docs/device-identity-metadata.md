# User-owned device identity and diagnostic presentation

WPF authors registrations, friendly names, metadata and groups in its local policy
draft. A stable registration DeviceId is generated only after an explicit user
registration decision. Saving names updates both the registry name and an existing
metadata alias; failed persistence retains the previous policy metadata. Nothing
is delivered automatically. Full policy delivery uses the existing authenticated
HTTPS API, revision/instance concurrency and canonical readback confirmation.

Engine persists the accepted control-plane snapshot for execution and read-only
diagnostic projection. It does not generate user aliases, register observed devices,
or become the author of those decisions. Monitor consumes the published projection
and provides no naming, registration, grouping or policy actions.

`LanDeviceObservation.Identity` separates registration DeviceId, friendly name,
observed hostname, confidence, association provenance, group labels and user type.
The session observation ID remains distinct. A registered identity may be shown
for a LAN-only observation with zero DNS activity. Identity metadata neither grants
an execution address binding nor proves DNS coverage.

The shared Core projection requires one nonempty observed MAC, one matching user
registration and one matching independent observation. Omitted evidence, duplicate
registrations and same-MAC observations on different interfaces withhold association.
IP alone and hostname alone never select a registered identity. Private/randomized
MAC possibility remains visible: current MAC correspondence does not prove permanent
physical continuity or survival of randomization. DNS address binding validation
remains a separate existing Engine requirement.

Friendly name is the user metadata alias, falling back to the user registration
name. An observed hostname is separately retained and may provide a display fallback
for unnamed observations; it never becomes user-confirmed metadata automatically.
WPF labels local draft identity separately from delivery, so unsent names may differ
from Monitor's accepted snapshot. Rescan after an accepted metadata readback refreshes
the projection. Conflicting DNS/registration associations remain unknown/ambiguous.

Monitor offers a dedicated Devices / DNS page and a link from aggregate Diagnostics.
The full-height most-active-first compact list has a count and visible scrollbar;
selected details scroll independently. Identity, presence, network evidence, DNS
activity and coverage have distinct headings. Unknown coverage explains missing
evidence rather than implying an error or proven bypass. Technical provenance and
IDs remain under an expandable section. Aggregate Diagnostics remains available.

WPF Devices uses a compact independently scrollable source list and selected-device
summary. Naming remains inside identification details with explicit Save to draft;
registration confirmation warns that MAC evidence does not prove binding/continuity.
All new presentation labels use centralized EN/HU resources. Existing policy actions
and per-device rule editing remain available below the identity view.

Tests exercise an isolated authenticated API registration/name/readback/rename round
trip, LAN-only projection, group metadata, ambiguity, omitted evidence and failed
WPF name persistence. GTK and WPF rendering tests cover many rows and separate
selection/details. Fixtures are explicitly development evidence, never production
identity seeding. Human visual review and production round-trip acceptance remain
separate gates; production currently has no registered device to demonstrate naming.
