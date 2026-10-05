# WPF UX, localization and notification foundation

The Windows control center runs as the invoking user. The retired HOSTS
Apply/Revert manifest comment was the sole reason for the retained global
Administrator request. The manifest now uses `asInvoker`. Management credential
protection, explicit certificate enrollment, HTTPS validation, authenticated
readback and revision/instance checks are unchanged. DNS cache clearing remains
an explicit local command, with success based on its exit code. A denied command
reports failure; the application does not elevate itself or alter DNS settings.
Legacy cleanup remains outside ordinary filtering UI.

## Local draft and confirmed Engine state

The Devices name editor changes the visible draft only. **Save names to draft**
saves names for registered DeviceIds into the existing local `config.json`.
It neither registers unknown identities nor sends policy to the Engine.
Sending the complete policy remains a separate authenticated operation with
readback confirmation. Individual device rules retain immediate local save and
rejected-save rollback. Durable IDs, IP/MAC evidence and diagnostic identity
details remain available. Owner/location/group/fingerprinting fields were not
invented.

## Localization and UI preferences

Embedded `Localization/en.json` and `hu.json` are the single catalogs used by
XAML bindings, view models, dialogs, events and notifications. Stable resource
keys drive XAML; C# looks up source templates in the same catalog. Binding
notifications refresh labels immediately. Enum values remain backend values;
only their presentation is translated. Unknown resource keys fall back safely.
Backend diagnostic payloads, OS output and old free-text audit entries are
preserved, rather than misrepresented as translated structured events.

The language selector shows English / Magyar and persists `en` / `hu` in
`%LOCALAPPDATA%\HostsGuardian\ui-preferences.json`. This atomic UI-only file also
stores four notification category preferences and contains no policy, secret or
certificate data. Persistence failure leaves the prior language active and
shows an error. Invalid preference input uses safe defaults and a visible warning.

Contextual tooltips explain only ambiguous actions. They use the same live
resources, with an initial hover delay of 2500 milliseconds and no immediate
between-tooltip shortcut. They do not replace critical state or required
instructions. Navigation and controls retain keyboard focus behavior.

## Activity and notifications

The existing Log remains the persistent local audit view. Existing entries have
UTC timestamp, severity and redacted free text; they are not an authenticated
Engine audit stream. Filters use actual INFO/WARN/ERROR severity, with ALL as
the unfiltered view. Clear visible list does not delete the audit file.

New structured local domain/device-rule events add source, category, nullable
actor, target, previous/current action and outcome, using the same audit file.
Actor stays null because there is no authenticated WPF login. Draft saves are
identified as local saves, not successful Engine changes. The structured message
template is localized on display and target arguments remain unchanged.

`NotificationCenter` accepts real observations separately from logging. It
deduplicates unresolved conditions, tracks severity/read/resolved state, and
resolves failures only on a fresh successful observation. Unknown upstream
state does not count as recovery. Engine/security/DNS/persistence conditions,
unconfirmed policy changes and unknown scanned devices are initial sources.
Startup without observation, page navigation, local refresh and language
changes do not fabricate notifications. No polling traffic was introduced.

The shell indicator opens an overlay on demand. Critical conditions also remain
in a visible banner when the overlay is closed or notifications are read.
Preferences filter warning/information delivery; disabled delivery never hides
active critical state. Notification navigation marks a message read and opens
an existing page without changing policy. Resolved history is bounded; active
conditions stay deduplicated. Notification history is session-local.

The desktop transport interface suppresses desktop delivery while the app is
active and shares the application's localization. **Native Windows toast
delivery is deferred**: this repository has no installer/package identity,
notification activation registration or Windows App SDK deployment. The
unregistered sink reports unavailable and makes no registry/shortcut/package
changes. A future registered adapter must implement reliable activation,
foreground detection and navigation with the same center. No imitation toast
or fragile registration workaround was added.

## Future schedules and metadata: design only

A future policy rule may reference a reusable schedule profile (Bedtime,
School time, Weekend or Gaming time). The policy remains stable across time
changes. The Engine evaluates the schedule condition and reports the effective
decision and active interval; the WPF must not rewrite policy on a timer.
Timezone, daylight-saving transitions, overnight intervals and clock validity
require an explicit future Engine design and versioned capability negotiation.

Future device details can group friendly name, owner, location, type and
confidence without removing identity diagnostics. Assisted identification,
groups and disruption of device networking are deferred.

Future schedule-start/end/advance-warning notifications should enter the same
event-to-notification path with stable condition IDs and localized templates.
Preferences may add schedule categories and a lead time, such as 15 minutes,
without coupling UI preferences to policy persistence. No schedule runtime,
new backend metadata fields or schedule-policy semantics were implemented.

## Verification

The WPF suite tests actual two-way bindings, EN/HU key/format parity, fallback,
selector switching and persistence, deduplication, read state, recovery,
preferences, desktop foreground routing, compact navigation bounds and tooltip
delay. It renders isolated fixture windows in both languages. Fixtures never
connect to VIVO, scan devices, clear DNS, write HOSTS or change production policy.
The established core suite remains the authority for management/authentication,
policy persistence/concurrency and Engine DNS semantics.

For local Debug visual review only, `--review-languages` opens the actual
control center in English and, after 20 seconds, sets the actual language
selector to Hungarian through its normal binding. It operates no other
controls. Release builds do not include this review helper.

Native notification reference: [Microsoft .NET app-notification documentation](https://learn.microsoft.com/windows/apps/develop/notifications/app-notifications/app-notifications-dotnet). Unpackaged apps are supported, but the Windows App SDK path still requires runtime integration and COM activation registration. Package identity itself is not mandatory.
