# HostsGuardian visual conventions

The application uses dark surfaces (#050A08 background, #0B1510 panels), readable
Segoe UI text, restrained mint-green (#00FF88) identity/focus accents, and thin
muted green borders. Orbitron is reserved for HostsGuardian branding.
Body text is #E6FFF0, secondary text #A3B5AC, warnings #FFD166, errors #FF8585.
State wording accompanies color; presentation never invents operational state.

Styles live in WPF/Styles/MatrixStyles.xaml, shared by main and connection windows.
PrimaryButton, SecondaryButton and DangerButton distinguish action hierarchy.
Controls have 34px minimum height, 12x7 button padding, 4px control corners;
cards have 6px corners, 12px padding and 1px borders. Focus, hover and disabled
states remain visible. Inputs use the native text viewport without double padding.
SectionHeading/HelperText and SuccessText/WarningText/ErrorText provide hierarchy.

Tables use Segoe UI 13px, 38px minimum rows, padded cells, muted column headers,
subtle alternating rows and clear selection/focus. Horizontal scrolling preserves
identity columns at narrow widths. Text wraps instead of silently clipping long
values; edit controls use the same dark theme. Unknown device icons are neutral circles with
the existing kind as tooltip; discovery/identity heuristics are not modified.
Existing log severity text is accented without changing records or behavior.

Main window supports 1000x640 and larger; sidebar scrolling and wrapped action
rows keep controls accessible. Tables scroll independently. Operational status,
navigation, page content and actions occupy separate visual regions. Search stays
visible above navigation; the HTTPS address receives a full-width information line.
The connection dialog shares these controls while retaining its security workflow,
with 10px section insets for its compact form.

For future screens, reuse these resources rather than copying styles. The Linux
Engine Monitor remains deferred until after Phase 5 and must remain an operational
read-only view, following the same palette/type hierarchy with native Linux controls.
No monitor, policy-management, networking or runtime changes are part of this pass.

Representative previews use isolated data and commands that cannot execute. All
four views are checked at 1200x760, Devices additionally at 1000x640. The real
MainViewModel constructor is excluded from fixtures, avoiding configuration, discovery
or networking side effects. Preview rendering does not certify runtime status.
